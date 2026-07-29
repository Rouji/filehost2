use std::io;
use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

pub(crate) type Conn = Box<dyn AsyncReadWrite + Unpin + Send>;

/// Open a connection to clamd. Accepts a TCP address ("host:port") or a
/// Unix socket path (anything starting with '/').
pub(crate) async fn connect(addr: &str) -> io::Result<Conn> {
    if addr.starts_with('/') {
        connect_unix(addr).await
    } else {
        Ok(Box::new(tokio::net::TcpStream::connect(addr).await?))
    }
}

#[cfg(unix)]
async fn connect_unix(addr: &str) -> io::Result<Conn> {
    Ok(Box::new(tokio::net::UnixStream::connect(addr).await?))
}

#[cfg(not(unix))]
async fn connect_unix(_addr: &str) -> io::Result<Conn> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix socket paths are not supported on this platform",
    ))
}

pub(crate) enum ScanResult {
    Clean,
    Infected(String),
}

/// clamd closing the connection early (virus found, or response already sent) surfaces
/// as one of these two error kinds.
fn is_connection_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

/// Stream a file to clamd via the INSTREAM protocol and return the scan result.
///
/// clamd may close its read side early when it finds a virus, producing a
/// BrokenPipe on our writes. We catch that, skip remaining writes, then read
/// the response that clamd has already buffered for us.
pub(crate) async fn scan_file(addr: &str, path: &Path) -> io::Result<ScanResult> {
    let mut conn = connect(addr).await?;
    conn.write_all(b"zINSTREAM\0").await?;

    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; 8192];
    'stream: loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        for chunk in [&(n as u32).to_be_bytes() as &[u8], &buf[..n]] {
            match conn.write_all(chunk).await {
                Ok(()) => {}
                Err(e) if is_connection_closed(&e) => break 'stream,
                Err(e) => return Err(e),
            }
        }
    }

    // Terminator — ignore errors; clamd may have already closed its read side.
    let _ = conn.write_all(&[0u8; 4]).await;
    let _ = conn.flush().await;

    // Read response: null- or newline-terminated (z-command protocol).
    // Also stop on EOF in case clamd closed the connection after responding.
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match conn.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == 0 || byte[0] == b'\n' {
                    break;
                }
                response.push(byte[0]);
            }
            Err(e) if is_connection_closed(&e) => break,
            Err(e) => return Err(e),
        }
    }

    let response = String::from_utf8_lossy(&response);
    let response = response.trim();
    if response == "stream: OK" {
        Ok(ScanResult::Clean)
    } else if let Some(name) = response
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix(" FOUND"))
    {
        Ok(ScanResult::Infected(name.to_string()))
    } else if response.ends_with(" ERROR") {
        Err(io::Error::other(response.to_string()))
    } else {
        Err(io::Error::other(format!(
            "unexpected clamd response: {response:?}"
        )))
    }
}
