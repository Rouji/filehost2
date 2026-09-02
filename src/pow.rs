use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use sha2::{Digest, Sha256};

const RANDOM_LEN: usize = 16;
const EXPIRY_LEN: usize = 8;
const MAC_LEN: usize = 32;
const TOKEN_LEN: usize = RANDOM_LEN + EXPIRY_LEN + MAC_LEN;

/// Issues and checks stateless proof-of-work challenges. The key lives only in
/// memory, so a restart invalidates outstanding challenges — same tradeoff as
/// `BanCache`'s in-memory lists.
pub(crate) struct PowSecret([u8; 32]);

impl PowSecret {
    pub(crate) fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self(key)
    }

    /// An opaque token: random || expiry || mac(random || expiry). The client
    /// must find a nonce such that `sha256(token.nonce)` has `difficulty`
    /// leading zero bits and send both back to `verify`.
    pub(crate) fn issue(&self, ttl_seconds: u64) -> String {
        let mut rnd = [0u8; RANDOM_LEN];
        rand::rng().fill_bytes(&mut rnd);
        let expiry = now() + ttl_seconds;

        let mut signed = Vec::with_capacity(RANDOM_LEN + EXPIRY_LEN);
        signed.extend_from_slice(&rnd);
        signed.extend_from_slice(&expiry.to_be_bytes());

        let mac = blake3::keyed_hash(&self.0, &signed);

        let mut token = signed;
        token.extend_from_slice(mac.as_bytes());
        to_hex(&token)
    }

    /// Checks the token is genuine and unexpired, and that `nonce` solves it.
    pub(crate) fn verify(&self, token: &str, nonce: &str, difficulty: u32) -> bool {
        let Some(buf) = from_hex(token) else {
            return false;
        };
        if buf.len() != TOKEN_LEN {
            return false;
        }
        let (signed, mac) = buf.split_at(RANDOM_LEN + EXPIRY_LEN);
        let expected = blake3::keyed_hash(&self.0, signed);
        if expected.as_bytes().as_slice() != mac {
            return false;
        }
        let expiry = u64::from_be_bytes(signed[RANDOM_LEN..].try_into().unwrap());
        if now() > expiry {
            return false;
        }
        // SHA-256, not blake3, because the client solves this in-browser via
        // the native `crypto.subtle.digest` API — no JS library to serve ourselves.
        let hash = Sha256::digest(format!("{token}.{nonce}").as_bytes());
        leading_zero_bits(&hash) >= difficulty
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for b in bytes {
        if *b == 0 {
            n += 8;
            continue;
        }
        n += b.leading_zeros();
        break;
    }
    n
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_verifies_with_a_solving_nonce() {
        let secret = PowSecret::generate();
        let token = secret.issue(60);
        // difficulty 0 means any nonce "solves" it — just exercises the plumbing
        assert!(secret.verify(&token, "anything", 0));
    }

    #[test]
    fn rejects_tampered_token() {
        let secret = PowSecret::generate();
        let mut token = secret.issue(60);
        token.replace_range(0..2, "ff");
        assert!(!secret.verify(&token, "anything", 0));
    }

    #[test]
    fn rejects_token_from_a_different_secret() {
        let a = PowSecret::generate();
        let b = PowSecret::generate();
        let token = a.issue(60);
        assert!(!b.verify(&token, "anything", 0));
    }

    #[test]
    fn rejects_expired_token() {
        let secret = PowSecret::generate();
        let token = secret.issue(0);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!secret.verify(&token, "anything", 0));
    }

    #[test]
    fn rejects_nonce_that_does_not_meet_difficulty() {
        let secret = PowSecret::generate();
        let token = secret.issue(60);
        // 256 is higher than any 32-byte hash can satisfy
        assert!(!secret.verify(&token, "anything", 256));
    }
}
