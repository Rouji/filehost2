use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use actix_web::body::{BodySize, EitherBody, MessageBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::web::Bytes;
use actix_web::{Error, HttpResponse, web};
use futures_util::future::{Ready, ok};

/// Per-IP token bucket over bytes. Shared by the upload direction (paced
/// chunk-by-chunk while the multipart body streams in) and the download
/// direction (paced chunk-by-chunk while the file streams out).
pub(crate) struct ByteThrottle(Mutex<HashMap<IpAddr, (Instant, f64)>>);

impl ByteThrottle {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// Charge `bytes` against the bucket for `ip`. Returns `Some(wait)` if the
    /// bucket is overdrawn: the caller must wait that long before the bytes may
    /// flow (or hand them to [`ThrottledBody`], which does it for you).
    ///
    /// `rate_bps` is the max bytes per second; `burst` is the maximum number of
    /// bytes that can be sent immediately before throttling kicks in.
    pub(crate) fn reserve(
        &self,
        ip: IpAddr,
        bytes: usize,
        rate_bps: f64,
        burst: f64,
    ) -> Option<Duration> {
        let mut map = self.0.lock().unwrap();

        let now = Instant::now();

        // Evict entries idle for longer than 1 bucket-refill period.
        map.retain(|_, (last, _)| now.duration_since(*last) < Duration::from_secs(60));

        let (last_refill, tokens) = map.entry(ip).or_insert((now, burst));

        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * rate_bps).min(burst);
        *last_refill = now;

        let bytes_f = bytes as f64;
        if *tokens >= bytes_f {
            *tokens -= bytes_f;
            None
        } else {
            let deficit = bytes_f - *tokens;
            *tokens = 0.0;
            Some(Duration::from_secs_f64(deficit / rate_bps))
        }
    }

    /// Blocking convenience over [`ByteThrottle::reserve`]: wait out the deficit
    /// before returning, so the caller's next step can proceed at pace.
    pub(crate) async fn throttle(&self, ip: IpAddr, bytes: usize, rate_bps: f64, burst: f64) {
        if let Some(wait) = self.reserve(ip, bytes, rate_bps, burst) {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Token bucket for the upload direction, applied per multipart chunk while
/// the body streams in.
pub(crate) type UploadThrottle = ByteThrottle;

/// Token bucket for the download direction, applied per body chunk while the
/// file streams out.
pub(crate) type DownloadThrottle = ByteThrottle;

pub(crate) struct MissTracker(Mutex<HashMap<IpAddr, (Instant, u32)>>);

impl MissTracker {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// Registers a miss for `ip`, returning the count within the current window.
    pub(crate) fn register(&self, ip: IpAddr) -> u32 {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, (window_start, _)| {
            now.duration_since(*window_start) < Duration::from_secs(120)
        });
        let (window_start, count) = map.entry(ip).or_insert_with(|| (now, 0));
        if now.duration_since(*window_start) >= Duration::from_secs(60) {
            *window_start = now;
            *count = 0;
        }
        *count += 1;
        *count
    }
}

/// Same sliding-minute window as [`MissTracker`], but counting every request
/// from an IP; drives the [`RequestRateLimiter`] middleware.
pub(crate) type RequestTracker = MissTracker;

pub(crate) struct RequestRateLimiter;

impl<S, B> Transform<S, ServiceRequest> for RequestRateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestRateLimit<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestRateLimit { service })
    }
}

pub(crate) struct RequestRateLimit<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestRateLimit<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let limit = req
            .app_data::<web::Data<crate::settings::Settings>>()
            .map(|s| s.max_requests_per_minute)
            .unwrap_or(0);

        if limit == 0 {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) });
        }

        let tracker = req
            .app_data::<web::Data<RequestTracker>>()
            .map(|t| t.get_ref());
        let ip = req
            .app_data::<web::Data<crate::ip::XffTrust>>()
            .and_then(|trust| crate::ip::extract_ip(req.request(), trust));

        if let (Some(tracker), Some(ip)) = (tracker, ip) {
            let count = tracker.register(ip);
            if count > limit as u32 {
                if count == limit as u32 + 1 {
                    log::warn!("rate limit hit: {count} requests within a minute (ip={ip})");
                }
                let res = req.into_response(
                    HttpResponse::TooManyRequests().body("Too many requests, slow down."),
                );
                return Box::pin(async move { Ok(res.map_into_right_body()) });
            }
        }

        let fut = self.service.call(req);
        Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) })
    }
}

/// `MessageBody` wrapper that paces chunks of `inner` through a shared
/// [`ByteThrottle`]. Bytes are buffered across the wait, so the client keeps
/// seeing data flow at `rate` instead of a frozen connection; range requests
/// are only charged for the bytes they actually get.
pub(crate) struct ThrottledBody<B: MessageBody> {
    pub(crate) inner: B,
    pub(crate) throttle: std::sync::Arc<ByteThrottle>,
    pub(crate) ip: IpAddr,
    pub(crate) rate: f64,
    pub(crate) burst: f64,
    /// chunk held back until its bucket deficit has elapsed
    buffered: Option<(Pin<Box<tokio::time::Sleep>>, Bytes)>,
}

impl<B: MessageBody> ThrottledBody<B> {
    pub(crate) fn new(
        inner: B,
        throttle: std::sync::Arc<ByteThrottle>,
        ip: IpAddr,
        rate: f64,
        burst: f64,
    ) -> Self {
        Self {
            inner,
            throttle,
            ip,
            rate,
            burst,
            buffered: None,
        }
    }
}

impl<B: MessageBody + Unpin> MessageBody for ThrottledBody<B> {
    type Error = B::Error;

    fn size(&self) -> BodySize {
        self.inner.size()
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.get_mut();

        if let Some((sleep, _)) = &mut this.buffered {
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            return Poll::Ready(this.buffered.take().map(|(_, bytes)| Ok(bytes)));
        }

        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(bytes))) => {
                match this
                    .throttle
                    .reserve(this.ip, bytes.len(), this.rate, this.burst)
                {
                    None => Poll::Ready(Some(Ok(bytes))),
                    Some(wait) => {
                        let mut sleep = Box::pin(tokio::time::sleep(wait));
                        if sleep.as_mut().poll(cx).is_ready() {
                            Poll::Ready(Some(Ok(bytes)))
                        } else {
                            this.buffered = Some((sleep, bytes));
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }
}
