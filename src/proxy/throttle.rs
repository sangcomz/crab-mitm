use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use pin_project::pin_project;
use tokio::time::Sleep;

use super::{ProxyBody, ThrottleConfig};

#[pin_project]
struct ThrottledBody<B> {
    #[pin]
    inner: B,
    bytes_per_sec: u64,
    pending_frame: Option<Frame<Bytes>>,
    #[pin]
    sleep: Option<Sleep>,
}

impl<B> ThrottledBody<B> {
    fn new(inner: B, bytes_per_sec: u64) -> Self {
        Self {
            inner,
            bytes_per_sec,
            pending_frame: None,
            sleep: None,
        }
    }
}

impl<B> HttpBody for ThrottledBody<B>
where
    B: HttpBody<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        loop {
            if this.pending_frame.is_some() {
                if let Some(mut sleep) = this.sleep.as_mut().as_pin_mut() {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                this.sleep.set(None);
                let frame = this
                    .pending_frame
                    .take()
                    .expect("pending_frame checked as some");
                return Poll::Ready(Some(Ok(frame)));
            }

            match this.inner.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref()
                        && let Some(wait) =
                            throttle_delay_for_chunk(data.len() as u64, *this.bytes_per_sec)
                    {
                        *this.pending_frame = Some(frame);
                        this.sleep.set(Some(tokio::time::sleep(wait)));
                        continue;
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending_frame.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(super) fn maybe_throttle_body(body: ProxyBody, cfg: &ThrottleConfig) -> ProxyBody {
    maybe_throttle_body_with_rate(body, cfg.downstream_bytes_per_sec)
}

pub(super) fn maybe_throttle_body_with_rate(body: ProxyBody, bytes_per_sec: u64) -> ProxyBody {
    if bytes_per_sec == 0 {
        return body;
    }
    ThrottledBody::new(body, bytes_per_sec).boxed_unsync()
}

fn throttle_delay_for_chunk(bytes: u64, bytes_per_sec: u64) -> Option<Duration> {
    if bytes == 0 || bytes_per_sec == 0 {
        return None;
    }

    let nanos = (bytes as u128)
        .saturating_mul(1_000_000_000u128)
        .checked_div(bytes_per_sec as u128)
        .unwrap_or(0);
    if nanos == 0 {
        return None;
    }

    let nanos = nanos.min(u64::MAX as u128) as u64;
    Some(Duration::from_nanos(nanos))
}
