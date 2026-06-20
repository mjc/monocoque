//! Stream and Sink adapters for futures ecosystem integration
//!
//! This module provides wrappers that implement `futures::Stream` and `futures::Sink`
//! for ZeroMQ sockets, allowing seamless integration with the Rust async ecosystem.
//!
//! # Examples
//!
//! ```rust,ignore
//! use monocoque_zmtp::{DealerSocket, adapters::SocketStream};
//! use futures::StreamExt;
//!
//! # async fn example() -> std::io::Result<()> {
//! let socket = DealerSocket::from_tcp("tcp://127.0.0.1:5555").await?;
//! let mut stream = SocketStream::new(socket);
//!
//! while let Some(msg) = stream.next().await {
//!     println!("Received: {:?}", msg);
//! }
//! # Ok(())
//! # }
//! ```

use bytes::Bytes;
use futures::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Wrapper that implements `futures::Stream` for any socket with `recv` method
///
/// This adapter allows using ZeroMQ sockets with stream combinators like
/// `map`, `filter`, `take`, etc.
pub struct SocketStream<S> {
    socket: S,
}

impl<S> SocketStream<S> {
    /// Create a new stream adapter for a socket
    pub const fn new(socket: S) -> Self {
        Self { socket }
    }

    /// Consume the stream and return the underlying socket
    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Get a reference to the underlying socket
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

/// Trait for sockets that can receive messages (needed for Stream impl)
pub trait RecvSocket {
    /// Receive a message from the socket
    fn poll_recv(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Vec<Bytes>>>>;
}

impl<S> Stream for SocketStream<S>
where
    S: RecvSocket + Unpin,
{
    type Item = io::Result<Vec<Bytes>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_recv(cx)
    }
}

/// Wrapper that implements `futures::Sink` for any socket with `send` method
///
/// This adapter allows using ZeroMQ sockets with sink combinators and
/// the `SinkExt` trait methods.
pub struct SocketSink<S> {
    socket: S,
    pending: Option<Vec<Bytes>>,
}

impl<S> SocketSink<S> {
    /// Create a new sink adapter for a socket
    pub const fn new(socket: S) -> Self {
        Self {
            socket,
            pending: None,
        }
    }

    /// Consume the sink and return the underlying socket
    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Get a reference to the underlying socket
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

/// Trait for sockets that can send messages (needed for Sink impl)
pub trait SendSocket {
    /// Check if the socket is ready to send
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Send a message through the socket
    fn poll_send(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        msg: Vec<Bytes>,
    ) -> Poll<io::Result<()>>;

    /// Flush any pending messages
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl<S> Sink<Vec<Bytes>> for SocketSink<S>
where
    S: SendSocket + Unpin,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.socket).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<Bytes>) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous message has not been flushed yet",
            ));
        }
        self.pending = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(msg) = self.pending.take() {
            match Pin::new(&mut self.socket).poll_send(cx, msg.clone()) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    self.pending = Some(msg);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Put the message back and return pending
                    self.pending = Some(msg);
                    return Poll::Pending;
                }
            }
        }

        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

/// Combined Stream + Sink adapter for bidirectional sockets
///
/// This provides both Stream and Sink implementations for sockets
/// that support both send and receive operations (DEALER, ROUTER, REQ, REP, etc.)
pub struct SocketStreamSink<S> {
    socket: S,
    pending: Option<Vec<Bytes>>,
}

impl<S> SocketStreamSink<S> {
    /// Create a new stream+sink adapter for a socket
    pub const fn new(socket: S) -> Self {
        Self {
            socket,
            pending: None,
        }
    }

    /// Consume the adapter and return the underlying socket
    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Get a reference to the underlying socket
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

impl<S> Stream for SocketStreamSink<S>
where
    S: RecvSocket + Unpin,
{
    type Item = io::Result<Vec<Bytes>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_recv(cx)
    }
}

impl<S> Sink<Vec<Bytes>> for SocketStreamSink<S>
where
    S: SendSocket + Unpin,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.socket).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<Bytes>) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous message has not been flushed yet",
            ));
        }
        self.pending = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(msg) = self.pending.take() {
            match Pin::new(&mut self.socket).poll_send(cx, msg.clone()) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    self.pending = Some(msg);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.pending = Some(msg);
                    return Poll::Pending;
                }
            }
        }

        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Sink;
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    #[derive(Clone, Default)]
    struct RecordingSendSocket {
        attempts: Arc<Mutex<Vec<Vec<Bytes>>>>,
        outcomes: Arc<Mutex<VecDeque<Poll<io::Result<()>>>>>,
    }

    impl RecordingSendSocket {
        fn new(outcomes: Vec<Poll<io::Result<()>>>) -> Self {
            Self {
                attempts: Arc::new(Mutex::new(Vec::new())),
                outcomes: Arc::new(Mutex::new(outcomes.into())),
            }
        }

        fn attempts(&self) -> Vec<Vec<Bytes>> {
            self.attempts.lock().expect("attempt log poisoned").clone()
        }
    }

    impl SendSocket for RecordingSendSocket {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            msg: Vec<Bytes>,
        ) -> Poll<io::Result<()>> {
            self.attempts
                .lock()
                .expect("attempt log poisoned")
                .push(msg);
            self.outcomes
                .lock()
                .expect("outcome queue poisoned")
                .pop_front()
                .unwrap_or(Poll::Ready(Ok(())))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn multipart_message() -> Vec<Bytes> {
        vec![
            Bytes::from_static(b"frame-1"),
            Bytes::from_static(b"frame-2"),
        ]
    }

    fn test_context() -> Context<'static> {
        let waker = Box::leak(Box::new(futures::task::noop_waker()));
        Context::from_waker(waker)
    }

    #[test]
    fn test_stream_creation() {
        struct MockSocket;
        let socket = MockSocket;
        let stream = SocketStream::new(socket);
        let _socket = stream.into_inner();
    }

    #[test]
    fn test_sink_creation() {
        struct MockSocket;
        let socket = MockSocket;
        let sink = SocketSink::new(socket);
        let _socket = sink.into_inner();
    }

    #[test]
    fn test_stream_sink_creation() {
        struct MockSocket;
        let socket = MockSocket;
        let adapter = SocketStreamSink::new(socket);
        let _socket = adapter.into_inner();
    }

    #[test]
    fn test_stream_sink_preserves_rfc_atomic_multipart_message() {
        let socket = RecordingSendSocket::new(vec![Poll::Ready(Ok(()))]);
        let mut adapter = SocketStreamSink::new(socket.clone());
        let message = multipart_message();
        let mut cx = test_context();

        assert!(Pin::new(&mut adapter).start_send(message.clone()).is_ok());
        assert!(matches!(
            Pin::new(&mut adapter).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(socket.attempts(), vec![message]);
        assert!(adapter.pending.is_none());
    }

    #[test]
    fn test_stream_sink_rejects_overwrite_before_flush() {
        let socket = RecordingSendSocket::new(vec![Poll::Ready(Ok(()))]);
        let mut adapter = SocketStreamSink::new(socket.clone());
        let first = multipart_message();
        let second = vec![Bytes::from_static(b"other")];

        assert!(Pin::new(&mut adapter).start_send(first.clone()).is_ok());

        let err = Pin::new(&mut adapter)
            .start_send(second)
            .expect_err("a second send before flush should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(adapter.pending.as_ref(), Some(&first));
        assert!(socket.attempts().is_empty());
    }

    #[test]
    fn test_stream_sink_keeps_pending_message_when_queue_is_full() {
        let socket = RecordingSendSocket::new(vec![Poll::Pending, Poll::Ready(Ok(()))]);
        let mut adapter = SocketStreamSink::new(socket.clone());
        let message = multipart_message();
        let mut cx = test_context();

        assert!(Pin::new(&mut adapter).start_send(message.clone()).is_ok());
        assert!(matches!(
            Pin::new(&mut adapter).poll_flush(&mut cx),
            Poll::Pending
        ));
        assert_eq!(adapter.pending.as_ref(), Some(&message));

        assert!(matches!(
            Pin::new(&mut adapter).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(adapter.pending.is_none());
        assert_eq!(socket.attempts(), vec![message.clone(), message]);
    }

    #[test]
    fn test_stream_sink_keeps_pending_message_when_send_errors() {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "send failed");
        let socket = RecordingSendSocket::new(vec![
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send failed",
            ))),
            Poll::Ready(Ok(())),
        ]);
        let mut adapter = SocketStreamSink::new(socket.clone());
        let message = multipart_message();
        let mut cx = test_context();

        assert!(Pin::new(&mut adapter).start_send(message.clone()).is_ok());
        let observed = match Pin::new(&mut adapter).poll_flush(&mut cx) {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected send error, got {other:?}"),
        };
        assert_eq!(observed.kind(), error.kind());
        assert_eq!(adapter.pending.as_ref(), Some(&message));
        assert_eq!(socket.attempts(), vec![message.clone()]);

        assert!(matches!(
            Pin::new(&mut adapter).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(adapter.pending.is_none());
        assert_eq!(socket.attempts(), vec![message.clone(), message]);
    }
}
