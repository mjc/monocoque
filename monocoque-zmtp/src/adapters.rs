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
    ///
    /// If this returns [`Poll::Pending`], the socket must retain ownership of
    /// `msg` and complete the send on a later `poll_flush` call.
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
        self.pending = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(msg) = self.pending.take() {
            match Pin::new(&mut self.socket).poll_send(cx, msg) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
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
        self.pending = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(msg) = self.pending.take() {
            match Pin::new(&mut self.socket).poll_send(cx, msg) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
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
    use std::cell::Cell;
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    struct MockSendSocket {
        send_calls: Cell<usize>,
        flush_calls: Cell<usize>,
        pending_once: Cell<bool>,
    }

    impl MockSendSocket {
        fn new() -> Self {
            Self {
                send_calls: Cell::new(0),
                flush_calls: Cell::new(0),
                pending_once: Cell::new(true),
            }
        }
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    impl SendSocket for MockSendSocket {
        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _msg: Vec<Bytes>,
        ) -> Poll<io::Result<()>> {
            self.send_calls.set(self.send_calls.get() + 1);
            if self.pending_once.replace(false) {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_calls.set(self.flush_calls.get() + 1);
            Poll::Ready(Ok(()))
        }
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
    fn test_sink_flush_does_not_resend_pending_message() {
        let socket = MockSendSocket::new();
        let mut sink = SocketSink::new(socket);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut sink).start_send(vec![Bytes::from_static(b"hello")]),
            Ok(())
        ));
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Pending));
        assert!(matches!(Pin::new(&mut sink).poll_flush(&mut cx), Poll::Ready(Ok(()))));

        let socket = sink.into_inner();
        assert_eq!(socket.send_calls.get(), 1);
        assert_eq!(socket.flush_calls.get(), 1);
    }
}
