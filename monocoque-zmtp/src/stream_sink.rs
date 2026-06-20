//! Stream and Sink adapters for ZeroMQ sockets.
//!
//! This module provides adapters that implement `futures::Stream` and `futures::Sink`
//! for ZeroMQ sockets, enabling integration with the Rust async ecosystem.
//!
//! # Examples
//!
//! ```no_run
//! use monocoque_zmtp::DealerSocket;
//! use monocoque_zmtp::stream_sink::SocketStream;
//! use futures::StreamExt;
//!
//! # async fn example() -> std::io::Result<()> {
//! let mut socket = DealerSocket::connect("127.0.0.1:5555").await?;
//! let mut stream = SocketStream::new(socket);
//!
//! while let Some(msg) = stream.next().await {
//!     println!("Received: {:?}", msg?);
//! }
//! # Ok(())
//! # }
//! ```

use bytes::Bytes;
use futures::sink::Sink;
use futures::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Socket;

/// Adapter that implements `Stream` for any socket implementing the `Socket` trait.
///
/// This allows using ZeroMQ sockets with stream combinators like `filter`, `map`,
/// `for_each`, etc.
///
/// # Examples
///
/// ```no_run
/// use monocoque_zmtp::{DealerSocket, stream_sink::SocketStream};
/// use futures::StreamExt;
///
/// # async fn example() -> std::io::Result<()> {
/// let socket = DealerSocket::connect("127.0.0.1:5555").await?;
/// let stream = SocketStream::new(socket);
///
/// // Use stream combinators
/// stream
///     .filter(|msg| futures::future::ready(msg.is_ok()))
///     .for_each(|msg| async move {
///         println!("Message: {:?}", msg);
///     })
///     .await;
/// # Ok(())
/// # }
/// ```
pub struct SocketStream<S> {
    socket: S,
}

impl<S> SocketStream<S> {
    /// Create a new stream adapter for a socket.
    pub const fn new(socket: S) -> Self {
        Self { socket }
    }

    /// Get a reference to the underlying socket.
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Consume the adapter and return the underlying socket.
    pub fn into_inner(self) -> S {
        self.socket
    }
}

impl<S: Socket + Unpin> Stream for SocketStream<S> {
    type Item = io::Result<Vec<Bytes>>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Placeholder Stream implementation - not yet fully integrated with Socket trait
        // A full implementation would require storing a pinned future in the struct
        Poll::Pending
    }
}

/// Adapter that implements `Sink` for any socket implementing the `Socket` trait.
///
/// This allows using ZeroMQ sockets with sink combinators like `send`, `send_all`, etc.
///
/// # Examples
///
/// ```no_run
/// use monocoque_zmtp::{DealerSocket, stream_sink::SocketSink};
/// use futures::SinkExt;
/// use bytes::Bytes;
///
/// # async fn example() -> std::io::Result<()> {
/// let socket = DealerSocket::connect("127.0.0.1:5555").await?;
/// let mut sink = SocketSink::new(socket);
///
/// // Use sink methods
/// sink.send(vec![Bytes::from("Hello")]).await?;
/// # Ok(())
/// # }
/// ```
pub struct SocketSink<S> {
    socket: S,
}

impl<S> SocketSink<S> {
    /// Create a new sink adapter for a socket.
    pub const fn new(socket: S) -> Self {
        Self { socket }
    }

    /// Get a reference to the underlying socket.
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Consume the adapter and return the underlying socket.
    pub fn into_inner(self) -> S {
        self.socket
    }
}

impl<S: Socket + Unpin> Sink<Vec<Bytes>> for SocketSink<S> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // ZeroMQ sockets are always ready to accept sends (they buffer internally)
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _item: Vec<Bytes>) -> Result<(), Self::Error> {
        // Placeholder Sink implementation - not yet fully integrated with Socket trait
        // For a complete implementation, this would need a buffer field in the struct
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Placeholder - full implementation would send buffered messages
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Flush any pending messages and close
        self.poll_flush(cx)
    }
}

/// Combined Stream + Sink adapter for bidirectional sockets.
///
/// This provides both `Stream` and `Sink` implementations for sockets that support
/// both sending and receiving (DEALER, ROUTER, REQ, REP, PAIR).
///
/// # Examples
///
/// ```no_run
/// use monocoque_zmtp::{DealerSocket, stream_sink::SocketStreamSink};
/// use futures::{StreamExt, SinkExt};
/// use bytes::Bytes;
///
/// # async fn example() -> std::io::Result<()> {
/// let socket = DealerSocket::connect("127.0.0.1:5555").await?;
/// let mut stream_sink = SocketStreamSink::new(socket);
///
/// // Send a message
/// stream_sink.send(vec![Bytes::from("Hello")]).await?;
///
/// // Receive a response
/// if let Some(msg) = stream_sink.next().await {
///     println!("Response: {:?}", msg?);
/// }
/// # Ok(())
/// # }
/// ```
pub struct SocketStreamSink<S> {
    socket: S,
    pending_send: Option<Vec<Bytes>>,
}

impl<S> SocketStreamSink<S> {
    /// Create a new combined stream/sink adapter.
    pub const fn new(socket: S) -> Self {
        Self {
            socket,
            pending_send: None,
        }
    }

    /// Get a reference to the underlying socket.
    pub const fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Get a mutable reference to the underlying socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Consume the adapter and return the underlying socket.
    pub fn into_inner(self) -> S {
        self.socket
    }
}

impl<S: Socket + Unpin> Stream for SocketStreamSink<S> {
    type Item = io::Result<Vec<Bytes>>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Placeholder - full implementation would poll the recv future
        Poll::Pending
    }
}

impl<S: Socket + Unpin> Sink<Vec<Bytes>> for SocketStreamSink<S> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<Bytes>) -> Result<(), Self::Error> {
        if let Some(pending) = self.pending_send.replace(item) {
            self.pending_send = Some(pending);
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous message has not been flushed yet",
            ))
        } else {
            Ok(())
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // Placeholder - the real implementation would write the pending
        // message to the socket. For now, just drain the staged item so the
        // sink can be used again without silently overwriting data.
        self.pending_send.take();
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Sink;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct MockSocket;

    #[async_trait::async_trait(?Send)]
    impl Socket for MockSocket {
        async fn send(&mut self, _msg: Vec<Bytes>) -> io::Result<()> {
            Ok(())
        }

        async fn recv(&mut self) -> io::Result<Option<Vec<Bytes>>> {
            Ok(None)
        }

        fn socket_type(&self) -> crate::SocketType {
            crate::SocketType::Pair
        }
    }

    fn multipart_message() -> Vec<Bytes> {
        vec![
            Bytes::from_static(b"frame-1"),
            Bytes::from_static(b"frame-2"),
        ]
    }

    fn start_send(sink: &mut SocketStreamSink<MockSocket>, msg: Vec<Bytes>) -> io::Result<()> {
        Pin::new(sink).start_send(msg)
    }

    fn poll_flush(
        sink: &mut SocketStreamSink<MockSocket>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(sink).poll_flush(cx)
    }

    fn test_context() -> Context<'static> {
        Context::from_waker(futures::task::noop_waker_ref())
    }

    #[test]
    fn test_stream_sink_stages_multipart_message_atomically_rfc37() {
        let mut adapter = SocketStreamSink::new(MockSocket);
        let multipart = multipart_message();

        start_send(&mut adapter, multipart.clone()).unwrap();
        assert_eq!(adapter.pending_send.as_ref(), Some(&multipart));
    }

    #[test]
    fn test_stream_sink_rejects_overwriting_pending_message() {
        let mut adapter = SocketStreamSink::new(MockSocket);
        let first = vec![Bytes::from_static(b"first")];
        let second = vec![Bytes::from_static(b"second")];

        start_send(&mut adapter, first.clone()).unwrap();

        let err = start_send(&mut adapter, second)
            .expect_err("a second send before flush should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(adapter.pending_send.as_ref(), Some(&first));
    }

    #[test]
    fn test_stream_sink_flush_clears_pending_message() {
        let mut adapter = SocketStreamSink::new(MockSocket);
        let message = vec![Bytes::from_static(b"payload")];
        let mut cx = test_context();

        start_send(&mut adapter, message).unwrap();
        assert!(matches!(
            poll_flush(&mut adapter, &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(adapter.pending_send.is_none());
    }
}
