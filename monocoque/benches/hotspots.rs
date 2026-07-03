//! Benchmarks for hot paths that were not previously covered.
//!
//! Run with:
//! `cargo bench --package monocoque -F zmq --bench hotspots`

use bytes::Bytes;
use criterion::{
    black_box, criterion_group, criterion_main, Criterion, Throughput,
};
use monocoque::zmq::{ReqSocket, RepSocket, SocketOptions};
use monocoque_core::inproc::{bind_inproc, connect_inproc, unbind_inproc};
use monocoque_core::message_builder::Message;
use monocoque_zmtp::proxy::{proxy, ProxySocket};
use monocoque_zmtp::security::curve::{CurveClient, CurveKeyPair, CurveServer};
use monocoque_zmtp::security::PlainAuthHandler;
use monocoque_zmtp::security::zap_handler::start_default_zap_server;
use monocoque_zmtp::stream::StreamSocket;
use std::cell::Cell;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static ENDPOINT_ID: AtomicUsize = AtomicUsize::new(0);

fn next_endpoint(label: &str) -> String {
    let id = ENDPOINT_ID.fetch_add(1, Ordering::Relaxed);
    format!("bench-{label}-{id}")
}

#[derive(Debug)]
struct AllowSingleUser {
    username: &'static str,
    password: &'static str,
}

#[async_trait::async_trait(?Send)]
impl PlainAuthHandler for AllowSingleUser {
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
        _domain: &str,
        _address: &str,
    ) -> Result<String, String> {
        if username == self.username && password == self.password {
            Ok(username.to_string())
        } else {
            Err("invalid credentials".to_string())
        }
    }
}

#[derive(Debug)]
enum RecvBehavior {
    MessageThenError {
        message: Vec<Bytes>,
        delivered: Cell<bool>,
    },
    Pending,
}

#[derive(Debug)]
struct MockProxySocket {
    name: &'static str,
    recv_behavior: RecvBehavior,
    sent_messages: Vec<Vec<Bytes>>,
}

impl MockProxySocket {
    fn message_then_error(name: &'static str, message: Vec<Bytes>) -> Self {
        Self {
            name,
            recv_behavior: RecvBehavior::MessageThenError {
                message,
                delivered: Cell::new(false),
            },
            sent_messages: Vec::new(),
        }
    }

    fn pending(name: &'static str) -> Self {
        Self {
            name,
            recv_behavior: RecvBehavior::Pending,
            sent_messages: Vec::new(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl ProxySocket for MockProxySocket {
    async fn recv_multipart(&mut self) -> io::Result<Option<Vec<Bytes>>> {
        match &self.recv_behavior {
            RecvBehavior::MessageThenError { message, delivered } => {
                if delivered.get() {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "done"))
                } else {
                    delivered.set(true);
                    Ok(Some(message.clone()))
                }
            }
            RecvBehavior::Pending => std::future::pending().await,
        }
    }

    async fn send_multipart(&mut self, msg: Vec<Bytes>) -> io::Result<()> {
        self.sent_messages.push(msg);
        Ok(())
    }

    fn socket_desc(&self) -> &'static str {
        self.name
    }
}

struct StreamSendHarness {
    socket: StreamSocket,
    routing_id: Bytes,
    payload: Bytes,
}

struct StreamRecvHarness {
    socket: StreamSocket,
    client: compio::net::TcpStream,
    payload: Bytes,
}

fn bench_builder_control_allocs(c: &mut Criterion) {
    let mut group = c.benchmark_group("builder_control_allocs");

    group.bench_function("push_str_two_frames", |b| {
        b.iter(|| {
            let msg = Message::new()
                .push_str(black_box("topic"))
                .push_str(black_box("payload"));
            black_box(msg);
        });
    });

    group.bench_function("push_u32_u64", |b| {
        b.iter(|| {
            let msg = Message::new()
                .push_u32(black_box(12345))
                .push_u64(black_box(67890));
            black_box(msg);
        });
    });

    group.finish();
}

fn bench_proxy_capture(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_capture");
    let rt = compio::runtime::Runtime::new().unwrap();
    let msg = vec![
        Bytes::from(vec![0u8; 32]),
        Bytes::from(vec![0u8; 128]),
        Bytes::from(vec![0u8; 512]),
    ];

    group.bench_function("forward_once_capture", |b| {
        b.iter(|| {
            let result = rt.block_on(async {
                let mut frontend = MockProxySocket::message_then_error("frontend", msg.clone());
                let mut backend = MockProxySocket::pending("backend");
                let mut capture = MockProxySocket::pending("capture");
                proxy(&mut frontend, &mut backend, Some(&mut capture)).await
            });

            let _ = black_box(result);
        });
    });

    group.bench_function("forward_once_no_capture", |b| {
        b.iter(|| {
            let result = rt.block_on(async {
                let mut frontend = MockProxySocket::message_then_error("frontend", msg.clone());
                let mut backend = MockProxySocket::pending("backend");
                proxy::<MockProxySocket, MockProxySocket, MockProxySocket>(
                    &mut frontend,
                    &mut backend,
                    None,
                )
                .await
            });

            let _ = black_box(result);
        });
    });

    group.finish();
}

fn setup_stream_send(rt: &compio::runtime::Runtime) -> StreamSendHarness {
    rt.block_on(async {
        use compio::buf::BufResult;
        use compio::io::AsyncRead;
        use monocoque_core::alloc::IoArena;

        let mut socket = StreamSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let client = compio::net::TcpStream::connect(addr).await.unwrap();
        let routing_id = socket.accept_raw().await.unwrap();
        let _ = socket.recv().await.unwrap().unwrap();

        let (mut read_half, _write_half) = client.into_split();
        compio::runtime::spawn(async move {
            let mut arena = IoArena::new();
            loop {
                let slab = arena.alloc_mut(8192);
                let BufResult(result, _slab) = read_half.read(slab).await;
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .detach();

        StreamSendHarness {
            socket,
            routing_id,
            payload: Bytes::from(vec![0u8; 1024]),
        }
    })
}

fn setup_stream_recv(rt: &compio::runtime::Runtime) -> StreamRecvHarness {
    rt.block_on(async {
        let mut socket = StreamSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let client = compio::net::TcpStream::connect(addr).await.unwrap();
        let _routing_id = socket.accept_raw().await.unwrap();
        let _ = socket.recv().await.unwrap().unwrap();

        StreamRecvHarness {
            socket,
            client,
            payload: Bytes::from(vec![0u8; 1024]),
        }
    })
}

fn bench_stream_transport(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_transport");
    let rt = compio::runtime::Runtime::new().unwrap();
    let mut send_harness = setup_stream_send(&rt);
    let mut recv_harness = setup_stream_recv(&rt);

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("send_1kb_frame", |b| {
        b.iter(|| {
            rt.block_on(async {
                send_harness
                    .socket
                    .send(vec![
                        send_harness.routing_id.clone(),
                        Bytes::new(),
                        send_harness.payload.clone(),
                    ])
                    .await
                    .unwrap();
            });
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("recv_1kb_frame", |b| {
        b.iter(|| {
            rt.block_on(async {
                use compio::io::AsyncWriteExt;

                recv_harness
                    .client
                    .write_all(recv_harness.payload.clone())
                    .await
                    .unwrap();
                let msg = recv_harness.socket.recv().await.unwrap().unwrap();
                black_box(msg);
            });
        });
    });

    group.finish();
}

fn bench_inproc_transport(c: &mut Criterion) {
    let mut group = c.benchmark_group("inproc_transport");
    let endpoint = format!("inproc://{}", next_endpoint("roundtrip"));
    let (server_tx, server_rx) = bind_inproc(&endpoint).unwrap();
    let client = connect_inproc(&endpoint).unwrap();
    let message = vec![Bytes::from(vec![0u8; 1024])];

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("message_roundtrip_1kb", |b| {
        b.iter(|| {
            client.send(message.clone()).unwrap();
            let received = server_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("inproc roundtrip should complete");
            black_box(received);
        });
    });

    drop(server_tx);
    unbind_inproc(&endpoint).unwrap();
    group.finish();
}

fn bench_connection_latency(c: &mut Criterion) {
    const CONNECTIONS: usize = 25;

    let mut group = c.benchmark_group("connection_latency");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));

    let rt = compio::runtime::Runtime::new().unwrap();
    let options = SocketOptions::default().with_buffer_sizes(4096, 4096);

    group.bench_function("req_connect", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = compio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let server_addr = listener.local_addr().unwrap();
                let server_options = options.clone();
                let client_options = options.clone();

                let server_task = compio::runtime::spawn(async move {
                    for _ in 0..CONNECTIONS {
                        let (stream, _) = listener.accept().await.unwrap();
                        let _ = RepSocket::from_tcp_with_options(stream, server_options.clone())
                            .await
                            .unwrap();
                    }
                });

                for _ in 0..CONNECTIONS {
                    let stream = compio::net::TcpStream::connect(server_addr).await.unwrap();
                    let req = ReqSocket::from_tcp_with_options(stream, client_options.clone())
                        .await
                        .unwrap();
                    black_box(req);
                }

                server_task.await;
            })
        });
    });

    group.finish();
}

fn bench_security_handshakes(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_handshakes");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(10));
    let rt = compio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let handler = AllowSingleUser {
            username: "bench-user",
            password: "bench-pass",
        };
        start_default_zap_server(Arc::new(handler), false).unwrap();
        compio::time::sleep(Duration::from_millis(50)).await;
    });

    group.bench_function("plain_handshake", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = compio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let addr = listener.local_addr().unwrap();
                let server_options = SocketOptions::new()
                    .with_plain_server(true)
                    .with_zap_domain("bench-domain")
                    .with_recv_timeout(Duration::from_secs(5));
                let client_options = SocketOptions::new()
                    .with_plain_credentials("bench-user", "bench-pass")
                    .with_zap_domain("bench-domain")
                    .with_recv_timeout(Duration::from_secs(5));

                let server_task = compio::runtime::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let server = RepSocket::from_tcp_with_options(stream, server_options)
                        .await
                        .unwrap();
                    black_box(server);
                });

                let client = ReqSocket::connect_with_options(&addr.to_string(), client_options)
                    .await
                    .unwrap();
                black_box(client);

                server_task.await;
            });
        });
    });

    group.bench_function("curve_handshake", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = compio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let addr = listener.local_addr().unwrap();

                let server_keypair = CurveKeyPair::generate();
                let client_keypair = CurveKeyPair::generate();
                let server_public = server_keypair.public;

                let server_task = compio::runtime::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut server = CurveServer::new(server_keypair);
                    let client_public = server
                        .handshake(&mut stream, Some(Duration::from_secs(5)))
                        .await
                        .unwrap();
                    black_box(client_public);
                });

                let mut stream = compio::net::TcpStream::connect(addr).await.unwrap();
                let mut client = CurveClient::new(client_keypair, server_public);
                client
                    .handshake(&mut stream, Some(Duration::from_secs(5)))
                    .await
                    .unwrap();

                server_task.await;
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_builder_control_allocs,
    bench_proxy_capture,
    bench_stream_transport,
    bench_inproc_transport,
    bench_connection_latency,
    bench_security_handshakes
);
criterion_main!(benches);
