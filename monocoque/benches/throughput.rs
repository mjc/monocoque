//! Throughput benchmarks: messages per second (PUSH/PULL one-way)
//!
//! Compares monocoque vs rust-zmq (zmq crate, FFI bindings to libzmq) for raw throughput.
//! Measures how many messages can be delivered per second in a PUSH->PULL pipeline.
//!
//! ## Methodology
//!
//! - Sender and receiver run on separate OS threads, each with their own compio runtime.
//! - Runtime, socket, listener, and handshake setup happens once per benchmark case.
//! - Timer starts on the PULL side just before the first recv.
//! - Both monocoque and zmq use the same protocol: one send per message, no reply.
//! - Warmup happens outside measurement (connection setup + handshake).
//! - `monocoque_push_pull_coalesced` uses write coalescing (64 KB flush threshold) to
//!   batch multiple sends into a single kernel write, closing the gap with libzmq's
//!   internal IO-thread batching.

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

// Identifies which runtime backend this build benchmarks, so compio and tokio
// results land under distinct criterion ids instead of overwriting each other.
const BENCH_BACKEND: &str = if cfg!(feature = "runtime-tokio") {
    "tokio"
} else {
    "compio"
};
use monocoque::rt::TcpListener;
use monocoque::zmq::{PullSocket, PushSocket, SocketOptions};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MESSAGE_SIZES: &[usize] = &[64, 256, 1024, 4096, 16384];
const BATCH_SIZE: usize = 10_000;

#[derive(Clone, Copy)]
enum MonocoqueRecvMode {
    Allocating,
    ReuseBuffer,
}

struct MonocoquePushPullBench {
    payload: Bytes,
    coalesced: bool,
    push_rt: monocoque::rt::LocalRuntime,
    push: PushSocket,
    command_tx: mpsc::Sender<usize>,
    started_rx: mpsc::Receiver<()>,
    elapsed_rx: mpsc::Receiver<Duration>,
    pull_thread: Option<JoinHandle<()>>,
}

impl MonocoquePushPullBench {
    fn new(size: usize, coalesced: bool, recv_mode: MonocoqueRecvMode) -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (elapsed_tx, elapsed_rx) = mpsc::channel::<Duration>();

        let pull_thread = thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let (stream, _) = listener.accept().await.unwrap();
                let mut pull = PullSocket::from_tcp_with_options(
                    stream,
                    SocketOptions::default().with_buffer_sizes(16384, 16384),
                )
                .await
                .unwrap();
                let mut msg: Vec<Bytes> = Vec::with_capacity(4);

                while let Ok(count) = command_rx.recv() {
                    if count == 0 {
                        break;
                    }

                    let t0 = Instant::now();
                    started_tx.send(()).unwrap();
                    for _ in 0..count {
                        match recv_mode {
                            MonocoqueRecvMode::Allocating => {
                                pull.recv().await.unwrap();
                            }
                            MonocoqueRecvMode::ReuseBuffer => {
                                assert!(pull.recv_into(&mut msg).await.unwrap());
                            }
                        }
                    }
                    elapsed_tx.send(t0.elapsed()).unwrap();
                }
            });
        });

        let port = port_rx.recv().unwrap();
        let push_rt = monocoque::rt::LocalRuntime::new().unwrap();
        let options = SocketOptions::default()
            .with_buffer_sizes(16384, 16384)
            .with_write_coalescing(coalesced);
        let push = push_rt
            .block_on(PushSocket::connect_with_options(
                ("127.0.0.1", port),
                options,
            ))
            .unwrap();

        let mut bench = Self {
            payload: Bytes::from(vec![0u8; size]),
            coalesced,
            push_rt,
            push,
            command_tx,
            started_rx,
            elapsed_rx,
            pull_thread: Some(pull_thread),
        };
        bench.run_batch(1);
        bench
    }

    fn run_iterations(&mut self, iters: u64) -> Duration {
        let mut total = Duration::ZERO;
        for _ in 0..iters {
            total += self.run_batch(BATCH_SIZE);
        }
        total
    }

    fn run_batch(&mut self, count: usize) -> Duration {
        self.command_tx.send(count).unwrap();
        self.started_rx.recv().unwrap();
        self.push_rt.block_on(async {
            for _ in 0..count {
                self.push.send_one(self.payload.clone()).await.unwrap();
            }
            if self.coalesced {
                self.push.flush().await.unwrap();
            }
        });
        self.elapsed_rx.recv().unwrap()
    }
}

impl Drop for MonocoquePushPullBench {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(pull_thread) = self.pull_thread.take() {
            let _ = pull_thread.join();
        }
    }
}

struct ZmqPushPullBench {
    payload: Vec<u8>,
    push: zmq::Socket,
    _ctx: zmq::Context,
    command_tx: mpsc::Sender<usize>,
    started_rx: mpsc::Receiver<()>,
    elapsed_rx: mpsc::Receiver<Duration>,
    pull_thread: Option<JoinHandle<()>>,
}

impl ZmqPushPullBench {
    fn new(size: usize) -> Self {
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<String>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (elapsed_tx, elapsed_rx) = mpsc::channel::<Duration>();

        let pull_thread = thread::spawn(move || {
            let ctx = zmq::Context::new();
            let pull = ctx.socket(zmq::PULL).unwrap();
            pull.bind("tcp://127.0.0.1:*").unwrap();
            endpoint_tx
                .send(pull.get_last_endpoint().unwrap().unwrap())
                .unwrap();

            while let Ok(count) = command_rx.recv() {
                if count == 0 {
                    break;
                }

                let t0 = Instant::now();
                started_tx.send(()).unwrap();
                for _ in 0..count {
                    pull.recv_bytes(0).unwrap();
                }
                elapsed_tx.send(t0.elapsed()).unwrap();
            }
        });

        let endpoint = endpoint_rx.recv().unwrap();
        thread::sleep(Duration::from_millis(5));

        let ctx = zmq::Context::new();
        let push = ctx.socket(zmq::PUSH).unwrap();
        push.connect(&endpoint).unwrap();

        let mut bench = Self {
            payload: vec![0u8; size],
            push,
            _ctx: ctx,
            command_tx,
            started_rx,
            elapsed_rx,
            pull_thread: Some(pull_thread),
        };
        bench.run_batch(1);
        bench
    }

    fn run_iterations(&mut self, iters: u64) -> Duration {
        let mut total = Duration::ZERO;
        for _ in 0..iters {
            total += self.run_batch(BATCH_SIZE);
        }
        total
    }

    fn run_batch(&mut self, count: usize) -> Duration {
        self.command_tx.send(count).unwrap();
        self.started_rx.recv().unwrap();
        for _ in 0..count {
            self.push.send(&self.payload, 0).unwrap();
        }
        self.elapsed_rx.recv().unwrap()
    }
}

impl Drop for ZmqPushPullBench {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(pull_thread) = self.pull_thread.take() {
            let _ = pull_thread.join();
        }
    }
}

/// Benchmark monocoque PUSH/PULL throughput - eager (one syscall per message).
///
/// PULL binds on a separate OS thread (own compio runtime). PUSH connects and
/// sends in the bench thread. The timer lives on the PULL side: it starts just
/// before the first recv and stops after the last one. That elapsed duration is
/// returned to criterion via `iter_custom`.
fn monocoque_push_pull(c: &mut Criterion) {
    monocoque::dev_tracing::init_tracing();
    let mut group = c.benchmark_group(format!("throughput/monocoque-{BENCH_BACKEND}/push_pull"));
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = MonocoquePushPullBench::new(size, false, MonocoqueRecvMode::Allocating);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

/// Benchmark monocoque PUSH/PULL throughput - with write coalescing enabled.
///
/// Same structure as `monocoque_push_pull` but the PUSH socket batches encoded
/// messages into a 64 KB internal buffer before writing to the kernel.  A
/// manual `flush()` after the loop drains any remainder.  This mirrors the
/// batching that libzmq performs internally via its IO-thread queue.
fn monocoque_push_pull_coalesced(c: &mut Criterion) {
    monocoque::dev_tracing::init_tracing();
    let mut group = c.benchmark_group(format!(
        "throughput/monocoque-{BENCH_BACKEND}/push_pull_coalesced"
    ));
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = MonocoquePushPullBench::new(size, true, MonocoqueRecvMode::Allocating);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

/// Benchmark monocoque PUSH/PULL throughput - coalesced, PULL side using
/// `recv_into` with a reused buffer.
///
/// Identical to `monocoque_push_pull_coalesced` except the PULL loop reuses one
/// `Vec` across calls via `recv_into`, removing the per-message message-`Vec`
/// allocation. Comparing the two isolates how much that allocation costs.
fn monocoque_push_pull_coalesced_recv_into(c: &mut Criterion) {
    monocoque::dev_tracing::init_tracing();
    let mut group = c.benchmark_group(format!(
        "throughput/monocoque-{BENCH_BACKEND}/push_pull_coalesced_recv_into"
    ));
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = MonocoquePushPullBench::new(size, true, MonocoqueRecvMode::ReuseBuffer);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

/// Benchmark rust-zmq (libzmq) PUSH/PULL throughput.
///
/// Same structure as `monocoque_push_pull`: PULL binds in a separate thread,
/// PUSH connects in the bench thread. Timer on the PULL side.
fn zmq_push_pull(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput/zmq/push_pull");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = ZmqPushPullBench::new(size);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(60))
        .warm_up_time(Duration::from_secs(5))
        .sample_size(10);
    targets =
        monocoque_push_pull,
        monocoque_push_pull_coalesced,
        monocoque_push_pull_coalesced_recv_into,
        zmq_push_pull
);
criterion_main!(benches);
