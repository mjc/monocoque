//! Throughput benchmarks for the fan-out and fan-in worker-pool topologies.
//!
//! These cover ground the single-connection PUSH/PULL benches cannot: one
//! ventilator spreading work across a pool of workers, and one sink merging a
//! pool of senders. Both use `PushFanOut` / `PullFanIn`.
//!
//! ## Methodology
//!
//! - Every socket runs on its own OS thread with its own compio runtime.
//! - `BATCH_SIZE` messages cross the pool per iteration, split evenly across
//!   `WORKERS` connections.
//! - Runtime, worker, connection setup, and the ZMTP handshake happen once per
//!   benchmark case and outside the timed window.
//! - Senders use write coalescing with a final flush, matching the maximum
//!   throughput path used by the cross-implementation bench peer.
//!
//! Fan-out has N parallel receivers, so each worker times its own receive window
//! from a shared start barrier and the iteration cost is the slowest worker's
//! window (the point at which the whole batch has landed). Fan-in has a single
//! sink, so the timer lives on the sink side exactly like the PUSH/PULL
//! throughput bench.

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
use monocoque::zmq::{PullFanIn, PullSocket, PushFanOut, PushSocket, SocketOptions};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MESSAGE_SIZES: &[usize] = &[64, 1024, 16384];
const BATCH_SIZE: usize = 10_000;
const WORKERS: usize = 4;

fn coalescing_options() -> SocketOptions {
    SocketOptions::default()
        .with_buffer_sizes(16384, 16384)
        .with_write_coalescing(true)
}

struct FanoutBench {
    worker_command_txs: Vec<mpsc::Sender<usize>>,
    worker_started_rx: mpsc::Receiver<()>,
    worker_elapsed_rx: mpsc::Receiver<Duration>,
    vent_command_tx: mpsc::Sender<usize>,
    vent_done_rx: mpsc::Receiver<()>,
    threads: Vec<JoinHandle<()>>,
}

impl FanoutBench {
    fn new(size: usize) -> Self {
        let payload = Bytes::from(vec![0u8; size]);
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (vent_command_tx, vent_command_rx) = mpsc::channel::<usize>();
        let (vent_done_tx, vent_done_rx) = mpsc::channel::<()>();
        let mut threads = Vec::with_capacity(WORKERS + 1);

        let vent_payload = payload.clone();
        threads.push(thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let mut fanout =
                    PushFanOut::accept_workers(&listener, WORKERS, coalescing_options())
                        .await
                        .unwrap();
                ready_tx.send(()).unwrap();

                while let Ok(count) = vent_command_rx.recv() {
                    if count == 0 {
                        break;
                    }

                    for _ in 0..count {
                        fanout.send_one(vent_payload.clone()).await.unwrap();
                    }
                    fanout.flush().await.unwrap();
                    vent_done_tx.send(()).unwrap();
                }
            });
        }));

        let port = port_rx.recv().unwrap();
        let mut worker_command_txs = Vec::with_capacity(WORKERS);
        let (worker_started_tx, worker_started_rx) = mpsc::channel::<()>();
        let (worker_elapsed_tx, worker_elapsed_rx) = mpsc::channel::<Duration>();

        for _ in 0..WORKERS {
            let (worker_command_tx, worker_command_rx) = mpsc::channel::<usize>();
            worker_command_txs.push(worker_command_tx);
            let worker_started_tx = worker_started_tx.clone();
            let worker_elapsed_tx = worker_elapsed_tx.clone();

            threads.push(thread::spawn(move || {
                let rt = monocoque::rt::LocalRuntime::new().unwrap();
                rt.block_on(async move {
                    let mut pull = PullSocket::connect(("127.0.0.1", port)).await.unwrap();

                    while let Ok(count) = worker_command_rx.recv() {
                        if count == 0 {
                            break;
                        }

                        let t0 = Instant::now();
                        worker_started_tx.send(()).unwrap();
                        for _ in 0..count {
                            pull.recv().await.unwrap();
                        }
                        worker_elapsed_tx.send(t0.elapsed()).unwrap();
                    }
                });
            }));
        }
        drop(worker_started_tx);
        drop(worker_elapsed_tx);
        ready_rx.recv().unwrap();

        let mut bench = Self {
            worker_command_txs,
            worker_started_rx,
            worker_elapsed_rx,
            vent_command_tx,
            vent_done_rx,
            threads,
        };
        bench.run_batch(WORKERS);
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
        assert_eq!(count % WORKERS, 0);
        let per_worker = count / WORKERS;

        for tx in &self.worker_command_txs {
            tx.send(per_worker).unwrap();
        }
        for _ in 0..WORKERS {
            self.worker_started_rx.recv().unwrap();
        }
        self.vent_command_tx.send(count).unwrap();

        let mut slowest = Duration::ZERO;
        for _ in 0..WORKERS {
            slowest = slowest.max(self.worker_elapsed_rx.recv().unwrap());
        }
        self.vent_done_rx.recv().unwrap();
        slowest
    }
}

impl Drop for FanoutBench {
    fn drop(&mut self) {
        let _ = self.vent_command_tx.send(0);
        for tx in &self.worker_command_txs {
            let _ = tx.send(0);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

struct FaninBench {
    worker_command_txs: Vec<mpsc::Sender<usize>>,
    worker_done_rx: mpsc::Receiver<()>,
    sink_command_tx: mpsc::Sender<usize>,
    sink_started_rx: mpsc::Receiver<()>,
    elapsed_rx: mpsc::Receiver<Duration>,
    threads: Vec<JoinHandle<()>>,
}

impl FaninBench {
    fn new(size: usize, coalesce: bool) -> Self {
        let payload = Bytes::from(vec![0u8; size]);
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (sink_command_tx, sink_command_rx) = mpsc::channel::<usize>();
        let (sink_started_tx, sink_started_rx) = mpsc::channel::<()>();
        let (elapsed_tx, elapsed_rx) = mpsc::channel::<Duration>();
        let mut threads = Vec::with_capacity(WORKERS + 1);

        threads.push(thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let mut sink = PullFanIn::accept_workers(
                    &listener,
                    WORKERS,
                    SocketOptions::default().with_buffer_sizes(16384, 16384),
                )
                .await
                .unwrap();
                ready_tx.send(()).unwrap();

                while let Ok(count) = sink_command_rx.recv() {
                    if count == 0 {
                        break;
                    }

                    let t0 = Instant::now();
                    sink_started_tx.send(()).unwrap();
                    let mut received = 0usize;
                    while received < count {
                        match sink.recv_batch().await.unwrap() {
                            Some(batch) => received += batch.len(),
                            None => panic!(
                                "fan-in sink closed before receiving {count} messages; got {received}"
                            ),
                        }
                    }
                    elapsed_tx.send(t0.elapsed()).unwrap();
                }
            });
        }));

        let port = port_rx.recv().unwrap();
        let mut worker_command_txs = Vec::with_capacity(WORKERS);
        let (worker_done_tx, worker_done_rx) = mpsc::channel::<()>();

        for _ in 0..WORKERS {
            let (worker_command_tx, worker_command_rx) = mpsc::channel::<usize>();
            worker_command_txs.push(worker_command_tx);
            let worker_done_tx = worker_done_tx.clone();
            let worker_payload = payload.clone();

            threads.push(thread::spawn(move || {
                let rt = monocoque::rt::LocalRuntime::new().unwrap();
                rt.block_on(async move {
                    let options = if coalesce {
                        coalescing_options()
                    } else {
                        SocketOptions::default().with_buffer_sizes(16384, 16384)
                    };
                    let mut push = PushSocket::connect_with_options(("127.0.0.1", port), options)
                        .await
                        .unwrap();

                    while let Ok(count) = worker_command_rx.recv() {
                        if count == 0 {
                            break;
                        }

                        for _ in 0..count {
                            push.send_one(worker_payload.clone()).await.unwrap();
                        }
                        push.flush().await.unwrap();
                        worker_done_tx.send(()).unwrap();
                    }
                });
            }));
        }
        drop(worker_done_tx);
        ready_rx.recv().unwrap();

        let mut bench = Self {
            worker_command_txs,
            worker_done_rx,
            sink_command_tx,
            sink_started_rx,
            elapsed_rx,
            threads,
        };
        bench.run_batch(WORKERS);
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
        assert_eq!(count % WORKERS, 0);
        let per_worker = count / WORKERS;

        self.sink_command_tx.send(count).unwrap();
        self.sink_started_rx.recv().unwrap();
        for tx in &self.worker_command_txs {
            tx.send(per_worker).unwrap();
        }

        let elapsed = self.elapsed_rx.recv().unwrap();
        for _ in 0..WORKERS {
            self.worker_done_rx.recv().unwrap();
        }
        elapsed
    }
}

impl Drop for FaninBench {
    fn drop(&mut self) {
        let _ = self.sink_command_tx.send(0);
        for tx in &self.worker_command_txs {
            let _ = tx.send(0);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Fan-out: one `PushFanOut` ventilator round-robins `BATCH_SIZE` messages across
/// `WORKERS` PULL workers.
///
/// The ventilator and all workers meet at a barrier so they start together. Each
/// worker times its own receive window and reports it; the iteration cost is the
/// slowest worker's window, i.e. when the last message of the batch arrives.
fn monocoque_fanout(c: &mut Criterion) {
    monocoque::dev_tracing::init_tracing();
    let mut group = c.benchmark_group(format!("fanout_fanin/monocoque-{BENCH_BACKEND}/fanout"));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = FanoutBench::new(size);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

/// Fan-in with write-coalescing senders: many messages per kernel write, so each
/// kernel read on the sink carries a big batch.
fn monocoque_fanin_coalesced(c: &mut Criterion) {
    fanin(
        c,
        &format!("fanout_fanin/monocoque-{BENCH_BACKEND}/fanin_coalesced"),
        true,
    );
}

/// Fan-in with eager senders: one kernel write per message, so a kernel read on
/// the sink may carry as little as one message. This is the case where batching
/// the merge channel could in principle add overhead rather than amortize it.
fn monocoque_fanin_eager(c: &mut Criterion) {
    fanin(
        c,
        &format!("fanout_fanin/monocoque-{BENCH_BACKEND}/fanin_eager"),
        false,
    );
}

/// Fan-in: `WORKERS` PUSH workers each send `PER_WORKER` messages to one
/// `PullFanIn` sink.
///
/// The sink is the single receiver, so the timer lives on its side: it starts
/// just before the first merged recv and stops after the whole batch is drained.
/// `coalesce` selects whether the senders batch writes or send eagerly.
fn fanin(c: &mut Criterion, group_name: &str, coalesce: bool) {
    monocoque::dev_tracing::init_tracing();
    let mut group = c.benchmark_group(group_name);
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    for &size in MESSAGE_SIZES {
        group.throughput(Throughput::Elements(BATCH_SIZE as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut bench = FaninBench::new(size, coalesce);
            b.iter_custom(|iters| bench.run_iterations(iters));
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .warm_up_time(Duration::from_secs(5))
        .sample_size(10);
    targets =
        monocoque_fanout,
        monocoque_fanin_coalesced,
        monocoque_fanin_eager
);
criterion_main!(benches);
