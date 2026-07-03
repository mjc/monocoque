//! Focused PUSH/PULL profiler for the 64-byte coalesced throughput claim.
//!
//! This is deliberately not a Criterion benchmark. It answers one question:
//! for the steady-state coalesced path, is the sender side or receiver side the
//! longer pole, and does that change across runtime backends?

use bytes::Bytes;
use compio_buf::BufResult;
use compio_io::{AsyncReadExt, AsyncWriteExt};
use monocoque::rt::TcpListener;
use monocoque::rt::TcpStream;
use monocoque::zmq::{PullSocket, PushSocket, SocketOptions};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const BACKEND: &str = if cfg!(feature = "runtime-tokio") {
    "tokio"
} else {
    "compio"
};

const BATCH_SIZE: usize = 10_000;
const BATCHES: usize = 1_000;
const WARMUP_BATCHES: usize = 25;
const RAW_SMALL_BATCHES: usize = 250;
const RAW_MULTI_BATCHES: usize = 50;
const RAW_MULTI_WARMUP_BATCHES: usize = 5;
const MESSAGE_SIZE: usize = 64;
const RAW_CONNECTIONS: usize = 16;

#[derive(Clone, Copy)]
enum RecvMode {
    Allocating,
    ReuseBuffer,
    Batch,
}

impl RecvMode {
    fn name(self) -> &'static str {
        match self {
            Self::Allocating => "recv",
            Self::ReuseBuffer => "recv_into",
            Self::Batch => "recv_batch",
        }
    }
}

struct PushPullProfile {
    payload: Bytes,
    push_rt: monocoque::rt::LocalRuntime,
    push: PushSocket,
    command_tx: mpsc::Sender<usize>,
    receiver_elapsed_rx: mpsc::Receiver<Duration>,
    receiver_thread: Option<JoinHandle<()>>,
}

impl PushPullProfile {
    fn new(mode: RecvMode) -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (receiver_elapsed_tx, receiver_elapsed_rx) = mpsc::channel::<Duration>();

        let receiver_thread = thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let (stream, _) = listener.accept().await.unwrap();
                let mut pull = PullSocket::from_tcp_with_options(
                    stream,
                    SocketOptions::default().with_buffer_sizes(16_384, 16_384),
                )
                .await
                .unwrap();
                let mut msg = Vec::with_capacity(4);

                while let Ok(count) = command_rx.recv() {
                    if count == 0 {
                        break;
                    }

                    let start = std::time::Instant::now();
                    match mode {
                        RecvMode::Allocating => {
                            for _ in 0..count {
                                pull.recv().await.unwrap();
                            }
                        }
                        RecvMode::ReuseBuffer => {
                            for _ in 0..count {
                                assert!(pull.recv_into(&mut msg).await.unwrap());
                            }
                        }
                        RecvMode::Batch => {
                            let mut received = 0;
                            while received < count {
                                received += pull.recv_batch().await.unwrap().unwrap().len();
                            }
                        }
                    }
                    receiver_elapsed_tx.send(start.elapsed()).unwrap();
                }
            });
        });

        let port = port_rx.recv().unwrap();
        let push_rt = monocoque::rt::LocalRuntime::new().unwrap();
        let push = push_rt
            .block_on(PushSocket::connect_with_options(
                ("127.0.0.1", port),
                SocketOptions::default()
                    .with_buffer_sizes(16_384, 16_384)
                    .with_write_coalescing(true),
            ))
            .unwrap();

        Self {
            payload: Bytes::from(vec![0u8; MESSAGE_SIZE]),
            push_rt,
            push,
            command_tx,
            receiver_elapsed_rx,
            receiver_thread: Some(receiver_thread),
        }
    }

    fn run_batch(&mut self, count: usize) -> (Duration, Duration) {
        self.command_tx.send(count).unwrap();

        let sender_start = std::time::Instant::now();
        self.push_rt.block_on(async {
            for _ in 0..count {
                self.push.send(vec![self.payload.clone()]).await.unwrap();
            }
            self.push.flush().await.unwrap();
        });
        let sender_elapsed = sender_start.elapsed();

        let receiver_elapsed = self.receiver_elapsed_rx.recv().unwrap();
        (sender_elapsed, receiver_elapsed)
    }
}

impl Drop for PushPullProfile {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(receiver_thread) = self.receiver_thread.take() {
            let _ = receiver_thread.join();
        }
    }
}

fn main() {
    for mode in [RecvMode::Allocating, RecvMode::ReuseBuffer, RecvMode::Batch] {
        let mut profile = PushPullProfile::new(mode);
        for _ in 0..WARMUP_BATCHES {
            profile.run_batch(BATCH_SIZE);
        }

        let mut sender = Vec::with_capacity(BATCHES);
        let mut receiver = Vec::with_capacity(BATCHES);
        for _ in 0..BATCHES {
            let (sender_elapsed, receiver_elapsed) = profile.run_batch(BATCH_SIZE);
            sender.push(sender_elapsed);
            receiver.push(receiver_elapsed);
        }

        print_summary(mode, &sender, &receiver);
    }

    let mut raw = RawTcpProfile::new(RawMode::BatchWrite);
    run_raw_profile(
        "raw TCP 640KB batch write",
        BATCH_SIZE,
        WARMUP_BATCHES,
        BATCHES,
        || raw.run_batch(),
    );

    let mut raw = RawTcpProfile::new(RawMode::SmallWrites);
    run_raw_profile(
        "raw TCP 10K small writes",
        BATCH_SIZE,
        WARMUP_BATCHES,
        RAW_SMALL_BATCHES,
        || raw.run_batch(),
    );

    let mut raw = RawMultiTcpProfile::new(RAW_CONNECTIONS);
    run_raw_profile(
        "raw TCP 16 connections, 10K small writes each",
        BATCH_SIZE * RAW_CONNECTIONS,
        RAW_MULTI_WARMUP_BATCHES,
        RAW_MULTI_BATCHES,
        || raw.run_batch(),
    );
}

fn print_summary(mode: RecvMode, sender: &[Duration], receiver: &[Duration]) {
    let sender_median = median(sender);
    let receiver_median = median(receiver);
    let sender_best = sender.iter().min().copied().unwrap();
    let receiver_best = receiver.iter().min().copied().unwrap();

    println!(
        "{BACKEND} {mode} {MESSAGE_SIZE}B coalesced, {BATCHES}x{BATCH_SIZE} messages",
        mode = mode.name()
    );
    println!(
        "  sender:   median {:>8.3} us ({:>6.2} Mmsg/s), best {:>8.3} us ({:>6.2} Mmsg/s)",
        micros(sender_median),
        mps(sender_median),
        micros(sender_best),
        mps(sender_best)
    );
    println!(
        "  receiver: median {:>8.3} us ({:>6.2} Mmsg/s), best {:>8.3} us ({:>6.2} Mmsg/s)",
        micros(receiver_median),
        mps(receiver_median),
        micros(receiver_best),
        mps(receiver_best)
    );
}

fn run_raw_profile(
    label: &str,
    messages_per_sample: usize,
    warmups: usize,
    batches: usize,
    mut run_batch: impl FnMut() -> (Duration, Duration),
) {
    for _ in 0..warmups {
        run_batch();
    }

    let mut sender = Vec::with_capacity(batches);
    let mut receiver = Vec::with_capacity(batches);
    for _ in 0..batches {
        let (sender_elapsed, receiver_elapsed) = run_batch();
        sender.push(sender_elapsed);
        receiver.push(receiver_elapsed);
    }
    print_raw_summary(label, messages_per_sample, batches, &sender, &receiver);
}

fn median(values: &[Duration]) -> Duration {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn mps(duration: Duration) -> f64 {
    BATCH_SIZE as f64 / duration.as_secs_f64() / 1_000_000.0
}

#[derive(Clone, Copy)]
enum RawMode {
    BatchWrite,
    SmallWrites,
}

struct RawTcpProfile {
    payload: Bytes,
    mode: RawMode,
    rt: monocoque::rt::LocalRuntime,
    stream: TcpStream,
    command_tx: mpsc::Sender<usize>,
    receiver_elapsed_rx: mpsc::Receiver<Duration>,
    receiver_thread: Option<JoinHandle<()>>,
}

impl RawTcpProfile {
    fn new(mode: RawMode) -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (receiver_elapsed_tx, receiver_elapsed_rx) = mpsc::channel::<Duration>();

        let receiver_thread = thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let (mut stream, _) = listener.accept().await.unwrap();
                while let Ok(bytes) = command_rx.recv() {
                    if bytes == 0 {
                        break;
                    }

                    let start = std::time::Instant::now();
                    match mode {
                        RawMode::BatchWrite => {
                            let BufResult(result, _) =
                                stream.read_exact(vec![0u8; bytes * MESSAGE_SIZE]).await;
                            result.unwrap();
                        }
                        RawMode::SmallWrites => {
                            for _ in 0..bytes {
                                let BufResult(result, _) =
                                    stream.read_exact(vec![0u8; MESSAGE_SIZE]).await;
                                result.unwrap();
                            }
                        }
                    }
                    receiver_elapsed_tx.send(start.elapsed()).unwrap();
                }
            });
        });

        let port = port_rx.recv().unwrap();
        let rt = monocoque::rt::LocalRuntime::new().unwrap();
        let stream = rt
            .block_on(TcpStream::connect(("127.0.0.1", port)))
            .unwrap();

        Self {
            payload: Bytes::from(vec![0u8; payload_len(mode)]),
            mode,
            rt,
            stream,
            command_tx,
            receiver_elapsed_rx,
            receiver_thread: Some(receiver_thread),
        }
    }

    fn run_batch(&mut self) -> (Duration, Duration) {
        self.command_tx.send(BATCH_SIZE).unwrap();

        let sender_start = std::time::Instant::now();
        match self.mode {
            RawMode::BatchWrite => {
                self.rt.block_on(async {
                    let BufResult(result, _) = self.stream.write_all(self.payload.clone()).await;
                    result.unwrap();
                });
            }
            RawMode::SmallWrites => {
                self.rt.block_on(async {
                    for _ in 0..BATCH_SIZE {
                        let BufResult(result, _) =
                            self.stream.write_all(self.payload.clone()).await;
                        result.unwrap();
                    }
                });
            }
        }
        let sender_elapsed = sender_start.elapsed();

        let receiver_elapsed = self.receiver_elapsed_rx.recv().unwrap();
        (sender_elapsed, receiver_elapsed)
    }
}

impl Drop for RawTcpProfile {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(receiver_thread) = self.receiver_thread.take() {
            let _ = receiver_thread.join();
        }
    }
}

fn payload_len(mode: RawMode) -> usize {
    match mode {
        RawMode::BatchWrite => BATCH_SIZE * MESSAGE_SIZE,
        RawMode::SmallWrites => MESSAGE_SIZE,
    }
}

struct RawMultiTcpProfile {
    payload: Bytes,
    rt: monocoque::rt::LocalRuntime,
    streams: Vec<TcpStream>,
    command_tx: mpsc::Sender<usize>,
    receiver_elapsed_rx: mpsc::Receiver<Duration>,
    receiver_thread: Option<JoinHandle<()>>,
}

impl RawMultiTcpProfile {
    fn new(connections: usize) -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (receiver_elapsed_tx, receiver_elapsed_rx) = mpsc::channel::<Duration>();

        let receiver_thread = thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            let mut streams = rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let mut streams = Vec::with_capacity(connections);
                for _ in 0..connections {
                    let (stream, _) = listener.accept().await.unwrap();
                    streams.push(stream);
                }
                streams
            });

            while let Ok(count) = command_rx.recv() {
                if count == 0 {
                    break;
                }

                let start = std::time::Instant::now();
                streams = rt.block_on(read_small_messages(streams, count));
                receiver_elapsed_tx.send(start.elapsed()).unwrap();
            }
        });

        let port = port_rx.recv().unwrap();
        let rt = monocoque::rt::LocalRuntime::new().unwrap();
        let streams = rt.block_on(async {
            let mut streams = Vec::with_capacity(connections);
            for _ in 0..connections {
                streams.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
            }
            streams
        });

        Self {
            payload: Bytes::from(vec![0u8; MESSAGE_SIZE]),
            rt,
            streams,
            command_tx,
            receiver_elapsed_rx,
            receiver_thread: Some(receiver_thread),
        }
    }

    fn run_batch(&mut self) -> (Duration, Duration) {
        self.command_tx.send(BATCH_SIZE).unwrap();

        let sender_start = std::time::Instant::now();
        let streams = std::mem::take(&mut self.streams);
        self.streams = self.rt.block_on(write_small_messages(
            streams,
            self.payload.clone(),
            BATCH_SIZE,
        ));
        let sender_elapsed = sender_start.elapsed();

        let receiver_elapsed = self.receiver_elapsed_rx.recv().unwrap();
        (sender_elapsed, receiver_elapsed)
    }
}

impl Drop for RawMultiTcpProfile {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(receiver_thread) = self.receiver_thread.take() {
            let _ = receiver_thread.join();
        }
    }
}

async fn read_small_messages(mut streams: Vec<TcpStream>, count: usize) -> Vec<TcpStream> {
    let mut handles = Vec::with_capacity(streams.len());
    for mut stream in streams.drain(..) {
        handles.push(monocoque::rt::spawn(async move {
            for _ in 0..count {
                let BufResult(result, _) = stream.read_exact(vec![0u8; MESSAGE_SIZE]).await;
                result.unwrap();
            }
            stream
        }));
    }

    let mut streams = Vec::with_capacity(handles.len());
    for handle in handles {
        streams.push(monocoque::rt::join(handle).await);
    }
    streams
}

async fn write_small_messages(
    mut streams: Vec<TcpStream>,
    payload: Bytes,
    count: usize,
) -> Vec<TcpStream> {
    let mut handles = Vec::with_capacity(streams.len());
    for mut stream in streams.drain(..) {
        let payload = payload.clone();
        handles.push(monocoque::rt::spawn(async move {
            for _ in 0..count {
                let BufResult(result, _) = stream.write_all(payload.clone()).await;
                result.unwrap();
            }
            stream
        }));
    }

    let mut streams = Vec::with_capacity(handles.len());
    for handle in handles {
        streams.push(monocoque::rt::join(handle).await);
    }
    streams
}

fn print_raw_summary(
    label: &str,
    messages_per_sample: usize,
    batches: usize,
    sender: &[Duration],
    receiver: &[Duration],
) {
    let sender_median = median(sender);
    let receiver_median = median(receiver);
    let sender_best = sender.iter().min().copied().unwrap();
    let receiver_best = receiver.iter().min().copied().unwrap();

    println!("{BACKEND} {label}, {batches} samples");
    println!(
        "  sender:   median {:>8.3} us ({:>6.2} Mmsg/s), best {:>8.3} us ({:>6.2} Mmsg/s)",
        micros(sender_median),
        raw_mps(messages_per_sample, sender_median),
        micros(sender_best),
        raw_mps(messages_per_sample, sender_best)
    );
    println!(
        "  receiver: median {:>8.3} us ({:>6.2} Mmsg/s), best {:>8.3} us ({:>6.2} Mmsg/s)",
        micros(receiver_median),
        raw_mps(messages_per_sample, receiver_median),
        micros(receiver_best),
        raw_mps(messages_per_sample, receiver_best)
    );
}

fn raw_mps(messages: usize, duration: Duration) -> f64 {
    messages as f64 / duration.as_secs_f64() / 1_000_000.0
}
