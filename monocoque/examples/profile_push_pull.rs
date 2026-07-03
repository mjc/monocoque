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
use std::ffi::{c_char, c_void};
use std::io::{Read, Write};
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};
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

macro_rules! coz_progress {
    () => {{
        static COUNTER: AtomicPtr<CozCounter> = AtomicPtr::new(std::ptr::null_mut());
        coz_increment(&COUNTER, concat!(file!(), ":", line!(), "\0").as_bytes(), 1);
    }};
    ($count:expr) => {{
        static COUNTER: AtomicPtr<CozCounter> = AtomicPtr::new(std::ptr::null_mut());
        coz_increment(
            &COUNTER,
            concat!(file!(), ":", line!(), "\0").as_bytes(),
            $count,
        );
    }};
}

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

#[derive(Clone, Copy)]
enum ProfileCase {
    Recv(RecvMode),
    RawBatch,
    RawSmall,
    RawMulti,
    RawSmallCompioRead,
    RawSmallCompioWrite,
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
                                coz_progress!();
                            }
                        }
                        RecvMode::ReuseBuffer => {
                            for _ in 0..count {
                                assert!(pull.recv_into(&mut msg).await.unwrap());
                                coz_progress!();
                            }
                        }
                        RecvMode::Batch => {
                            let mut received = 0;
                            while received < count {
                                let batch = pull.recv_batch().await.unwrap().unwrap().len();
                                received += batch;
                                coz_progress!(batch);
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
    let cases = parse_cases();
    for case in cases {
        match case {
            ProfileCase::Recv(mode) => run_zmtp_profile(mode),
            ProfileCase::RawBatch => {
                let mut raw = RawTcpProfile::new(RawMode::BatchWrite);
                run_raw_profile(
                    "raw TCP 640KB batch write",
                    BATCH_SIZE,
                    WARMUP_BATCHES,
                    BATCHES,
                    || raw.run_batch(),
                );
            }
            ProfileCase::RawSmall => {
                let mut raw = RawTcpProfile::new(RawMode::SmallWrites);
                run_raw_profile(
                    "raw TCP 10K small writes",
                    BATCH_SIZE,
                    WARMUP_BATCHES,
                    RAW_SMALL_BATCHES,
                    || raw.run_batch(),
                );
            }
            ProfileCase::RawMulti => {
                let mut raw = RawMultiTcpProfile::new(RAW_CONNECTIONS);
                run_raw_profile(
                    "raw TCP 16 connections, 10K small writes each",
                    BATCH_SIZE * RAW_CONNECTIONS,
                    RAW_MULTI_WARMUP_BATCHES,
                    RAW_MULTI_BATCHES,
                    || raw.run_batch(),
                );
            }
            ProfileCase::RawSmallCompioRead => {
                let mut raw = RawSmallCompioReadProfile::new();
                run_raw_profile(
                    "raw TCP compio read, std write",
                    BATCH_SIZE,
                    WARMUP_BATCHES,
                    RAW_SMALL_BATCHES,
                    || raw.run_batch(),
                );
            }
            ProfileCase::RawSmallCompioWrite => {
                let mut raw = RawSmallCompioWriteProfile::new();
                run_raw_profile(
                    "raw TCP compio write, std read",
                    BATCH_SIZE,
                    WARMUP_BATCHES,
                    RAW_SMALL_BATCHES,
                    || raw.run_batch(),
                );
            }
        }
    }
}

fn parse_cases() -> Vec<ProfileCase> {
    let Some(case) = std::env::args().nth(1) else {
        return vec![
            ProfileCase::Recv(RecvMode::Allocating),
            ProfileCase::Recv(RecvMode::ReuseBuffer),
            ProfileCase::Recv(RecvMode::Batch),
            ProfileCase::RawBatch,
            ProfileCase::RawSmall,
            ProfileCase::RawMulti,
            ProfileCase::RawSmallCompioRead,
            ProfileCase::RawSmallCompioWrite,
        ];
    };

    match case.as_str() {
        "recv" => vec![ProfileCase::Recv(RecvMode::Allocating)],
        "recv-into" => vec![ProfileCase::Recv(RecvMode::ReuseBuffer)],
        "recv-batch" => vec![ProfileCase::Recv(RecvMode::Batch)],
        "raw-batch" => vec![ProfileCase::RawBatch],
        "raw-small" => vec![ProfileCase::RawSmall],
        "raw-small-compio-read" => vec![ProfileCase::RawSmallCompioRead],
        "raw-small-compio-write" => vec![ProfileCase::RawSmallCompioWrite],
        "raw-multi" => vec![ProfileCase::RawMulti],
        "all" => parse_cases_from_all(),
        other => {
            eprintln!(
                "unknown case {other:?}; expected all, recv, recv-into, recv-batch, raw-batch, raw-small, raw-small-compio-read, raw-small-compio-write, or raw-multi"
            );
            std::process::exit(2);
        }
    }
}

fn parse_cases_from_all() -> Vec<ProfileCase> {
    vec![
        ProfileCase::Recv(RecvMode::Allocating),
        ProfileCase::Recv(RecvMode::ReuseBuffer),
        ProfileCase::Recv(RecvMode::Batch),
        ProfileCase::RawBatch,
        ProfileCase::RawSmall,
        ProfileCase::RawMulti,
        ProfileCase::RawSmallCompioRead,
        ProfileCase::RawSmallCompioWrite,
    ]
}

fn run_zmtp_profile(mode: RecvMode) {
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
        coz_progress!();
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
                let mut read_buf = Vec::new();
                while let Ok(bytes) = command_rx.recv() {
                    if bytes == 0 {
                        break;
                    }

                    let start = std::time::Instant::now();
                    match mode {
                        RawMode::BatchWrite => {
                            let batch_bytes = bytes * MESSAGE_SIZE;
                            if read_buf.len() != batch_bytes {
                                read_buf.resize(batch_bytes, 0);
                            }
                            let BufResult(result, returned) = stream.read_exact(read_buf).await;
                            read_buf = returned;
                            result.unwrap();
                            coz_progress!(bytes);
                        }
                        RawMode::SmallWrites => {
                            if read_buf.len() != MESSAGE_SIZE {
                                read_buf.resize(MESSAGE_SIZE, 0);
                            }
                            for _ in 0..bytes {
                                let BufResult(result, returned) = stream.read_exact(read_buf).await;
                                read_buf = returned;
                                result.unwrap();
                                coz_progress!();
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
                        coz_progress!();
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

struct RawSmallCompioReadProfile {
    payload: Vec<u8>,
    stream: StdTcpStream,
    command_tx: mpsc::Sender<usize>,
    receiver_elapsed_rx: mpsc::Receiver<Duration>,
    receiver_thread: Option<JoinHandle<()>>,
}

impl RawSmallCompioReadProfile {
    fn new() -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (receiver_elapsed_tx, receiver_elapsed_rx) = mpsc::channel::<Duration>();

        let receiver_thread = thread::spawn(move || {
            let rt = monocoque::rt::LocalRuntime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                port_tx.send(listener.local_addr().unwrap().port()).unwrap();

                let (mut stream, _) = listener.accept().await.unwrap();
                let mut read_buf = vec![0u8; MESSAGE_SIZE];
                while let Ok(count) = command_rx.recv() {
                    if count == 0 {
                        break;
                    }

                    let start = std::time::Instant::now();
                    for _ in 0..count {
                        let BufResult(result, returned) = stream.read_exact(read_buf).await;
                        read_buf = returned;
                        result.unwrap();
                        coz_progress!();
                    }
                    receiver_elapsed_tx.send(start.elapsed()).unwrap();
                }
            });
        });

        let port = port_rx.recv().unwrap();
        let stream = StdTcpStream::connect(("127.0.0.1", port)).unwrap();

        Self {
            payload: vec![0u8; MESSAGE_SIZE],
            stream,
            command_tx,
            receiver_elapsed_rx,
            receiver_thread: Some(receiver_thread),
        }
    }

    fn run_batch(&mut self) -> (Duration, Duration) {
        self.command_tx.send(BATCH_SIZE).unwrap();

        let sender_start = std::time::Instant::now();
        for _ in 0..BATCH_SIZE {
            self.stream.write_all(&self.payload).unwrap();
        }
        let sender_elapsed = sender_start.elapsed();

        let receiver_elapsed = self.receiver_elapsed_rx.recv().unwrap();
        (sender_elapsed, receiver_elapsed)
    }
}

impl Drop for RawSmallCompioReadProfile {
    fn drop(&mut self) {
        let _ = self.command_tx.send(0);
        if let Some(receiver_thread) = self.receiver_thread.take() {
            let _ = receiver_thread.join();
        }
    }
}

struct RawSmallCompioWriteProfile {
    payload: Bytes,
    rt: monocoque::rt::LocalRuntime,
    stream: TcpStream,
    command_tx: mpsc::Sender<usize>,
    receiver_elapsed_rx: mpsc::Receiver<Duration>,
    receiver_thread: Option<JoinHandle<()>>,
}

impl RawSmallCompioWriteProfile {
    fn new() -> Self {
        let (port_tx, port_rx) = mpsc::channel::<u16>();
        let (command_tx, command_rx) = mpsc::channel::<usize>();
        let (receiver_elapsed_tx, receiver_elapsed_rx) = mpsc::channel::<Duration>();

        let receiver_thread = thread::spawn(move || {
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            port_tx.send(listener.local_addr().unwrap().port()).unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut read_buf = vec![0u8; MESSAGE_SIZE];
            while let Ok(count) = command_rx.recv() {
                if count == 0 {
                    break;
                }

                let start = std::time::Instant::now();
                for _ in 0..count {
                    stream.read_exact(&mut read_buf).unwrap();
                }
                receiver_elapsed_tx.send(start.elapsed()).unwrap();
            }
        });

        let port = port_rx.recv().unwrap();
        let rt = monocoque::rt::LocalRuntime::new().unwrap();
        let stream = rt
            .block_on(TcpStream::connect(("127.0.0.1", port)))
            .unwrap();

        Self {
            payload: Bytes::from(vec![0u8; MESSAGE_SIZE]),
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
        self.rt.block_on(async {
            for _ in 0..BATCH_SIZE {
                let BufResult(result, _) = self.stream.write_all(self.payload.clone()).await;
                result.unwrap();
                coz_progress!();
            }
        });
        let sender_elapsed = sender_start.elapsed();

        let receiver_elapsed = self.receiver_elapsed_rx.recv().unwrap();
        (sender_elapsed, receiver_elapsed)
    }
}

impl Drop for RawSmallCompioWriteProfile {
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
            let mut read_buf = vec![0u8; MESSAGE_SIZE];
            for _ in 0..count {
                let BufResult(result, returned) = stream.read_exact(read_buf).await;
                read_buf = returned;
                result.unwrap();
                coz_progress!();
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
                coz_progress!();
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

#[repr(C)]
struct CozCounter {
    count: usize,
    _backoff: usize,
}

type CozGetCounter = unsafe extern "C" fn(i32, *const c_char) -> *mut CozCounter;

static COZ_GET_COUNTER: OnceLock<Option<CozGetCounter>> = OnceLock::new();

fn coz_increment(counter: &'static AtomicPtr<CozCounter>, name: &'static [u8], count: usize) {
    let mut ptr = counter.load(Ordering::Relaxed);
    if ptr.is_null() {
        ptr = init_coz_counter(counter, name);
    }

    if !ptr.is_null() {
        unsafe { atomic_coz_count(ptr).fetch_add(count, Ordering::Relaxed) };
    }
}

fn init_coz_counter(
    counter: &'static AtomicPtr<CozCounter>,
    name: &'static [u8],
) -> *mut CozCounter {
    let Some(get_counter) = COZ_GET_COUNTER.get_or_init(load_coz_get_counter) else {
        return std::ptr::null_mut();
    };

    let ptr = unsafe { get_counter(1, name.as_ptr().cast::<c_char>()) };
    counter.store(ptr, Ordering::Relaxed);
    ptr
}

unsafe fn atomic_coz_count(ptr: *mut CozCounter) -> &'static std::sync::atomic::AtomicUsize {
    unsafe { &*std::ptr::addr_of!((*ptr).count).cast::<std::sync::atomic::AtomicUsize>() }
}

fn load_coz_get_counter() -> Option<CozGetCounter> {
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    let ptr = unsafe { dlsym(std::ptr::null_mut(), b"_coz_get_counter\0".as_ptr().cast()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, CozGetCounter>(ptr) })
    }
}
