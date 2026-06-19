//! Memory allocation benchmarks.
//!
//! Tracks allocation pressure in the hot path: frame construction, Bytes
//! clone-vs-copy, and arena vs heap allocation patterns.
//!
//! Run with: `cargo bench --package monocoque -F zmq --bench allocation`

use bytes::{BufMut, Bytes, BytesMut};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use monocoque_core::buffer::SegmentedBuffer;
use monocoque_core::message_builder::Message;
use monocoque_core::subscription::SubscriptionEvent;

fn subscription_event_from_bytes(msg: Bytes) -> Option<SubscriptionEvent> {
    if msg.is_empty() {
        return None;
    }

    let prefix = msg.slice(1..);
    match msg[0] {
        0x01 => Some(SubscriptionEvent::Subscribe(prefix)),
        0x00 => Some(SubscriptionEvent::Unsubscribe(prefix)),
        _ => None,
    }
}

fn subscription_event_from_message_copy(msg: &[u8]) -> Option<SubscriptionEvent> {
    if msg.is_empty() {
        return None;
    }

    let prefix = Bytes::copy_from_slice(&msg[1..]);
    match msg[0] {
        0x01 => Some(SubscriptionEvent::Subscribe(prefix)),
        0x00 => Some(SubscriptionEvent::Unsubscribe(prefix)),
        _ => None,
    }
}

fn greeting_padding_old(mechanism_name: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(64);
    b.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    b.extend_from_slice(mechanism_name);
    let padding = 20usize.saturating_sub(mechanism_name.len());
    b.extend_from_slice(&vec![0u8; padding]);
    b.freeze()
}

fn greeting_padding_new(mechanism_name: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(64);
    b.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    b.extend_from_slice(mechanism_name);
    let padding = 20usize.saturating_sub(mechanism_name.len());
    b.put_bytes(0, padding);
    b.freeze()
}

/// Bytes::copy_from_slice vs Bytes::from (moves ownership)
fn bench_bytes_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytes_construction");

    let small = vec![0u8; 64];
    let medium = vec![0u8; 1024];
    let large = vec![0u8; 65536];

    group.throughput(Throughput::Bytes(64));
    group.bench_function("copy_64b", |b| {
        b.iter(|| {
            let b = Bytes::copy_from_slice(black_box(&small));
            black_box(b);
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("copy_1kb", |b| {
        b.iter(|| {
            let b = Bytes::copy_from_slice(black_box(&medium));
            black_box(b);
        });
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("copy_64kb", |b| {
        b.iter(|| {
            let b = Bytes::copy_from_slice(black_box(&large));
            black_box(b);
        });
    });

    // Cloning Bytes is an Arc reference-count bump  -  O(1), no allocation
    let frozen = Bytes::from(vec![0u8; 1024]);
    group.bench_function("clone_arc_1kb", |b| {
        b.iter(|| {
            let c = frozen.clone();
            black_box(c);
        });
    });

    group.finish();
}

/// BytesMut reuse vs fresh allocation
fn bench_bytesmut_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("bytesmut_reuse");

    group.bench_function("fresh_8kb", |b| {
        b.iter(|| {
            let buf = BytesMut::with_capacity(8192);
            black_box(buf);
        });
    });

    group.bench_function("clear_and_reuse_8kb", |b| {
        let mut buf = BytesMut::with_capacity(8192);
        b.iter(|| {
            buf.clear();
            buf.extend_from_slice(&[0u8; 128]);
            black_box(buf.len());
        });
    });

    group.finish();
}

/// SegmentedBuffer push/drain cycle (mimics the codec read path)
fn bench_segmented_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("segmented_buffer");

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("push_1kb", |b| {
        b.iter_batched(
            || (SegmentedBuffer::new(), Bytes::from(vec![0u8; 1024])),
            |(mut buf, data)| {
                buf.push(data);
                black_box(buf.len());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("push_drain_cycle_1kb", |b| {
        b.iter_batched(
            || {
                let mut buf = SegmentedBuffer::new();
                buf.push(Bytes::from(vec![0u8; 1024]));
                buf
            },
            |mut buf| {
                // Simulate draining 2 bytes (frame header) then the rest
                buf.advance(2);
                buf.advance(1022);
                black_box(buf.len());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Multipart message Vec allocation patterns
fn bench_multipart_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("multipart_alloc");
    let frame = Bytes::from(vec![0u8; 256]);

    group.bench_function("2_frame_vec", |b| {
        b.iter(|| {
            let msg: Vec<Bytes> = vec![frame.clone(), frame.clone()];
            black_box(msg);
        });
    });

    group.bench_function("5_frame_vec", |b| {
        b.iter(|| {
            let msg: Vec<Bytes> = vec![
                frame.clone(),
                frame.clone(),
                frame.clone(),
                frame.clone(),
                frame.clone(),
            ];
            black_box(msg);
        });
    });

    group.bench_function("router_envelope_3_frame", |b| {
        // Simulates a ROUTER envelope: [routing_id, empty, payload]
        let id = Bytes::copy_from_slice(b"peer-identity-01");
        let empty = Bytes::new();
        b.iter(|| {
            let msg: Vec<Bytes> = vec![id.clone(), empty.clone(), frame.clone()];
            black_box(msg);
        });
    });

    group.finish();
}

/// Protocol-path allocation fixes that are cheap to benchmark directly.
fn bench_protocol_alloc_fixes(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_alloc_fixes");

    let subscribe_wire =
        SubscriptionEvent::Subscribe(Bytes::from_static(b"topic.foo")).to_message();
    let unsubscribe_wire =
        SubscriptionEvent::Unsubscribe(Bytes::from_static(b"topic.foo")).to_message();
    let req_tail = vec![
        Bytes::copy_from_slice(b"\x00\x00\x00\x01"),
        Bytes::from_static(b"body-1"),
        Bytes::from_static(b"body-2"),
    ];
    let router_id = Bytes::from_static(b"peer-identity-01");
    let router_msg = vec![
        Bytes::from_static(b"body-1"),
        Bytes::from_static(b"body-2"),
        Bytes::from_static(b"body-3"),
    ];

    group.bench_function("subscription_event_from_message", |b| {
        b.iter(|| {
            let parsed = SubscriptionEvent::from_message(black_box(&subscribe_wire));
            black_box(parsed);
        });
    });

    group.bench_function("subscription_event_from_message_unsubscribe", |b| {
        b.iter(|| {
            let parsed = SubscriptionEvent::from_message(black_box(&unsubscribe_wire));
            black_box(parsed);
        });
    });

    group.bench_function("subscription_event_from_bytes", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_bytes(black_box(subscribe_wire.clone()));
            black_box(parsed);
        });
    });

    group.bench_function("subscription_event_from_bytes_unsubscribe", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_bytes(black_box(unsubscribe_wire.clone()));
            black_box(parsed);
        });
    });

    group.bench_function("subscription_event_encode", |b| {
        b.iter(|| {
            let wire = SubscriptionEvent::Subscribe(Bytes::from_static(b"topic.foo")).to_message();
            black_box(wire);
        });
    });

    group.bench_function("req_correlate_tail_clone", |b| {
        b.iter(|| {
            let cloned = req_tail[1..].to_vec();
            black_box(cloned);
        });
    });

    group.bench_function("req_correlate_tail_remove", |b| {
        b.iter(|| {
            let mut msg = req_tail.clone();
            msg.remove(0);
            black_box(msg);
        });
    });

    group.bench_function("router_envelope_prealloc", |b| {
        b.iter(|| {
            let mut frames = Vec::with_capacity(router_msg.len() + 1);
            frames.push(router_id.clone());
            frames.extend(router_msg.clone());
            black_box(frames);
        });
    });

    group.bench_function("handshake_padding_vec", |b| {
        b.iter(|| {
            let padding = 20usize.saturating_sub(5);
            let mut buf = BytesMut::new();
            buf.extend_from_slice(b"PLAIN");
            buf.extend_from_slice(&vec![0u8; padding]);
            black_box(buf);
        });
    });

    group.bench_function("handshake_padding_put_bytes", |b| {
        b.iter(|| {
            let padding = 20usize.saturating_sub(5);
            let mut buf = BytesMut::new();
            buf.extend_from_slice(b"PLAIN");
            buf.put_bytes(0, padding);
            black_box(buf);
        });
    });

    group.finish();
}

/// Inproc stream adapter copy path: read/write bridge between Bytes and byte buffers.
fn bench_inproc_stream_adapter(c: &mut Criterion) {
    let mut group = c.benchmark_group("inproc_stream_adapter");

    group.bench_function("write_copy_from_slice_1kb", |b| {
        let payload = Bytes::from(vec![0u8; 1024]);
        b.iter(|| {
            let data = Bytes::copy_from_slice(black_box(payload.as_ref()));
            black_box(data);
        });
    });

    group.bench_function("read_copy_into_buf_1kb", |b| {
        let payload = Bytes::from(vec![0u8; 1024]);
        b.iter_batched(
            || payload.clone(),
            |frame| {
                let mut buf = vec![0u8; frame.len()];
                buf.copy_from_slice(black_box(frame.as_ref()));
                black_box(buf);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Builder/control path copies for the convenience message APIs.
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

/// Fragmented receive reassembly and multipart encode hot paths.
fn bench_fragmented_and_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fragmented_and_encode");

    group.bench_function("segmented_buffer_single_segment_take", |b| {
        b.iter_batched(
            || {
                let mut buf = SegmentedBuffer::new();
                buf.push(Bytes::from(vec![0u8; 1024]));
                buf
            },
            |mut local| {
                let out = local.take_bytes(black_box(512));
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("segmented_buffer_multi_segment_take", |b| {
        b.iter_batched(
            || {
                let mut buf = SegmentedBuffer::new();
                buf.push(Bytes::from(vec![0u8; 512]));
                buf.push(Bytes::from(vec![0u8; 512]));
                buf
            },
            |mut local| {
                let out = local.take_bytes(black_box(768));
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("encode_multipart_single_frame", |b| {
        let msg = vec![Bytes::from(vec![0u8; 1024])];
        b.iter(|| {
            let mut buf = BytesMut::new();
            monocoque_zmtp::codec::encode_multipart(black_box(&msg), &mut buf);
            black_box(buf);
        });
    });

    group.bench_function("encode_multipart_three_frames", |b| {
        let msg = vec![
            Bytes::from(vec![0u8; 32]),
            Bytes::from(vec![0u8; 256]),
            Bytes::from(vec![0u8; 1024]),
        ];
        b.iter(|| {
            let mut buf = BytesMut::new();
            monocoque_zmtp::codec::encode_multipart(black_box(&msg), &mut buf);
            black_box(buf);
        });
    });

    group.finish();
}

/// Benchmark the old/new code shapes in one binary so we can attribute changes
/// to the implementation instead of target-dir or binary-layout noise.
fn bench_regression_validations(c: &mut Criterion) {
    let mut group = c.benchmark_group("regression_validations");

    let subscribe_wire =
        SubscriptionEvent::Subscribe(Bytes::from_static(b"topic.foo")).to_message();
    let unsubscribe_wire =
        SubscriptionEvent::Unsubscribe(Bytes::from_static(b"topic.foo")).to_message();
    let router_id = Bytes::from_static(b"peer-identity-01");

    group.bench_function("subscription_event_old_copy_parse", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_message_copy(black_box(&subscribe_wire));
            black_box(parsed);
        });
    });
    group.bench_function("subscription_event_new_slice_parse", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_bytes(black_box(subscribe_wire.clone()));
            black_box(parsed);
        });
    });
    group.bench_function("subscription_event_old_copy_parse_unsubscribe", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_message_copy(black_box(&unsubscribe_wire));
            black_box(parsed);
        });
    });
    group.bench_function("subscription_event_new_slice_parse_unsubscribe", |b| {
        b.iter(|| {
            let parsed = subscription_event_from_bytes(black_box(unsubscribe_wire.clone()));
            black_box(parsed);
        });
    });

    for &frame_count in &[1usize, 3, 8] {
        let msg = vec![Bytes::from(vec![0u8; 256]); frame_count];
        let old_name = format!("router_envelope_old_vec_{frame_count}");
        let new_name = format!("router_envelope_new_prealloc_{frame_count}");

        group.bench_function(old_name.as_str(), |b| {
            b.iter(|| {
                let mut frames = vec![router_id.clone()];
                frames.extend(msg.clone());
                black_box(frames);
            });
        });

        group.bench_function(new_name.as_str(), |b| {
            b.iter(|| {
                let mut frames = Vec::with_capacity(msg.len() + 1);
                frames.push(router_id.clone());
                frames.extend(msg.clone());
                black_box(frames);
            });
        });
    }

    for &label in &["NULL", "PLAIN", "CURVE"] {
        let mech_name = match label {
            "NULL" => b"NULL".as_slice(),
            "PLAIN" => b"PLAIN".as_slice(),
            _ => b"CURVE".as_slice(),
        };
        let old_name = format!("handshake_padding_old_vec_{label}");
        let new_name = format!("handshake_padding_new_put_bytes_{label}");

        group.bench_function(old_name.as_str(), |b| {
            b.iter(|| {
                let wire = greeting_padding_old(black_box(mech_name));
                black_box(wire);
            });
        });

        group.bench_function(new_name.as_str(), |b| {
            b.iter(|| {
                let wire = greeting_padding_new(black_box(mech_name));
                black_box(wire);
            });
        });
    }

    for &(label, parts) in &[
        ("single_255", &[255usize][..]),
        ("single_256", &[256usize][..]),
        ("single_1kb", &[1024usize][..]),
        ("multi_3", &[32usize, 256, 1024][..]),
    ] {
        let msg: Vec<Bytes> = parts.iter().copied().map(|len| Bytes::from(vec![0u8; len])).collect();
        let fresh_name = format!("encode_multipart_fresh_{label}");
        let prealloc_name = format!("encode_multipart_prealloc_{label}");
        let reuse_name = format!("encode_multipart_reuse_{label}");

        group.bench_function(fresh_name.as_str(), |b| {
            b.iter(|| {
                let mut buf = BytesMut::new();
                monocoque_zmtp::codec::encode_multipart(black_box(&msg), &mut buf);
                black_box(buf);
            });
        });

        group.bench_function(prealloc_name.as_str(), |b| {
            b.iter(|| {
                let mut buf = BytesMut::with_capacity(msg.iter().map(|p| p.len() + 9).sum());
                monocoque_zmtp::codec::encode_multipart(black_box(&msg), &mut buf);
                black_box(buf);
            });
        });

        group.bench_function(reuse_name.as_str(), |b| {
            let mut buf = BytesMut::with_capacity(msg.iter().map(|p| p.len() + 9).sum());
            b.iter(|| {
                buf.clear();
                monocoque_zmtp::codec::encode_multipart(black_box(&msg), &mut buf);
                black_box(&buf);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_bytes_construction,
    bench_bytesmut_reuse,
    bench_segmented_buffer,
    bench_multipart_alloc,
    bench_protocol_alloc_fixes,
    bench_inproc_stream_adapter,
    bench_builder_control_allocs,
    bench_fragmented_and_encode,
    bench_regression_validations,
);
criterion_main!(benches);
