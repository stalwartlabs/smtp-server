use std::time::Duration;

use ahash::RandomState;
use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use smtp_server::{
    config::{Throttle, ThrottleRate},
    core::{
        throttle::{ThrottleKey, ThrottleKeyHasherBuilder},
        Envelope,
    },
};

pub fn criterion_benchmark(c: &mut Criterion) {
    let envelope = Envelope {
        local_ip: "127.0.0.1".parse().unwrap(),
        remote_ip: "A:B::C:D".parse().unwrap(),
        sender_domain: "domain.org".to_string(),
        sender: "sender@mydomain.com".to_string(),
        rcpt_domain: "otherdomain.net".to_string(),
        rcpt: "rcpt@otherdomain.net".to_string(),
        authenticated_as: "test@test.org".to_string(),
        mx: "mx.tester.org".to_string(),
        listener_id: 0,
        priority: 1,
    };
    let throttle = Throttle {
        condition: vec![],
        keys: u16::MAX,
        concurrency: 10.into(),
        rate: ThrottleRate {
            requests: 30,
            period: Duration::from_secs(60),
        }
        .into(),
    };
    let blake3_map: DashMap<ThrottleKey, usize, ThrottleKeyHasherBuilder> =
        DashMap::with_capacity_and_hasher(100, ThrottleKeyHasherBuilder::default());
    let ahash_map: DashMap<String, usize, RandomState> =
        DashMap::with_capacity_and_hasher(100, RandomState::default());

    let mut envelope1 = envelope.clone();
    let mut envelope2 = envelope;

    c.bench_function("blake3 key", |b| {
        b.iter(|| {
            envelope1.listener_id += 1;

            blake3_map.insert(ThrottleKey::new(&envelope1, &throttle), 0)
        })
    });

    c.bench_function("ahash key", |b| {
        b.iter(|| {
            envelope2.listener_id += 1;

            ahash_map.insert(throttle.to_key(&envelope2), 0)
        })
    });

    println!(
        "keys -> blake3: {}/{} ahash: {}/{}",
        blake3_map.len(),
        envelope1.listener_id,
        ahash_map.len(),
        envelope2.listener_id
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
