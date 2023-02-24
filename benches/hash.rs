/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use ahash::RandomState;
use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use stalwart_smtp::{
    config::*,
    core::{
        throttle::{ThrottleKey, ThrottleKeyHasherBuilder},
        Envelope,
    },
};

#[derive(Debug, PartialEq, Eq, Hash)]
enum Item {
    String(String),
    Uint(u64),
    Listener(u16),
    IpAddr(IpAddr),
}

#[derive(Debug, Clone)]
struct TestEnvelope {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub sender_domain: String,
    pub sender: String,
    pub rcpt_domain: String,
    pub rcpt: String,
    pub helo_domain: String,
    pub authenticated_as: String,
    pub mx: String,
    pub listener_id: u16,
    pub priority: i16,
}

impl Envelope for TestEnvelope {
    fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    fn remote_ip(&self) -> IpAddr {
        self.remote_ip
    }

    fn sender_domain(&self) -> &str {
        self.sender_domain.as_str()
    }

    fn sender(&self) -> &str {
        self.sender.as_str()
    }

    fn rcpt_domain(&self) -> &str {
        self.rcpt_domain.as_str()
    }

    fn rcpt(&self) -> &str {
        self.rcpt.as_str()
    }

    fn helo_domain(&self) -> &str {
        self.helo_domain.as_str()
    }

    fn authenticated_as(&self) -> &str {
        self.authenticated_as.as_str()
    }

    fn mx(&self) -> &str {
        self.mx.as_str()
    }

    fn listener_id(&self) -> u16 {
        self.listener_id
    }

    fn priority(&self) -> i16 {
        self.priority
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let envelope = TestEnvelope {
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
        helo_domain: "ehlo-domain.org".to_string(),
    };
    let throttle = Throttle {
        conditions: Conditions { conditions: vec![] },
        keys: THROTTLE_LISTENER, //u16::MAX,
        concurrency: 10.into(),
        rate: Rate {
            requests: 30,
            period: Duration::from_secs(60),
        }
        .into(),
    };
    let blake3_map: DashMap<ThrottleKey, usize, ThrottleKeyHasherBuilder> =
        DashMap::with_capacity_and_hasher(100, ThrottleKeyHasherBuilder::default());
    let string_map: DashMap<String, usize, RandomState> =
        DashMap::with_capacity_and_hasher(100, RandomState::default());
    let item_map: DashMap<Vec<Item>, usize, RandomState> =
        DashMap::with_capacity_and_hasher(100, RandomState::default());

    let mut envelope1 = envelope.clone();
    let mut envelope2 = envelope.clone();
    let mut envelope3 = envelope;

    let mut remote_ip1: u32 = 0;
    let mut remote_ip2: u32 = 0;
    let mut remote_ip3: u32 = 0;

    c.bench_function("blake3 key", |b| {
        b.iter(|| {
            remote_ip1 += 1;
            let remote_ip = remote_ip1.to_be_bytes();
            envelope1.remote_ip = IpAddr::V4(Ipv4Addr::new(
                remote_ip[0],
                remote_ip[1],
                remote_ip[2],
                remote_ip[3],
            ));

            blake3_map.insert(throttle.new_key(&envelope1), 0)
        })
    });

    c.bench_function("string key", |b| {
        b.iter(|| {
            remote_ip2 += 1;
            let remote_ip = remote_ip2.to_be_bytes();
            envelope2.remote_ip = IpAddr::V4(Ipv4Addr::new(
                remote_ip[0],
                remote_ip[1],
                remote_ip[2],
                remote_ip[3],
            ));

            string_map.insert(to_key(&throttle, &envelope2), 0)
        })
    });

    c.bench_function("items key", |b| {
        b.iter(|| {
            remote_ip3 += 1;
            let remote_ip = remote_ip3.to_be_bytes();
            envelope3.remote_ip = IpAddr::V4(Ipv4Addr::new(
                remote_ip[0],
                remote_ip[1],
                remote_ip[2],
                remote_ip[3],
            ));

            item_map.insert(to_items(&throttle, &envelope3), 0)
        })
    });
}

fn to_key(t: &Throttle, e: &TestEnvelope) -> String {
    use std::fmt::Write;

    let mut result = String::with_capacity(32);
    if (t.keys & THROTTLE_RCPT) != 0 {
        result.push_str(e.rcpt.as_str());
    }
    if (t.keys & THROTTLE_RCPT_DOMAIN) != 0 {
        result.push_str(e.rcpt_domain.as_str());
    }
    if (t.keys & THROTTLE_SENDER) != 0 {
        result.push_str(e.sender.as_str());
    }
    if (t.keys & THROTTLE_SENDER_DOMAIN) != 0 {
        result.push_str(e.sender_domain.as_str());
    }
    if (t.keys & THROTTLE_AUTH_AS) != 0 {
        result.push_str(e.authenticated_as.as_str());
    }
    if (t.keys & THROTTLE_LISTENER) != 0 {
        write!(result, "{}", e.listener_id).ok();
    }
    if (t.keys & THROTTLE_MX) != 0 {
        result.push_str(e.mx.as_str());
    }
    if (t.keys & THROTTLE_REMOTE_IP) != 0 {
        write!(result, "{}", e.local_ip).ok();
    }
    if (t.keys & THROTTLE_LOCAL_IP) != 0 {
        write!(result, "{}", e.remote_ip).ok();
    }
    if let Some(rate_limit) = &t.rate {
        write!(result, "{}", rate_limit.period.as_secs()).ok();
        write!(result, "{}", rate_limit.requests).ok();
    }
    if let Some(concurrency) = &t.concurrency {
        write!(result, "{concurrency}").ok();
    }
    result
}

fn to_items(t: &Throttle, e: &TestEnvelope) -> Vec<Item> {
    let mut result = Vec::new();

    if (t.keys & THROTTLE_RCPT) != 0 {
        result.push(Item::String(e.rcpt.clone()));
    }
    if (t.keys & THROTTLE_RCPT_DOMAIN) != 0 {
        result.push(Item::String(e.rcpt_domain.clone()));
    }
    if (t.keys & THROTTLE_SENDER) != 0 {
        result.push(Item::String(e.sender.clone()));
    }
    if (t.keys & THROTTLE_SENDER_DOMAIN) != 0 {
        result.push(Item::String(e.sender_domain.clone()));
    }
    if (t.keys & THROTTLE_AUTH_AS) != 0 {
        result.push(Item::String(e.authenticated_as.clone()));
    }
    if (t.keys & THROTTLE_LISTENER) != 0 {
        result.push(Item::Listener(e.listener_id));
    }
    if (t.keys & THROTTLE_MX) != 0 {
        result.push(Item::String(e.mx.clone()));
    }
    if (t.keys & THROTTLE_REMOTE_IP) != 0 {
        result.push(Item::IpAddr(e.local_ip));
    }
    if (t.keys & THROTTLE_LOCAL_IP) != 0 {
        result.push(Item::IpAddr(e.remote_ip));
    }
    if let Some(rate_limit) = &t.rate {
        result.push(Item::Uint(rate_limit.period.as_secs()));
        result.push(Item::Uint(rate_limit.requests));
    }
    if let Some(concurrency) = &t.concurrency {
        result.push(Item::Uint(*concurrency));
    }

    result
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
