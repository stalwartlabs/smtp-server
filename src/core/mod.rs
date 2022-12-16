use std::{net::IpAddr, sync::Arc};

use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Span;

use crate::config::Stage;

use self::throttle::{
    ConcurrencyLimiter, InFlightRequest, Limiter, ThrottleKey, ThrottleKeyHasherBuilder,
};

pub mod if_block;
pub mod throttle;

#[derive(Debug, Clone)]
pub struct Envelope {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub sender_domain: String,
    pub sender: String,
    pub rcpt_domain: String,
    pub rcpt: String,
    pub authenticated_as: String,
    pub mx: String,
    pub listener_id: u16,
    pub priority: i16,
}

pub struct Core {
    pub stage: Stage,
    pub concurrency: ConcurrencyLimiter,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub envelope: Envelope,
    pub core: Arc<Core>,
    pub span: Span,
    pub stream: T,
    pub in_flight: Vec<InFlightRequest>,
}

impl Envelope {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr) -> Self {
        Self {
            local_ip,
            remote_ip,
            sender_domain: String::new(),
            sender: String::new(),
            rcpt_domain: String::new(),
            rcpt: String::new(),
            authenticated_as: String::new(),
            mx: String::new(),
            listener_id: 0,
            priority: 0,
        }
    }

    pub fn with_listener_id(mut self, listener_id: u16) -> Self {
        self.listener_id = listener_id;
        self
    }
}
