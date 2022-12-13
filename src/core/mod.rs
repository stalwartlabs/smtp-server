use std::net::IpAddr;

pub mod context;
pub mod rate_limit;

pub struct Context {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub sender_domain: String,
    pub sender: String,
    pub rcpt_domain: String,
    pub rcpt: String,
    pub authenticated_as: String,
    pub mx: String,
    pub listener_id: u64,
    pub priority: i64,
}
