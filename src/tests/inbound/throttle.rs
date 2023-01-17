use std::time::Duration;

use crate::{
    config::ConfigContext,
    core::{Core, Session, SessionAddress},
    tests::ParseTestConfig,
};

#[tokio::test]
async fn throttle() {
    let mut core = Core::test();
    let mut config = &mut core.session.config;
    config.throttle.connect = r"[[throttle]]
    match = {if = 'remote-ip', eq = '10.0.0.1'}
    key = 'remote-ip'
    concurrency = 2
    rate = '3/1s'
    "
    .parse_throttle(&ConfigContext::default());
    config.throttle.mail_from = r"[[throttle]]
    key = 'sender'
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::default());
    config.throttle.rcpt_to = r"[[throttle]]
    key = ['remote-ip', 'rcpt']
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::default());

    // Test connection concurrency limit
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    assert!(
        session.is_allowed().await,
        "Concurrency limiter too strict."
    );
    assert!(
        session.is_allowed().await,
        "Concurrency limiter too strict."
    );
    assert!(!session.is_allowed().await, "Concurrency limiter failed.");

    // Test connection rate limit
    session.in_flight.clear(); // Manually reset concurrency limiter
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.in_flight.clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        session.is_allowed().await,
        "Rate limiter did not restore quota."
    );

    // Test mail from rate limit
    session.data.mail_from = SessionAddress {
        address: "sender@test.org".to_string(),
        address_lcase: "sender@test.org".to_string(),
        domain: "test.org".to_string(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.mail_from = SessionAddress {
        address: "other-sender@test.org".to_string(),
        address_lcase: "other-sender@test.org".to_string(),
        domain: "test.org".to_string(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter failed.");

    // Test recipient rate limit
    session.data.rcpt_to.push(SessionAddress {
        address: "recipient@example.org".to_string(),
        address_lcase: "recipient@example.org".to_string(),
        domain: "example.org".to_string(),
        flags: 0,
        dsn_info: None,
    });
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
}
