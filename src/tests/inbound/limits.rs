use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::{
    config::ConfigContext,
    core::{Core, Session},
    tests::{session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
async fn limits() {
    let mut core = Core::test();
    let mut config = &mut core.session.config;
    config.transfer_limit = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 10},
    {else = 1024}]"
        .parse_if(&ConfigContext::default());
    config.timeout = r"[{if = 'remote-ip', eq = '10.0.0.2', then = '500ms'},
    {else = '30m'}]"
        .parse_if(&ConfigContext::default());
    config.duration = r"[{if = 'remote-ip', eq = '10.0.0.3', then = '500ms'},
    {else = '60m'}]"
        .parse_if(&ConfigContext::default());
    let (_tx, rx) = watch::channel(true);

    // Exceed max line length
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    let mut buf = vec![b'A'; 2049];
    session.ingest(&buf).await.unwrap();
    session.ingest(b"\r\n").await.unwrap();
    session.response().assert_code("554 5.3.4");

    // Invalid command
    buf.extend_from_slice(b"\r\n");
    session.ingest(&buf).await.unwrap();
    session.response().assert_code("500 5.5.1");

    // Exceed transfer quota
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn_(rx.clone()).await;
    session.response().assert_code("451 4.7.28");

    // Loitering
    session.data.remote_ip = "10.0.0.3".parse().unwrap();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn_(rx.clone()).await;
    session.response().assert_code("453 4.3.2");

    // Timeout
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn_(rx.clone()).await;
    session.response().assert_code("221 2.0.0");
}
