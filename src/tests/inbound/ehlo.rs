use std::time::{Duration, Instant};

use mail_auth::{common::parse::TxtRecordParser, spf::Spf, SpfResult};

use crate::{
    config::{ConfigContext, IfBlock},
    core::{Core, Session},
    tests::{session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
async fn ehlo() {
    let mut core = Core::test();
    core.resolvers.dns.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "mx2.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    let mut config = &mut core.session.config;
    config.data.max_message_size = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 1024},
    {else = 2048}]"
        .parse_if(&ConfigContext::default());
    config.extensions.future_release = r"[{if = 'remote-ip', eq = '10.0.0.1', then = '1h'},
    {else = false}]"
        .parse_if(&ConfigContext::default());
    config.extensions.mt_priority = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'nsep'},
    {else = false}]"
        .parse_if(&ConfigContext::default());
    core.mail_auth.spf.verify_ehlo = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::default());
    config.ehlo.reject_non_fqdn = IfBlock::new(true);

    // Reject non-FQDN domains
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.stream.tls = false;
    session.eval_session_params().await;
    session.cmd("EHLO domain", "550 5.5.0").await;

    // EHLO capabilities evaluation
    session
        .cmd("EHLO mx1.foobar.org", "250")
        .await
        .assert_contains("SIZE 1024")
        .assert_contains("MT-PRIORITY NSEP")
        .assert_contains("FUTURERELEASE 3600")
        .assert_contains("STARTTLS");

    // SPF should be a Pass for 10.0.0.1
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );

    // Test SPF strict mode
    session.data.helo_domain = String::new();
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.stream.tls = true;
    session.eval_session_params().await;
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("550 5.7.23");

    // EHLO capabilities evaluation
    session.ingest(b"EHLO mx2.foobar.org\r\n").await.unwrap();
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    session
        .response()
        .assert_code("250")
        .assert_contains("SIZE 2048")
        .assert_not_contains("MT-PRIORITY")
        .assert_not_contains("FUTURERELEASE")
        .assert_not_contains("STARTTLS");
}
