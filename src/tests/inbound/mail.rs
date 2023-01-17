use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{common::parse::TxtRecordParser, spf::Spf, IprevResult, SpfResult};

use crate::{
    config::{ConfigContext, IfBlock, VerifyStrategy},
    core::{Core, Session},
    tests::{session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
async fn mail() {
    let mut core = Core::test();
    core.resolvers.dns.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ptr_add(
        "10.0.0.1".parse().unwrap(),
        vec!["mx1.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org.",
        vec!["10.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ptr_add(
        "10.0.0.2".parse().unwrap(),
        vec!["mx2.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );

    let mut config = &mut core.session.config;
    config.ehlo.require = IfBlock::new(true);
    core.mail_auth.spf.verify_ehlo = IfBlock::new(VerifyStrategy::Relaxed);
    core.mail_auth.spf.verify_mail_from = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::default());
    core.mail_auth.iprev.verify = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::default());
    config.throttle.mail_from = r"[[throttle]]
    match = {if = 'remote-ip', eq = '10.0.0.1'}
    key = 'sender'
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::default());

    // Be rude and do not say EHLO
    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Both IPREV and SPF should pass
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("250");
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.spf_mail_from.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.iprev.as_ref().unwrap().result(),
        &IprevResult::Pass
    );

    // Multiple MAIL FROMs should not be allowed
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Test rate limit
    for n in 0..2 {
        session.ingest(b"RSET\r\n").await.unwrap();
        session.response().assert_code("250");
        session
            .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
            .await
            .unwrap();
        session
            .response()
            .assert_code(if n == 0 { "250" } else { "451 4.4.5" });
    }

    // Test strict IPREV
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.data.iprev = None;
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.25");
    session.data.iprev = None;
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.org.",
        vec!["10.0.0.2".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );

    // Test strict SPF
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.23");
    core.resolvers.dns.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
}
