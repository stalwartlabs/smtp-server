use std::sync::Arc;

use ahash::AHashSet;

use crate::{
    config::ConfigContext,
    core::{Core, Session},
    lookup::Lookup,
    tests::{session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
async fn vrfy_expn() {
    let mut core = Core::test();
    let mut ctx = ConfigContext::default();
    ctx.lookup.insert(
        "vrfy".to_string(),
        Arc::new(Lookup::Local(AHashSet::from_iter([
            "john@foobar.org:john@foobar.org".to_string(),
            "john:john@foobar.org".to_string(),
        ]))),
    );
    ctx.lookup.insert(
        "expn".to_string(),
        Arc::new(Lookup::Local(AHashSet::from_iter([
            "sales:john@foobar.org,bill@foobar.org,jane@foobar.org".to_string(),
            "support:mike@foobar.org".to_string(),
        ]))),
    );

    let mut config = &mut core.session.config.rcpt;

    config.lookup_vrfy = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'vrfy'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.lookup_expn = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'expn'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();

    // EHLO should not avertise VRFY/EXPN to 10.0.0.2
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("EXPN")
        .assert_not_contains("VRFY");
    session.cmd("VRFY john", "252 2.5.1").await;
    session.cmd("EXPN sales", "252 2.5.1").await;

    // EHLO should advertise VRFY/EXPN for 10.0.0.1
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("EXPN")
        .assert_contains("VRFY");

    // Successful VRFY
    session.cmd("VRFY john", "250 john@foobar.org").await;

    // Successful EXPN
    session
        .cmd("EXPN sales", "250")
        .await
        .assert_contains("250-john@foobar.org")
        .assert_contains("250-bill@foobar.org")
        .assert_contains("250 jane@foobar.org");

    // Non-existent VRFY
    session.cmd("VRFY bill", "550 5.1.2").await;

    // Non-existent EXPN
    session.cmd("EXPN procurement", "550 5.1.2").await;
}
