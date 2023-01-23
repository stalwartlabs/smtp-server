use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    config::{Config, ConfigContext, IfBlock},
    core::{Core, Session},
    queue::{manager::Queue, DeliveryAttempt, Event, WorkerResult},
    tests::{outbound::start_test_server, session::VerifyResponse, ParseTestConfig},
};

const REMOTE: &str = "
[remote.lmtp]
address = lmtp.foobar.org
port = 9924
protocol = 'lmtp'
concurrency = 5

[remote.lmtp.tls]
implicit = true
allow-invalid-certs = true
";

#[tokio::test]
async fn lmtp_delivery() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = Core::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("lmtp_delivery_remote");
    let _rx = start_test_server(core.into(), false);

    // Add mock DNS entries
    let mut core = Core::test();
    core.resolvers.dns.ipv4_add(
        "lmtp.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Multiple delivery attempts
    let mut local_qr = core.init_test_queue("lmtp_delivery_local");

    let mut ctx = ConfigContext::default();
    let config = Config::parse(REMOTE).unwrap();
    config.parse_remote_hosts(&mut ctx).unwrap();
    core.queue.config.next_hop = "[{if = 'rcpt-domain', eq = 'foobar.org', then = 'lmtp'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .into_relay_host(&ctx)
        .unwrap();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.rcpt.max_recipients = IfBlock::new(100);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut config = &mut core.queue.config;
    config.retry = IfBlock::new(vec![Duration::from_millis(100)]);
    config.notify = "[{if = 'rcpt-domain', eq = 'foobar.org', then = ['100ms', '200ms']},
    {else = ['100ms']}]"
        .parse_if(&ctx);
    config.expire = "[{if = 'rcpt-domain', eq = 'foobar.org', then = '400ms'},
    {else = '500ms'}]"
        .parse_if(&ctx);
    config.timeout.data = IfBlock::new(Duration::from_millis(50));

    let core = Arc::new(core);
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<bill@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<jane@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<john@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    let mut dsn = Vec::new();
    loop {
        match local_qr.try_read_event().await {
            Some(Event::Queue(message)) => {
                dsn.push(message.inner);
            }
            Some(Event::Done(wr)) => match wr {
                WorkerResult::Done => {
                    break;
                }
                WorkerResult::Retry(retry) => {
                    queue.main.push(retry);
                }
                WorkerResult::OnHold(_) => unreachable!(),
            },
            None | Some(Event::Stop) => break,
        }

        if !queue.main.is_empty() {
            tokio::time::sleep(queue.wake_up_time()).await;
            DeliveryAttempt::from(queue.next_due().unwrap())
                .try_deliver(core.clone(), &mut queue)
                .await;
        }
    }
    assert!(queue.main.is_empty());
    assert_eq!(dsn.len(), 4);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("<jane@foobar.org> (delivered to")
        .assert_contains("<john@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.org> (host 'lmtp.foobar.org' rejected command");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: failed");

    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec![
            "bill@foobar.org".to_string(),
            "jane@foobar.org".to_string(),
            "john@foobar.org".to_string()
        ]
    );
    remote_qr.assert_empty_queue();
}
