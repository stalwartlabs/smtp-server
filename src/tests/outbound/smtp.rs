use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::MX;

use crate::{
    config::{ConfigContext, IfBlock},
    core::{Core, Session},
    queue::{manager::Queue, DeliveryAttempt, Event, WorkerResult},
    tests::{outbound::start_test_server, session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = Core::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_delivery_remote");
    let _rx = start_test_server(core.into(), true);

    // Add mock DNS entries
    let mut core = Core::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![
            MX {
                exchanges: vec!["mx1.foobar.org".to_string()],
                preference: 10,
            },
            MX {
                exchanges: vec!["mx2.foobar.org".to_string()],
                preference: 20,
            },
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.mx_add(
        "foobar.net",
        vec![MX {
            exchanges: vec!["mx1.foobar.net".to_string(), "mx2.foobar.net".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Multiple delivery attempts
    let mut local_qr = core.init_test_queue("smtp_delivery_local");
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.rcpt.max_recipients = IfBlock::new(100);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut config = &mut core.queue.config;
    config.retry = IfBlock::new(vec![Duration::from_millis(100)]);
    config.notify = "[{if = 'rcpt-domain', eq = 'foobar.org', then = ['100ms', '200ms']},
    {else = ['100ms']}]"
        .parse_if(&ConfigContext::default());
    config.expire = "[{if = 'rcpt-domain', eq = 'foobar.org', then = '650ms'},
    {else = '750ms'}]"
        .parse_if(&ConfigContext::default());

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
                "<ok@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<ok@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    let message = local_qr.read_event().await.unwrap_message();
    let num_domains = message.domains.len();
    assert_eq!(num_domains, 3);
    DeliveryAttempt::from(message)
        .try_deliver(core.clone(), &mut queue)
        .await;
    let mut dsn = Vec::new();
    let mut domain_retries = vec![0; num_domains];
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
                    for (idx, domain) in retry.inner.domains.iter().enumerate() {
                        domain_retries[idx] = domain.retry.inner;
                    }
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
    assert_eq!(domain_retries[0], 0, "retries {domain_retries:?}");
    assert!(domain_retries[1] >= 5, "retries {domain_retries:?}");
    assert!(domain_retries[2] >= 5, "retries {domain_retries:?}");
    assert!(
        domain_retries[1] >= domain_retries[2],
        "retries {domain_retries:?}"
    );

    assert!(queue.main.is_empty());
    assert_eq!(dsn.len(), 5);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<ok@foobar.net> (delivered to")
        .assert_contains("<ok@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.net> (host ")
        .assert_contains("<fail@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.net> (host ")
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
        vec!["ok@foobar.net".to_string()]
    );
    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["ok@foobar.org".to_string()]
    );

    remote_qr.assert_empty_queue();
}
