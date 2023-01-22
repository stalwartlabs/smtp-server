use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    config::{ConfigContext, IfBlock},
    core::{Core, Session},
    queue::{manager::Queue, DeliveryAttempt, Event, WorkerResult},
    tests::{session::VerifyResponse, ParseTestConfig},
};

#[tokio::test]
async fn queue_retry() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    let mut core = Core::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_queue_retry_test");

    let mut config = &mut core.session.config.rcpt;
    config.relay = IfBlock::new(true);
    let mut config = &mut core.session.config.extensions;
    config.deliver_by = IfBlock::new(Some(Duration::from_secs(86400)));
    config.future_release = IfBlock::new(Some(Duration::from_secs(86400)));
    let mut config = &mut core.queue.config;
    config.retry = IfBlock::new(vec![
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_millis(300),
    ]);
    config.notify = "[{if = 'sender-domain', eq = 'test.org', then = ['150ms', '200ms']},
    {else = ['15h', '22h']}]"
        .parse_if(&ConfigContext::default());
    config.expire = "[{if = 'sender-domain', eq = 'test.org', then = '600ms'},
    {else = '1d'}]"
        .parse_if(&ConfigContext::default());

    // Create test message
    let core = Arc::new(core);
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    let attempt = DeliveryAttempt::from(qr.read_event().await.unwrap_message());

    // Expect a failed DSN
    let path = attempt.message.path.clone();
    attempt.try_deliver(core.clone(), &mut queue).await;
    let message = qr.read_event().await.unwrap_message();
    assert_eq!(message.return_path, "");
    assert_eq!(message.domains.first().unwrap().domain, "test.org");
    assert_eq!(message.recipients.first().unwrap().address, "john@test.org");
    message
        .read_lines()
        .assert_contains("Content-Type: multipart/report")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");
    qr.read_event().await.unwrap_done();
    assert!(!path.exists());

    // Expect a failed DSN for foobar.org, followed by two delayed DSN and
    // a final failed DSN for _dns_error.org.
    session
        .send_message(
            "john@test.org",
            &["bill@foobar.org", "jane@_dns_error.org"],
            "test:no_dkim",
            "250",
        )
        .await;
    let attempt = DeliveryAttempt::from(qr.read_event().await.unwrap_message());
    let path = attempt.message.path.clone();
    let mut dsn = Vec::new();
    let mut num_retries = 0;
    attempt.try_deliver(core.clone(), &mut queue).await;
    loop {
        match qr.try_read_event().await {
            Some(Event::Queue(message)) => {
                dsn.push(message.inner);
            }
            Some(Event::Done(wr)) => match wr {
                WorkerResult::Done => break,
                WorkerResult::Retry(retry) => {
                    queue.main.push(retry);
                    num_retries += 1;
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
    assert_eq!(num_retries, 3);
    assert_eq!(dsn.len(), 4);
    assert!(!path.exists());
    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<bill@foobar.org> (failed to lookup 'foobar.org'")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: failed");

    // Test FUTURERELEASE + DELIVERBY (RETURN)
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message(
            "<bill@foobar.org> HOLDFOR=60 BY=3600;R",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let now = Instant::now();
    let schedule = qr.read_event().await.unwrap_schedule();
    assert!([59, 60].contains(&schedule.due.duration_since(now).as_secs()));
    assert!([59, 60].contains(
        &schedule
            .inner
            .next_delivery_event()
            .duration_since(now)
            .as_secs()
    ));
    assert!([3599, 3600].contains(
        &schedule
            .inner
            .domains
            .first()
            .unwrap()
            .expires
            .duration_since(now)
            .as_secs()
    ));
    assert!([54059, 54060].contains(
        &schedule
            .inner
            .domains
            .first()
            .unwrap()
            .notify
            .due
            .duration_since(now)
            .as_secs()
    ));

    // Test DELIVERBY (NOTIFY)
    session
        .send_message(
            "<bill@foobar.org> BY=3600;N",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let now = Instant::now();
    let schedule = qr.read_event().await.unwrap_schedule();
    assert!([3599, 3600].contains(
        &schedule
            .inner
            .domains
            .first()
            .unwrap()
            .notify
            .due
            .duration_since(now)
            .as_secs()
    ));
}
