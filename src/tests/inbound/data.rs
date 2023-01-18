use std::{sync::Arc, time::Duration};

use ahash::AHashSet;
use tokio::sync::mpsc;

use crate::{
    config::{ConfigContext, IfBlock, List},
    core::{Core, Session, SessionAddress},
    queue::{Event, Message, Schedule},
    tests::{
        make_temp_dir,
        session::{DummyIo, VerifyResponse},
        ParseTestConfig,
    },
};

#[tokio::test]
async fn data() {
    let mut core = Core::test();

    // Create temp dir for queue
    let coco = "false";
    let temp_dir = make_temp_dir("smtp_data_test", false);
    core.queue.config.path = IfBlock::new(temp_dir.temp_dir.clone());

    // Create queue receiver
    let (queue_tx, mut queue_rx) = mpsc::channel(128);
    core.queue.tx = queue_tx;

    let mut config = &mut core.session.config.rcpt;
    config.lookup_domains = IfBlock::new(Some(Arc::new(List::Local(AHashSet::from_iter([
        "foobar.org".to_string(),
        "domain.net".to_string(),
    ])))));
    config.lookup_addresses = IfBlock::new(Some(Arc::new(List::Local(AHashSet::from_iter([
        "bill@foobar.org".to_string(),
        "john@foobar.org".to_string(),
        "jane@domain.net".to_string(),
    ])))));

    let mut config = &mut core.session.config;
    core.mail_auth.spf.verify_mail_from = r"[{if = 'remote-ip', eq = '10.0.0.3', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::default());
    config.data.max_received_headers = IfBlock::new(3);
    config.data.max_messages = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 1},
    {else = 100}]"
        .parse_if(&ConfigContext::default());

    core.queue.config.quota = r"[[queue.quota]]
    match = {if = 'sender', eq = 'john@doe.org'}
    key = ['sender']
    messages = 1

    [[queue.quota]]
    match = {if = 'rcpt-domain', eq = 'foobar.org'}
    key = ['rcpt-domain']
    size = 1500

    [[queue.quota]]
    match = {if = 'rcpt', eq = 'jane@domain.net'}
    key = ['rcpt']
    size = 1500
    "
    .parse_quota(&ConfigContext::default());

    // Test queue message builder
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.test_builder().await;

    // Send DATA without RCPT
    session.ehlo("mx.doe.org").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("503 5.5.1");

    // Send broken message
    session
        .send_message("john@doe.org", "bill@foobar.org", "From: john", "550 5.7.7")
        .await;

    // Naive Loop detection
    session
        .send_message("john@doe.org", "bill@foobar.org", "test:loop", "450 4.4.6")
        .await;

    // Send message
    session
        .send_message("john@doe.org", "bill@foobar.org", "test:no_dkim", "250")
        .await;
    read_queue(&mut queue_rx).await;

    // Maximum one message per session is allowed for 10.0.0.1
    session.mail_from("john@doe.org", "250").await;
    session.rcpt_to("bill@foobar.org", "250").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("451 4.4.5");
    session.rset().await;

    // Only one message is allowed in the queue from john@doe.org
    let mut queued_messages = vec![];
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message("john@doe.org", "bill@foobar.org", "test:no_dkim", "250")
        .await;
    queued_messages.push(read_queue(&mut queue_rx).await);
    session
        .send_message(
            "john@doe.org",
            "bill@foobar.org",
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Release quota
    queued_messages.clear();

    // Only 1500 bytes are allowed in the queue to domain foobar.org
    session
        .send_message("jane@foobar.org", "bill@foobar.org", "test:no_dkim", "250")
        .await;
    queued_messages.push(read_queue(&mut queue_rx).await);
    session
        .send_message(
            "jane@foobar.org",
            "bill@foobar.org",
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Only 1500 bytes are allowed in the queue to recipient jane@domain.net
    session
        .send_message("jane@foobar.org", "jane@domain.net", "test:no_dkim", "250")
        .await;
    queued_messages.push(read_queue(&mut queue_rx).await);
    session
        .send_message(
            "jane@foobar.org",
            "jane@domain.net",
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;
}

async fn read_queue(rx: &mut mpsc::Receiver<Event>) -> Schedule<Box<Message>> {
    match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        Ok(Some(event)) => match event {
            Event::Queue(message) => message,
            _ => panic!("Unexpected event."),
        },
        Ok(None) => panic!("Channel closed."),
        Err(_) => panic!("No queue event received."),
    }
}

impl Session<DummyIo> {
    async fn test_builder(&self) {
        let message = self
            .build_message(
                SessionAddress {
                    address: "bill@foobar.org".to_string(),
                    address_lcase: "bill@foobar.org".to_string(),
                    domain: "foobar.org".to_string(),
                    flags: 123,
                    dsn_info: "envelope1".to_string().into(),
                },
                vec![
                    SessionAddress {
                        address: "a@foobar.org".to_string(),
                        address_lcase: "a@foobar.org".to_string(),
                        domain: "foobar.org".to_string(),
                        flags: 1,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "b@test.net".to_string(),
                        address_lcase: "b@test.net".to_string(),
                        domain: "test.net".to_string(),
                        flags: 2,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "c@foobar.org".to_string(),
                        address_lcase: "c@foobar.org".to_string(),
                        domain: "foobar.org".to_string(),
                        flags: 3,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "d@test.net".to_string(),
                        address_lcase: "d@test.net".to_string(),
                        domain: "test.net".to_string(),
                        flags: 4,
                        dsn_info: None,
                    },
                ],
            )
            .await;
        assert_eq!(
            message
                .domains
                .iter()
                .map(|d| d.domain.clone())
                .collect::<Vec<_>>(),
            vec!["foobar.org".to_string(), "test.net".to_string()]
        );
        let rcpts = ["a@foobar.org", "b@test.net", "c@foobar.org", "d@test.net"];
        let domain_idx = [0, 1, 0, 1];
        for rcpt in &message.recipients {
            let idx = (rcpt.flags - 1) as usize;
            assert_eq!(rcpts[idx], rcpt.address);
            assert_eq!(domain_idx[idx], rcpt.domain_idx);
        }
    }
}
