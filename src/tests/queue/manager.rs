use std::time::{Duration, Instant};

use mail_auth::trust_dns_resolver::proto::op::ResponseCode;

use crate::queue::{manager::Queue, Domain, Message, Schedule, Status};

#[test]
fn queue_due() {
    let mut queue = Queue::default();

    let mut message = new_message(0);
    message.domains.push(domain("c", 3, 8, 9));
    queue.schedule(Schedule {
        due: message.next_delivery_event(),
        inner: message,
    });

    let mut message = new_message(1);
    message.domains.push(domain("b", 2, 6, 7));
    queue.schedule(Schedule {
        due: message.next_delivery_event(),
        inner: message,
    });

    let mut message = new_message(2);
    message.domains.push(domain("a", 1, 4, 5));
    queue.schedule(Schedule {
        due: message.next_delivery_event(),
        inner: message,
    });

    for domain in vec!["a", "b", "c"].into_iter() {
        let wake_up = queue.wake_up_time();
        assert!(
            (900..=1000).contains(&wake_up.as_millis()),
            "{}",
            wake_up.as_millis()
        );
        std::thread::sleep(wake_up);
        queue.next_due().unwrap().domain(domain);
    }

    assert!(queue.next_due().is_none());
}

#[test]
fn delivery_events() {
    let mut message = new_message(0);

    message.domains.push(domain("a", 1, 2, 3));
    message.domains.push(domain("b", 4, 5, 6));
    message.domains.push(domain("c", 7, 8, 9));

    for t in 0..2 {
        assert_eq!(message.next_event().unwrap(), message.domain("a").retry.due);
        assert_eq!(message.next_delivery_event(), message.domain("a").retry.due);
        assert_eq!(
            message
                .next_event_after(message.domain("a").expires)
                .unwrap(),
            message.domain("b").retry.due
        );
        assert_eq!(
            message
                .next_event_after(message.domain("b").expires)
                .unwrap(),
            message.domain("c").retry.due
        );
        assert_eq!(
            message
                .next_event_after(message.domain("c").notify.due)
                .unwrap(),
            message.domain("c").expires
        );
        assert!(message
            .next_event_after(message.domain("c").expires)
            .is_none());

        if t == 0 {
            message.domains.reverse();
        } else {
            message.domains.swap(0, 1);
        }
    }

    message.domain_mut("a").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert_eq!(message.next_event().unwrap(), message.domain("b").retry.due);
    assert_eq!(message.next_delivery_event(), message.domain("b").retry.due);

    message.domain_mut("b").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert_eq!(message.next_event().unwrap(), message.domain("c").retry.due);
    assert_eq!(message.next_delivery_event(), message.domain("c").retry.due);

    message.domain_mut("c").set_status(
        mail_auth::Error::DnsRecordNotFound(ResponseCode::BADCOOKIE),
        &[],
    );
    assert!(message.next_event().is_none());
}

pub fn new_message(id: u64) -> Box<Message> {
    Box::new(Message {
        size: 0,
        id,
        path: Default::default(),
        created: 0,
        return_path: "sender@foobar.org".to_string(),
        return_path_lcase: "".to_string(),
        return_path_domain: "foobar.org".to_string(),
        recipients: vec![],
        domains: vec![],
        flags: 0,
        env_id: None,
        priority: 0,
        queue_refs: vec![],
    })
}

fn domain(domain: &str, retry: u64, notify: u64, expires: u64) -> Domain {
    Domain {
        domain: domain.to_string(),
        retry: Schedule::later(Duration::from_secs(retry)),
        notify: Schedule::later(Duration::from_secs(notify)),
        expires: Instant::now() + Duration::from_secs(expires),
        status: Status::Scheduled,
        changed: false,
    }
}

impl Message {
    fn domain(&self, name: &str) -> &Domain {
        self.domains.iter().find(|d| d.domain == name).unwrap()
    }

    fn domain_mut(&mut self, name: &str) -> &mut Domain {
        self.domains.iter_mut().find(|d| d.domain == name).unwrap()
    }
}
