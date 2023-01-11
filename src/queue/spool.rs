use smtp_proto::Response;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::slice::Iter;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use std::{fmt::Write, time::Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::{fs, io::AsyncWriteExt};

use crate::config::QueueConfig;
use crate::core::QueueCore;

use super::{
    instant_to_timestamp, Domain, Error, ErrorDetails, Event, HostResponse, Message, Recipient,
    Schedule, SimpleEnvelope, Status, RCPT_STATUS_CHANGED,
};

impl QueueCore {
    pub async fn queue_message(
        &self,
        mut message: Box<Message>,
        mut message_bytes: Vec<Vec<u8>>,
    ) -> bool {
        // Generate id
        if message.id == 0 {
            message.id = self.queue_id();
        }

        // Build path
        message.path = self.config.path.eval(message.as_ref()).await.clone();
        let hash = *self.config.hash.eval(message.as_ref()).await;
        if hash > 0 {
            message.path.push((message.id % hash).to_string());
        }
        let _ = fs::create_dir(&message.path).await;
        message
            .path
            .push(format!("{}_{}.msg", message.id, message.size));

        // Serialize metadata
        message_bytes.push(message.serialize());

        // Save message
        let mut file = match fs::File::create(&message.path).await {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("Failed to create file {}: {}", message.path.display(), err);
                return false;
            }
        };
        for bytes in message_bytes {
            if let Err(err) = file.write_all(&bytes).await {
                tracing::error!(
                    "Failed to write to file {}: {}",
                    message.path.display(),
                    err
                );
                return false;
            }
        }
        if let Err(err) = file.flush().await {
            tracing::error!("Failed to flush file {}: {}", message.path.display(), err);
            return false;
        }

        // Queue the message
        if self
            .tx
            .send(Event::Queue(Schedule {
                due: message.next_event().unwrap(),
                inner: message,
            }))
            .await
            .is_err()
        {
            tracing::warn!(
                "Queue channel closed: Message queued but won't be sent until next restart."
            );
        }

        true
    }

    pub fn queue_id(&self) -> u64 {
        (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .saturating_sub(946684800)
            & 0xFFFFFFFF)
            | (self.id_seq.fetch_add(1, Ordering::Relaxed) as u64) << 32
    }
}

impl Message {
    pub fn new_boxed(
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
    ) -> Box<Message> {
        Box::new(Message {
            id: 0,
            path: PathBuf::new(),
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            return_path: return_path.into(),
            return_path_lcase: return_path_lcase.into(),
            return_path_domain: return_path_domain.into(),
            recipients: Vec::with_capacity(1),
            domains: Vec::with_capacity(1),
            flags: 0,
            env_id: None,
            priority: 0,
            size: 0,
            size_headers: 0,
            queue_refs: vec![],
        })
    }

    pub async fn add_recipient(
        &mut self,
        rcpt: impl Into<String>,
        rcpt_lcase: impl Into<String>,
        rcpt_domain: impl Into<String>,
        config: &QueueConfig,
    ) {
        let rcpt_domain = rcpt_domain.into();
        let domain_idx =
            if let Some(idx) = self.domains.iter().position(|d| d.domain == rcpt_domain) {
                idx
            } else {
                let idx = self.domains.len();
                let expires = *config
                    .expire
                    .eval(&SimpleEnvelope::new(self, &rcpt_domain))
                    .await;
                self.domains.push(Domain {
                    domain: rcpt_domain,
                    retry: Schedule::now(),
                    notify: Schedule::later(expires + Duration::from_secs(10)),
                    expires: Instant::now() + expires,
                    status: Status::Scheduled,
                    changed: false,
                });
                idx
            };
        self.recipients.push(Recipient {
            domain_idx,
            address: rcpt.into(),
            address_lcase: rcpt_lcase.into(),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
        });
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = String::with_capacity(
            self.return_path.len()
                + self.env_id.as_ref().map_or(0, |e| e.len())
                + (self.domains.len() * 64)
                + (self.recipients.len() * 64)
                + 50,
        );

        // Serialize message properties
        (self.created as usize).serialize(&mut buf);
        self.return_path.serialize(&mut buf);
        (self.env_id.as_deref().unwrap_or_default()).serialize(&mut buf);
        (self.flags as usize).serialize(&mut buf);
        self.priority.serialize(&mut buf);
        self.size_headers.serialize(&mut buf);

        // Serialize domains
        let now = Instant::now();
        self.domains.len().serialize(&mut buf);
        for domain in &self.domains {
            domain.domain.serialize(&mut buf);
            (instant_to_timestamp(now, domain.expires) as usize).serialize(&mut buf);
        }

        // Serialize recipients
        self.recipients.len().serialize(&mut buf);
        for rcpt in &self.recipients {
            rcpt.domain_idx.serialize(&mut buf);
            rcpt.address.serialize(&mut buf);
            (rcpt.orcpt.as_deref().unwrap_or_default()).serialize(&mut buf);
        }

        // Serialize domain status
        for (idx, domain) in self.domains.iter().enumerate() {
            domain.serialize(idx, now, &mut buf);
        }

        // Serialize recipient status
        for (idx, rcpt) in self.recipients.iter().enumerate() {
            rcpt.serialize(idx, &mut buf);
        }

        buf.into_bytes()
    }

    pub async fn from_path(path: PathBuf) -> Result<Self, String> {
        let (id, size) = path
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|f| f.rsplit_once('.'))
            .and_then(|(f, _)| f.rsplit_once('_'))
            .and_then(|(id, size)| (id.parse::<u64>().ok()?, size.parse::<u64>().ok()?).into())
            .ok_or_else(|| format!("Invalid queue file name {}", path.display()))?;
        let file_size = fs::metadata(&path)
            .await
            .map_err(|err| {
                format!(
                    "Failed to obtain file metadata for {}: {}",
                    path.display(),
                    err
                )
            })?
            .len();
        if size == 0 || size >= file_size {
            return Err(format!(
                "Invalid queue file name size {} for {}",
                size,
                path.display()
            ));
        }
        let mut buf = Vec::with_capacity((file_size - size) as usize);
        let mut file = File::open(&path)
            .await
            .map_err(|err| format!("Failed to open queue file {}: {}", path.display(), err))?;
        file.seek(SeekFrom::Start(size))
            .await
            .map_err(|err| format!("Failed to seek queue file {}: {}", path.display(), err))?;
        file.read_to_end(&mut buf)
            .await
            .map_err(|err| format!("Failed to read queue file {}: {}", path.display(), err))?;

        let mut message = Self::deserialize(&buf)
            .ok_or_else(|| format!("Failed to deserialize metadata for file {}", path.display()))?;
        message.path = path;
        message.size = size as usize;
        message.id = id;
        Ok(message)
    }

    fn deserialize(bytes: &[u8]) -> Option<Self> {
        let mut bytes = bytes.iter();
        let created = usize::deserialize(&mut bytes)? as u64;
        let return_path = String::deserialize(&mut bytes)?;
        let return_path_lcase = return_path.to_lowercase();
        let env_id = String::deserialize(&mut bytes)?;

        let mut message = Message {
            id: 0,
            path: PathBuf::new(),
            created,
            return_path_domain: return_path_lcase
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or_default()
                .to_string(),
            return_path_lcase,
            return_path,
            env_id: if !env_id.is_empty() {
                env_id.into()
            } else {
                None
            },
            flags: usize::deserialize(&mut bytes)? as u64,
            priority: i16::deserialize(&mut bytes)?,
            size: 0,
            size_headers: usize::deserialize(&mut bytes)?,
            recipients: vec![],
            domains: vec![],
            queue_refs: vec![],
        };

        // Deserialize domains
        let num_domains = usize::deserialize(&mut bytes)?;
        message.domains = Vec::with_capacity(num_domains);
        for _ in 0..num_domains {
            message.domains.push(Domain {
                domain: String::deserialize(&mut bytes)?,
                expires: Instant::deserialize(&mut bytes)?,
                retry: Schedule::now(),
                notify: Schedule::now(),
                status: Status::Scheduled,
                changed: false,
            });
        }

        // Deserialize recipients
        let num_recipients = usize::deserialize(&mut bytes)?;
        message.recipients = Vec::with_capacity(num_recipients);
        for _ in 0..num_recipients {
            let domain_idx = usize::deserialize(&mut bytes)?;
            let address = String::deserialize(&mut bytes)?;
            let orcpt = String::deserialize(&mut bytes)?;
            message.recipients.push(Recipient {
                domain_idx,
                address_lcase: address.to_lowercase(),
                address,
                status: Status::Scheduled,
                flags: 0,
                orcpt: if !orcpt.is_empty() {
                    orcpt.into()
                } else {
                    None
                },
            });
        }

        // Deserialize status
        while let Some((ch, idx)) = bytes
            .next()
            .and_then(|ch| (ch, usize::deserialize(&mut bytes)?).into())
        {
            match ch {
                b'D' => {
                    if let (Some(domain), Some(retry), Some(notify), Some(status)) = (
                        message.domains.get_mut(idx),
                        Schedule::deserialize(&mut bytes),
                        Schedule::deserialize(&mut bytes),
                        Status::deserialize(&mut bytes),
                    ) {
                        domain.retry = retry;
                        domain.notify = notify;
                        domain.status = status;
                    } else {
                        break;
                    }
                }
                b'R' => {
                    if let (Some(rcpt), Some(flags), Some(status)) = (
                        message.recipients.get_mut(idx),
                        usize::deserialize(&mut bytes),
                        Status::deserialize(&mut bytes),
                    ) {
                        rcpt.flags = flags as u64;
                        rcpt.status = status;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        message.into()
    }

    fn serialize_changes(&mut self) -> Vec<u8> {
        let now = Instant::now();
        let mut buf = String::with_capacity(128);

        for (idx, domain) in self.domains.iter_mut().enumerate() {
            if domain.changed {
                domain.changed = false;
                domain.serialize(idx, now, &mut buf);
            }
        }

        for (idx, rcpt) in self.recipients.iter_mut().enumerate() {
            if rcpt.has_flag(RCPT_STATUS_CHANGED) {
                rcpt.flags &= !RCPT_STATUS_CHANGED;
                rcpt.serialize(idx, &mut buf);
            }
        }

        buf.into_bytes()
    }

    pub async fn save_changes(&mut self) {
        let buf = self.serialize_changes();
        if !buf.is_empty() {
            let err = match OpenOptions::new().append(true).open(&self.path).await {
                Ok(mut file) => match file.write_all(&buf).await {
                    Ok(_) => return,
                    Err(err) => err,
                },
                Err(err) => err,
            };
            tracing::error!(
                module = "queue",
                event = "error",
                "Failed to write to {}: {}",
                self.path.display(),
                err
            );
        }
    }

    pub async fn remove(&self) {
        if let Err(err) = fs::remove_file(&self.path).await {
            tracing::error!(
                module = "queue",
                event = "error",
                "Failed to delete queued message {}: {}",
                self.path.display(),
                err
            );
        }
    }
}

impl Domain {
    fn serialize(&self, idx: usize, now: Instant, buf: &mut String) {
        let _ = write!(
            buf,
            "D{} {} {} {} {} ",
            idx,
            self.retry.inner,
            instant_to_timestamp(now, self.retry.due),
            self.notify.inner,
            instant_to_timestamp(now, self.notify.due)
        );
        self.status.serialize(buf);
    }
}

impl Recipient {
    fn serialize(&self, idx: usize, buf: &mut String) {
        let _ = write!(buf, "R{} {} ", idx, self.flags);
        self.status.serialize(buf);
    }
}

pub trait QueueSerializer: Sized {
    fn serialize(&self, buf: &mut String);
    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl<T: QueueSerializer, E: QueueSerializer> QueueSerializer for Status<T, E> {
    fn serialize(&self, buf: &mut String) {
        match self {
            Status::Scheduled => buf.push('S'),
            Status::Completed(s) => {
                buf.push('C');
                s.serialize(buf);
            }
            Status::TemporaryFailure(s) => {
                buf.push('T');
                s.serialize(buf);
            }
            Status::PermanentFailure(s) => {
                buf.push('F');
                s.serialize(buf);
            }
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match bytes.next()? {
            b'S' => Self::Scheduled.into(),
            b'C' => Self::Completed(T::deserialize(bytes)?).into(),
            b'T' => Self::TemporaryFailure(E::deserialize(bytes)?).into(),
            b'F' => Self::PermanentFailure(E::deserialize(bytes)?).into(),
            _ => None,
        }
    }
}

impl QueueSerializer for Response<String> {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(
            buf,
            "{} {} {} {} {} {}",
            self.code,
            self.esc[0],
            self.esc[1],
            self.esc[2],
            self.message.len(),
            self.message
        );
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Response {
            code: usize::deserialize(bytes)? as u16,
            esc: [
                usize::deserialize(bytes)? as u8,
                usize::deserialize(bytes)? as u8,
                usize::deserialize(bytes)? as u8,
            ],
            message: String::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for usize {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{} ", self);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let mut num = 0;
        loop {
            match bytes.next()? {
                ch @ (b'0'..=b'9') => {
                    num = (num * 10) + (*ch - b'0') as usize;
                }
                b' ' => {
                    return num.into();
                }
                _ => {
                    return None;
                }
            }
        }
    }
}

impl QueueSerializer for i16 {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{} ", self);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let mut num = 0;
        let mut mul = 1;
        loop {
            match bytes.next()? {
                ch @ (b'0'..=b'9') => {
                    num = (num * 10) + (*ch - b'0') as i16;
                }
                b' ' => {
                    return (num * mul).into();
                }
                b'-' => {
                    mul = -1;
                }
                _ => {
                    return None;
                }
            }
        }
    }
}

impl QueueSerializer for ErrorDetails {
    fn serialize(&self, buf: &mut String) {
        self.entity.serialize(buf);
        self.details.serialize(buf);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        ErrorDetails {
            entity: String::deserialize(bytes)?,
            details: String::deserialize(bytes)?,
        }
        .into()
    }
}

impl<T: QueueSerializer> QueueSerializer for HostResponse<T> {
    fn serialize(&self, buf: &mut String) {
        self.hostname.serialize(buf);
        self.response.serialize(buf);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        HostResponse {
            hostname: T::deserialize(bytes)?,
            response: Response::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for String {
    fn serialize(&self, buf: &mut String) {
        if !self.is_empty() {
            let _ = write!(buf, "{} {}", self.len(), self);
        } else {
            buf.push_str("0 ");
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match usize::deserialize(bytes)? {
            len @ (1..=4096) => {
                String::from_utf8(bytes.take(len).copied().collect::<Vec<_>>()).ok()
            }
            0 => String::new().into(),
            _ => None,
        }
    }
}

impl QueueSerializer for &str {
    fn serialize(&self, buf: &mut String) {
        if !self.is_empty() {
            let _ = write!(buf, "{} {}", self.len(), self);
        } else {
            buf.push_str("0 ");
        }
    }

    fn deserialize(_bytes: &mut Iter<'_, u8>) -> Option<Self> {
        unimplemented!()
    }
}

impl QueueSerializer for Instant {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{} ", instant_to_timestamp(Instant::now(), *self),);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let timestamp = usize::deserialize(bytes)? as u64;
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if timestamp > current_timestamp {
            Instant::now() + Duration::from_secs(timestamp - current_timestamp)
        } else {
            Instant::now()
        }
        .into()
    }
}

impl QueueSerializer for Schedule<u32> {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(
            buf,
            "{} {} ",
            self.inner,
            instant_to_timestamp(Instant::now(), self.due),
        );
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Schedule {
            inner: usize::deserialize(bytes)? as u32,
            due: Instant::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for Error {
    fn serialize(&self, buf: &mut String) {
        match self {
            Error::DnsError(e) => {
                buf.push('0');
                e.serialize(buf);
            }
            Error::UnexpectedResponse(e) => {
                buf.push('1');
                e.serialize(buf);
            }
            Error::ConnectionError(e) => {
                buf.push('2');
                e.serialize(buf);
            }
            Error::TlsError(e) => {
                buf.push('3');
                e.serialize(buf);
            }
            Error::DaneError(e) => {
                buf.push('4');
                e.serialize(buf);
            }
            Error::MtaStsError(e) => {
                buf.push('5');
                e.serialize(buf);
            }
            Error::RateLimited => {
                buf.push('6');
            }
            Error::ConcurrencyLimited => {
                buf.push('7');
            }
            Error::Io(e) => {
                buf.push('8');
                e.serialize(buf);
            }
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match bytes.next()? {
            b'0' => Error::DnsError(String::deserialize(bytes)?).into(),
            b'1' => Error::UnexpectedResponse(HostResponse::deserialize(bytes)?).into(),
            b'2' => Error::ConnectionError(ErrorDetails::deserialize(bytes)?).into(),
            b'3' => Error::TlsError(ErrorDetails::deserialize(bytes)?).into(),
            b'4' => Error::DaneError(ErrorDetails::deserialize(bytes)?).into(),
            b'5' => Error::MtaStsError(String::deserialize(bytes)?).into(),
            b'6' => Error::RateLimited.into(),
            b'7' => Error::ConcurrencyLimited.into(),
            b'8' => Error::Io(String::deserialize(bytes)?).into(),
            _ => None,
        }
    }
}

impl QueueSerializer for () {
    fn serialize(&self, _buf: &mut String) {}

    fn deserialize(_bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Some(())
    }
}

#[cfg(test)]
mod test {
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };

    use smtp_proto::{Response, MAIL_REQUIRETLS, MAIL_SMTPUTF8, RCPT_CONNEG, RCPT_NOTIFY_FAILURE};
    use tokio::fs;

    use crate::queue::{
        Domain, Error, ErrorDetails, HostResponse, Message, Recipient, Schedule, Status,
        RCPT_STATUS_CHANGED,
    };

    #[tokio::test]
    async fn queue_serialize_message() {
        let mut message = Message {
            size_headers: 7890,
            size: 0,
            id: 0,
            path: PathBuf::new(),
            created: 123456,
            return_path: "sender@FooBar.org".to_string(),
            return_path_lcase: "sender@foobar.org".to_string(),
            return_path_domain: "foobar.org".to_string(),
            recipients: vec![
                Recipient {
                    domain_idx: 0,
                    address: "FOOBAR@example.org".to_string(),
                    address_lcase: "foobar@example.org".to_string(),
                    status: Status::Scheduled,
                    flags: RCPT_CONNEG,
                    orcpt: None,
                },
                Recipient {
                    domain_idx: 1,
                    address: "FOOBAR@example.org".to_string(),
                    address_lcase: "foobar@example.org".to_string(),
                    status: Status::Scheduled,
                    flags: RCPT_NOTIFY_FAILURE,
                    orcpt: None,
                },
            ],
            domains: vec![
                Domain {
                    domain: "example.org".to_string(),
                    retry: Schedule::now(),
                    notify: Schedule::now(),
                    expires: Instant::now() + Duration::from_secs(10),
                    status: Status::Scheduled,
                    changed: false,
                },
                Domain {
                    domain: "example.com".to_string(),
                    retry: Schedule::now(),
                    notify: Schedule::now(),
                    expires: Instant::now() + Duration::from_secs(10),
                    status: Status::Scheduled,
                    changed: false,
                },
            ],
            flags: MAIL_REQUIRETLS | MAIL_SMTPUTF8,
            env_id: "hello".to_string().into(),
            priority: -1,

            queue_refs: vec![],
        };

        // Roundtrip test
        let mut bytes = message.serialize();
        assert_msg_eq(&message, &Message::deserialize(&bytes).unwrap());

        // Write update
        message.recipients[0].status = Status::PermanentFailure(HostResponse {
            hostname: ErrorDetails {
                entity: "mx.example.org".to_string(),
                details: "RCPT TO:<foobar@example.org>".to_string(),
            },
            response: Response {
                code: 550,
                esc: [5, 1, 2],
                message: "User does not exist\nplease contact support for details\n".to_string(),
            },
        });
        message.recipients[0].flags |= RCPT_STATUS_CHANGED;

        message.recipients[1].status = Status::Completed(HostResponse {
            hostname: "smtp.foo.bar".to_string(),
            response: Response {
                code: 250,
                esc: [2, 1, 5],
                message: "Great success!".to_string(),
            },
        });
        message.recipients[1].flags |= RCPT_STATUS_CHANGED;

        message.domains[0].status =
            Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
                hostname: ErrorDetails {
                    entity: "mx2.example.org".to_string(),
                    details: "DATA".to_string(),
                },
                response: Response {
                    code: 450,
                    esc: [4, 3, 1],
                    message: "Can't accept mail at this moment".to_string(),
                },
            }));
        message.domains[0].changed = true;

        message.domains[1].status =
            Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                entity: "mx.domain.org".to_string(),
                details: "Connection timeout".to_string(),
            }));
        message.domains[1].changed = true;
        message.domains[1].notify = Schedule::later(Duration::from_secs(30));
        message.domains[1].notify.inner = 321;
        message.domains[1].retry = Schedule::later(Duration::from_secs(62));
        message.domains[1].retry.inner = 678;
        let changes = message.serialize_changes();
        assert!(message.serialize_changes().is_empty());
        bytes.extend_from_slice(&changes);
        assert_msg_eq(&message, &Message::deserialize(&bytes).unwrap());

        // Disk deserialization
        let mut raw_message =
            "From: test@domain.org\r\nTo: rcpt@example.org\r\nSubject: test\r\n\r\nhi"
                .as_bytes()
                .to_vec();
        message.id = 12345;
        message.size = raw_message.len();
        message.path = std::env::temp_dir();
        message
            .path
            .push(format!("{}_{}.msg", message.id, message.size));
        raw_message.extend_from_slice(&bytes);
        fs::write(&message.path, raw_message).await.unwrap();
        let message_check = Message::from_path(message.path.clone()).await.unwrap();
        assert_msg_eq(&message, &message_check);
        message.remove().await;
        assert!(!message.path.exists());
    }

    fn assert_msg_eq(msg: &Message, other: &Message) {
        assert_eq!(msg.id, other.id);
        assert_eq!(msg.created, other.created);
        assert_eq!(msg.path, other.path);
        assert_eq!(msg.return_path, other.return_path);
        assert_eq!(msg.return_path_lcase, other.return_path_lcase);
        assert_eq!(msg.return_path_domain, other.return_path_domain);
        assert_eq!(msg.recipients, other.recipients);
        assert_eq!(msg.domains.len(), other.domains.len());
        for (domain, other) in msg.domains.iter().zip(other.domains.iter()) {
            assert_eq!(domain.domain, other.domain);
            assert_eq!(domain.retry.inner, other.retry.inner);
            assert_eq!(domain.notify.inner, other.notify.inner);
            assert_eq!(domain.status, other.status);
            assert_instant_eq(domain.expires, other.expires);
            assert_instant_eq(domain.retry.due, other.retry.due);
            assert_instant_eq(domain.notify.due, other.notify.due);
        }
        assert_eq!(msg.flags, other.flags);
        assert_eq!(msg.env_id, other.env_id);
        assert_eq!(msg.priority, other.priority);
        assert_eq!(msg.size, other.size);
        assert_eq!(msg.size_headers, other.size_headers);
    }

    fn assert_instant_eq(instant: Instant, other: Instant) {
        let dur = if instant > other {
            instant - other
        } else {
            other - instant
        }
        .as_secs();
        assert!(dur <= 1, "dur {}", dur);
    }
}
