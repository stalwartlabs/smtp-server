use std::{path::PathBuf, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::{Core, ServerInstance, Session, SessionData, SessionParameters, State},
    inbound::IsTls,
};

pub struct DummyIo {
    pub tx_buf: Vec<u8>,
    pub rx_buf: Vec<u8>,
    pub tls: bool,
}

impl AsyncRead for DummyIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.rx_buf.is_empty() {
            buf.put_slice(&self.rx_buf);
            self.rx_buf.clear();
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl AsyncWrite for DummyIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.tx_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl IsTls for DummyIo {
    fn is_tls(&self) -> bool {
        self.tls
    }

    fn write_tls_header(&self, _headers: &mut Vec<u8>) {}
}

impl Unpin for DummyIo {}

impl Session<DummyIo> {
    pub fn test(core: impl Into<Arc<Core>>) -> Self {
        Self {
            state: State::default(),
            instance: Arc::new(ServerInstance::test()),
            core: core.into(),
            span: tracing::info_span!("test"),
            stream: DummyIo {
                rx_buf: vec![],
                tx_buf: vec![],
                tls: false,
            },
            data: SessionData::new("127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap()),
            params: SessionParameters::default(),
            in_flight: vec![],
        }
    }

    pub fn response(&mut self) -> Vec<String> {
        if !self.stream.tx_buf.is_empty() {
            let response = std::str::from_utf8(&self.stream.tx_buf)
                .unwrap()
                .split("\r\n")
                .filter_map(|r| {
                    if !r.is_empty() {
                        r.to_string().into()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            self.stream.tx_buf.clear();
            response
        } else {
            panic!("There was no response.");
        }
    }

    pub fn write_rx(&mut self, data: &str) {
        self.stream.rx_buf.extend_from_slice(data.as_bytes());
    }

    pub async fn rset(&mut self) {
        self.ingest(b"RSET\r\n").await.unwrap();
        self.response().assert_code("250");
    }

    pub async fn cmd(&mut self, cmd: &str, expected_code: &str) -> Vec<String> {
        self.ingest(format!("{}\r\n", cmd).as_bytes())
            .await
            .unwrap();
        self.response().assert_code(expected_code)
    }

    pub async fn ehlo(&mut self, host: &str) -> Vec<String> {
        self.ingest(format!("EHLO {}\r\n", host).as_bytes())
            .await
            .unwrap();
        self.response().assert_code("250")
    }

    pub async fn mail_from(&mut self, from: &str, expected_code: &str) {
        self.ingest(
            if !from.starts_with("<") {
                format!("MAIL FROM:<{}>\r\n", from)
            } else {
                format!("MAIL FROM:{}\r\n", from)
            }
            .as_bytes(),
        )
        .await
        .unwrap();
        self.response().assert_code(expected_code);
    }

    pub async fn rcpt_to(&mut self, to: &str, expected_code: &str) {
        self.ingest(
            if !to.starts_with("<") {
                format!("RCPT TO:<{}>\r\n", to)
            } else {
                format!("RCPT TO:{}\r\n", to)
            }
            .as_bytes(),
        )
        .await
        .unwrap();
        self.response().assert_code(expected_code);
    }

    pub async fn data(&mut self, data: &str, expected_code: &str) {
        self.ingest(b"DATA\r\n").await.unwrap();
        self.response().assert_code("354");
        if let Some(file) = data.strip_prefix("test:") {
            self.ingest(load_test_message(file, "messages").as_bytes())
                .await
                .unwrap();
        } else if let Some(file) = data.strip_prefix("report:") {
            self.ingest(load_test_message(file, "reports").as_bytes())
                .await
                .unwrap();
        } else {
            self.ingest(data.as_bytes()).await.unwrap();
        }
        self.ingest(b"\r\n.\r\n").await.unwrap();
        self.response().assert_code(expected_code);
    }

    pub async fn send_message(&mut self, from: &str, to: &[&str], data: &str, expected_code: &str) {
        self.mail_from(from, "250").await;
        for to in to {
            self.rcpt_to(to, "250").await;
        }
        self.data(data, expected_code).await;
    }
}

pub fn load_test_message(file: &str, test: &str) -> String {
    let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("resources");
    test_file.push("tests");
    test_file.push(test);
    test_file.push(format!("{}.eml", file));
    std::fs::read_to_string(test_file).unwrap()
}

pub trait VerifyResponse {
    fn assert_code(self, expected_code: &str) -> Self;
    fn assert_contains(self, expected_text: &str) -> Self;
    fn assert_not_contains(self, expected_text: &str) -> Self;
}

impl VerifyResponse for Vec<String> {
    fn assert_code(self, expected_code: &str) -> Self {
        if self.last().expect("response").starts_with(expected_code) {
            self
        } else {
            panic!("Expected {:?} but got {:?}.", expected_code, self);
        }
    }

    fn assert_contains(self, expected_text: &str) -> Self {
        if self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!("Expected {:?} but got {:?}.", expected_text, self);
        }
    }

    fn assert_not_contains(self, expected_text: &str) -> Self {
        if !self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!("Not expecting {:?} but got it {:?}.", expected_text, self);
        }
    }
}

impl ServerInstance {
    pub fn test() -> Self {
        Self {
            id: "smtp".to_string(),
            listener_id: 1,
            is_smtp: true,
            hostname: "mx.example.org".to_string(),
            greeting: b"220 mx.example.org at your service.\r\n".to_vec(),
        }
    }
}
