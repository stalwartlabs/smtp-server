use std::sync::Arc;

use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufStream},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::{Config, ConfigContext, Host},
    remote::lookup::{Item, LookupChannel, LookupResult},
};

use super::dummy_tls_acceptor;

const REMOTE: &str = "
[remote.lmtp]
address = 127.0.0.1
port = 9999
protocol = 'lmtp'

[remote.lmtp.auth]
username = 'hello'
secret = 'world'

[remote.lmtp.limits]
errors = 3
requests = 5

[remote.lmtp.cache]
entries = 5
ttl = {positive = '10s', negative = '5s'}

[remote.lmtp.tls]
implicit = true
allow-invalid-certs = true
";

#[tokio::test]
async fn remote_smtp() {
    // Enable logging
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();

    // Spawn mock LMTP server
    let shutdown = spawn_mock_lmtp_server();

    // Spawn lookup client
    let mut ctx = ConfigContext::default();
    let config = Config::parse(REMOTE).unwrap();
    config.parse_remote_hosts(&mut ctx).unwrap();
    let lookup = LookupChannel {
        tx: ctx.hosts.remove("lmtp").unwrap().spawn(&config),
    };

    // Basic lookup
    let tests = vec![
        (
            Item::Exists("john-ok@domain".to_string()),
            LookupResult::True,
        ),
        (
            Item::Exists("john-bad@domain".to_string()),
            LookupResult::False,
        ),
        (
            Item::Verify("john-ok@domain".to_string()),
            LookupResult::Values(Arc::new(vec!["john-ok@domain".to_string()])),
        ),
        (
            Item::Verify("doesnot@exist.org".to_string()),
            LookupResult::False,
        ),
        (
            Item::Expand("sales-ok,item1,item2,item3".to_string()),
            LookupResult::Values(Arc::new(vec![
                "sales-ok".to_string(),
                "item1".to_string(),
                "item2".to_string(),
                "item3".to_string(),
            ])),
        ),
        (Item::Expand("other".to_string()), LookupResult::False),
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".to_string(),
                secret: "ok".to_string(),
            }),
            LookupResult::True,
        ),
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".to_string(),
                secret: "bad".to_string(),
            }),
            LookupResult::False,
        ),
    ];

    for (item, expected) in &tests {
        assert_eq!(&lookup.lookup(item.clone()).await.unwrap(), expected);
    }

    // Concurrent requests
    let mut requests = Vec::new();
    for n in 0..100 {
        let (item, expected) = &tests[n % tests.len()];
        let item = item.clone();
        let lookup = lookup.clone();
        requests.push((
            tokio::spawn(async move { lookup.lookup(item).await }),
            expected.clone(),
        ));
    }
    println!("hi");
    for (result, expected_result) in requests {
        println!("ok");
        let result = result.await.unwrap();
        assert_eq!(result, Some(expected_result));
    }

    // Shutdown
    shutdown.send(false).ok();
}

pub fn spawn_mock_lmtp_server() -> watch::Sender<bool> {
    let (tx, mut rx) = watch::channel(true);

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9999")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock SMTP server to 127.0.0.1:9999: {}", e);
            });
        let acceptor = dummy_tls_acceptor();
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            let acceptor = acceptor.clone();
                            tokio::spawn(accept_smtp(stream, acceptor));
                        }
                        Err(err) => {
                            panic!("Something went wrong: {}", err);
                        }
                    }
                },
                _ = rx.changed() => {
                    break;
                }
            };
        }
    });

    tx
}

async fn accept_smtp(stream: TcpStream, acceptor: Arc<TlsAcceptor>) {
    let mut stream = acceptor.accept(stream).await.unwrap();
    stream
        .write_all(b"220 [127.0.0.1] Clueless host service ready\r\n")
        .await
        .unwrap();

    let mut buf_u8 = vec![0u8; 1024];

    loop {
        let br = if let Ok(br) = stream.read(&mut buf_u8).await {
            br
        } else {
            break;
        };
        let buf = std::str::from_utf8(&buf_u8[0..br]).unwrap();
        print!("-> {}", buf);
        if buf.starts_with("LHLO") {
            stream
                .write_all(b"250-mx.foobar.org\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
        } else if buf.starts_with("MAIL FROM") {
            if buf.contains("<>") || buf.contains("ok@") {
                stream.write_all(b"250 OK\r\n").await.unwrap();
            } else {
                stream
                    .write_all("552-I do not\r\n552 like that MAIL FROM.\r\n".as_bytes())
                    .await
                    .unwrap();
            }
        } else if buf.starts_with("RCPT TO") {
            if buf.contains("ok") {
                stream.write_all(b"250 OK\r\n").await.unwrap();
            } else {
                stream
                    .write_all("550-I refuse to\r\n550 accept that recipient.\r\n".as_bytes())
                    .await
                    .unwrap();
            }
        } else if buf.starts_with("VRFY") {
            if buf.contains("ok") {
                stream
                    .write_all(format!("250 {}\r\n", buf.split_once(' ').unwrap().1).as_bytes())
                    .await
                    .unwrap();
            } else {
                stream
                    .write_all("550-I refuse to\r\n550 accept that recipient.\r\n".as_bytes())
                    .await
                    .unwrap();
            }
        } else if buf.starts_with("EXPN") {
            if buf.contains("ok") {
                let parts = buf
                    .split_once(' ')
                    .unwrap()
                    .1
                    .split(",")
                    .filter_map(|s| {
                        if !s.is_empty() {
                            s.to_string().into()
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let mut buf = Vec::with_capacity(16);
                for (pos, part) in parts.iter().enumerate() {
                    buf.extend_from_slice(b"250");
                    buf.push(if pos == parts.len() - 1 { b' ' } else { b'-' });
                    buf.extend_from_slice(part.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                stream.write_all(&buf).await.unwrap();
            } else {
                stream
                    .write_all("550-I refuse to\r\n550 accept that recipient.\r\n".as_bytes())
                    .await
                    .unwrap();
            }
        } else if buf.starts_with("AUTH PLAIN") {
            let buf = base64_decode(buf.rsplit_once(' ').unwrap().1.as_bytes()).unwrap();
            if String::from_utf8_lossy(&buf).contains("ok") {
                stream
                    .write_all("235 Great success!\r\n".as_bytes())
                    .await
                    .unwrap();
            } else {
                stream
                    .write_all("535 No soup for you\r\n".as_bytes())
                    .await
                    .unwrap();
            }
        } else if buf.starts_with("QUIT") {
            stream
                .write_all("250 Arrivederci!\r\n".as_bytes())
                .await
                .unwrap();
            break;
        } else if buf.starts_with("RSET") {
            stream
                .write_all("250 Your wish is my command.\r\n".as_bytes())
                .await
                .unwrap();
        } else {
            panic!("Unknown command: {}", buf.trim());
        }
        if buf.contains("bye") {
            return;
        }
    }
}
