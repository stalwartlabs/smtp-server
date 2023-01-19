use crate::{
    core::{Core, Session},
    tests::session::VerifyResponse,
};

#[tokio::test]
async fn basic_commands() {
    let mut session = Session::test(Core::test());

    // STARTTLS should be available on clear text connections
    session.stream.tls = false;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("STARTTLS");
    assert!(!session.ingest(b"STARTTLS\r\n").await.unwrap());
    session.response().assert_contains("220 2.0.0");

    // STARTTLS should not be offered on TLS connections
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("STARTTLS");
    session.cmd("STARTTLS", "504 5.7.4").await;

    // Test NOOP
    session.cmd("NOOP", "250").await;

    // Test RSET
    session.cmd("RSET", "250").await;

    // Test HELP
    session.cmd("HELP QUIT", "250").await;

    // Test LHLO on SMTP channel
    session.cmd("LHLO domain.org", "502").await;

    // Test QUIT
    session.ingest(b"QUIT\r\n").await.unwrap_err();
    session.response().assert_code("221");
}
