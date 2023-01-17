use crate::{
    core::{Core, Session},
    tests::session::VerifyResponse,
};

#[tokio::test]
async fn basic_commands() {
    let mut session = Session::test(Core::test());

    // Test NOOP
    session.ingest(b"NOOP\r\n").await.unwrap();
    session.response().assert_code("250");

    // Test RSET
    session.ingest(b"RSET\r\n").await.unwrap();
    session.response().assert_code("250");

    // Test HELP
    session.ingest(b"HELP QUIT\r\n").await.unwrap();
    session.response().assert_code("250");

    // Test LHLO on SMTP channel
    session.ingest(b"LHLO domain.org\r\n").await.unwrap();
    session.response().assert_code("502");

    // Test QUIT
    session.ingest(b"QUIT\r\n").await.unwrap_err();
    session.response().assert_code("221");
}
