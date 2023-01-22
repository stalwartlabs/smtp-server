use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    spf::Spf,
};

use crate::{
    config::{Config, ConfigContext, IfBlock, List, VerifyStrategy},
    core::{Core, Session},
    tests::{session::VerifyResponse, ParseTestConfig},
};

const SIGNATURES: &str = "
[signature.rsa]
public-key = '''
-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----'''
domain = 'example.com'
selector = 'rsa'
headers = ['From', 'To', 'Date', 'Subject', 'Message-ID']
algorithm = 'rsa-sha256'
canonicalization = 'simple/relaxed'
expire = '10d'
set-body-length = true
report = true

[signature.ed]
public-key = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
private-key = 'nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A='
domain = 'example.com'
selector = 'ed'
headers = ['From', 'To', 'Date', 'Subject', 'Message-ID']
algorithm = 'ed25519-sha256'
canonicalization = 'relaxed/simple'
set-body-length = false
";

#[tokio::test]
async fn sign_and_seal() {
    let mut core = Core::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_sign_test");

    // Add SPF, DKIM and DMARC records
    core.resolvers.dns.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "ed._domainkey.scamorza.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; k=ed25519; ",
                "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "rsa._domainkey.manchego.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    let mut config = &mut core.session.config.rcpt;
    config.lookup_domains = IfBlock::new(Some(Arc::new(List::Local(AHashSet::from_iter([
        "example.com".to_string(),
    ])))));
    config.lookup_addresses = IfBlock::new(Some(Arc::new(List::Local(AHashSet::from_iter([
        "jdoe@example.com".to_string(),
    ])))));

    let mut config = &mut core.session.config;
    config.data.add_auth_results = IfBlock::new(true);
    config.data.add_date = IfBlock::new(true);
    config.data.add_message_id = IfBlock::new(true);
    config.data.add_received = IfBlock::new(true);
    config.data.add_return_path = IfBlock::new(true);
    config.data.add_received_spf = IfBlock::new(true);

    let mut config = &mut core.mail_auth;
    let ctx = ConfigContext::default().parse_signatures();
    config.spf.verify_ehlo = IfBlock::new(VerifyStrategy::Relaxed);
    config.spf.verify_mail_from = config.spf.verify_ehlo.clone();
    config.dkim.verify = config.spf.verify_ehlo.clone();
    config.arc.verify = config.spf.verify_ehlo.clone();
    config.dmarc.verify = config.spf.verify_ehlo.clone();
    config.dkim.sign = "['rsa']"
        .parse_if::<Vec<String>>(&ctx)
        .map_if_block(&ctx.signers, "", "")
        .unwrap();
    config.arc.seal = "'ed'"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.sealers, "", "")
        .unwrap();

    // Test DKIM signing
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session
        .send_message(
            "bill@foobar.org",
            &["jdoe@example.com"],
            "test:no_dkim",
            "250",
        )
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains(
            "DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com; c=simple/relaxed;",
        );

    // Test ARC verify and seal
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:arc", "250")
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("ARC-Seal: i=3; a=ed25519-sha256; s=ed; d=example.com; cv=pass;")
        .assert_contains(
            "ARC-Message-Signature: i=3; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );
}

impl ConfigContext {
    pub fn parse_signatures(mut self) -> Self {
        Config::parse(SIGNATURES)
            .unwrap()
            .parse_signatures(&mut self)
            .unwrap();
        self
    }
}
