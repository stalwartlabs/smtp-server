use std::{fs, sync::Arc, time::Duration};

use crate::{
    config::{AddressMatch, IfBlock},
    core::{Core, Session},
    tests::make_temp_dir,
};

#[tokio::test]
async fn report_analyze() {
    let mut core = Core::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_analyze_report_test");
    let report_dir = make_temp_dir("smtp_report_incoming", true);

    let mut config = &mut core.session.config.rcpt;
    config.relay = IfBlock::new(true);
    let mut config = &mut core.session.config.data;
    config.max_messages = IfBlock::new(1024);
    let mut config = &mut core.report.config.analysis;
    config.addresses = vec![
        AddressMatch::StartsWith("reports@".to_string()),
        AddressMatch::EndsWith("@dmarc.foobar.org".to_string()),
        AddressMatch::Equals("feedback@foobar.org".to_string()),
    ];
    config.forward = false;
    config.store = report_dir.temp_dir.clone().into();

    // Create test message
    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    let addresses = [
        "reports@foobar.org",
        "rep@dmarc.foobar.org",
        "feedback@foobar.org",
    ];
    let mut ac = 0;
    let mut total_reports_received = 0;
    for (test, num_tests) in [("arf", 5), ("dmarc", 5), ("tls", 2)] {
        for num_test in 1..=num_tests {
            total_reports_received += 1;
            session
                .send_message(
                    "john@test.org",
                    &[addresses[ac % addresses.len()]],
                    &format!("report:{test}{num_test}"),
                    "250",
                )
                .await;
            qr.assert_empty_queue();
            ac += 1;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut total_reports = 0;
    for entry in fs::read_dir(&report_dir.temp_dir).unwrap() {
        let path = entry.unwrap().path();
        assert_ne!(fs::metadata(&path).unwrap().len(), 0);
        total_reports += 1;
    }
    assert_eq!(total_reports, total_reports_received);

    // Test delivery to non-report addresses
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    qr.read_event().await.unwrap_message();
}
