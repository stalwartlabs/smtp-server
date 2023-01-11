use std::{sync::Arc, time::Duration};

use mail_auth::mta_sts::TlsRpt;

#[derive(Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRpt>,
    pub interval: Duration,
}
