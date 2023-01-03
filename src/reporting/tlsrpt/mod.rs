pub mod parse;

#[derive(Debug, PartialEq, Eq)]
pub struct TlsRpt {
    rua: Vec<ReportUri>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReportUri {
    Mail(String),
    Http(String),
}
