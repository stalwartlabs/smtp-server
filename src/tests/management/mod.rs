use std::time::Duration;

use hyper::header::AUTHORIZATION;
use serde::{de::DeserializeOwned, Deserialize};

pub mod queue;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    Data { data: T },
    Error { error: String, details: String },
}

pub async fn send_manage_request<T: DeserializeOwned>(query: &str) -> Result<Response<T>, String> {
    send_manage_request_raw(query).await.map(|result| {
        serde_json::from_str::<Response<T>>(&result).unwrap_or_else(|err| panic!("{err}: {result}"))
    })
}

pub async fn send_manage_request_raw(query: &str) -> Result<String, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:9980{query}"))
        .header(AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
        .send()
        .await
        .map_err(|err| err.to_string())?
        .bytes()
        .await
        .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
        .map_err(|err| err.to_string())
}

impl<T> Response<T> {
    pub fn unwrap_data(self) -> T {
        match self {
            Response::Data { data } => data,
            Response::Error { error, details } => {
                panic!("Expected data, found error {error:?}: {details:?}")
            }
        }
    }

    pub fn unwrap_error(self) -> (String, String) {
        match self {
            Response::Error { error, details } => (error, details),
            Response::Data { .. } => panic!("Expected error, found data."),
        }
    }
}
