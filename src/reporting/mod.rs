use std::sync::Arc;

use mail_auth::common::headers::HeaderWriter;

use crate::{
    config::{DkimSigner, IfBlock, Report},
    queue::Message,
};

pub mod spf;

pub fn sign_local_message(
    message: Vec<u8>,
    signers: &Vec<Arc<DkimSigner>>,
) -> (usize, Vec<Vec<u8>>) {
    if !signers.is_empty() {
        let mut headers = Vec::with_capacity(64);
        for signer in signers.iter() {
            match signer.sign(&message) {
                Ok(signature) => {
                    signature.write_header(&mut headers);
                }
                Err(err) => {}
            }
        }
        if !headers.is_empty() {
            (headers.len() + message.len(), vec![headers, message])
        } else {
            (message.len(), vec![message])
        }
    } else {
        (message.len(), vec![message])
    }
}

impl Message {
    pub async fn sign(
        &mut self,
        config: &IfBlock<Vec<Arc<DkimSigner>>>,
        bytes: Vec<u8>,
    ) -> Vec<Vec<u8>> {
        self.size = bytes.len();
        self.size_headers = bytes.len();

        let signers = config.eval(self).await;
        if !signers.is_empty() {
            let mut headers = Vec::with_capacity(64);
            for signer in signers.iter() {
                match signer.sign(&bytes) {
                    Ok(signature) => {
                        signature.write_header(&mut headers);
                    }
                    Err(err) => {}
                }
            }
            if !headers.is_empty() {
                self.size += headers.len();
                self.size_headers += headers.len();

                return vec![headers, bytes];
            }
        }
        vec![bytes]
    }
}
