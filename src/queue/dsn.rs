use crate::core::QueueCore;

use super::Message;

impl QueueCore {
    pub async fn send_dsn(&self, message: &mut Message) {
        todo!()
    }
}
