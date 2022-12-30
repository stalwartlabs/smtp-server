use std::sync::atomic::Ordering;

use tokio::{fs, io::AsyncWriteExt};

use crate::core::QueueCore;

use super::{Event, Message, Schedule};

impl QueueCore {
    pub async fn queue_message(&self, mut message: Box<Message>, message_bytes: Vec<u8>) -> bool {
        // Generate id
        message.id = (message.created.saturating_sub(946684800) & 0xFFFFFFFF)
            | (self.id_seq.fetch_add(1, Ordering::Relaxed) as u64) << 32;

        // Build path
        message.path = self.config.path.eval(message.as_ref()).await.clone();
        let hash = *self.config.hash.eval(message.as_ref()).await;
        if hash > 0 {
            message.path.push((message.id % hash).to_string());
        }
        let _ = fs::create_dir(&message.path).await;
        message
            .path
            .push(format!("{}_{}.msg", message.id, message.size));

        // Save message
        let mut file = match fs::File::create(&message.path).await {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("Failed to create file {}: {}", message.path.display(), err);
                return false;
            }
        };
        for bytes in [&message_bytes] {
            if let Err(err) = file.write_all(bytes).await {
                tracing::error!(
                    "Failed to write to file {}: {}",
                    message.path.display(),
                    err
                );
                return false;
            }
        }
        if let Err(err) = file.flush().await {
            tracing::error!("Failed to flush file {}: {}", message.path.display(), err);
            return false;
        }

        // Queue the message
        if self
            .tx
            .send(Event::Queue(Schedule {
                due: message.next_event().unwrap(),
                inner: message,
            }))
            .await
            .is_err()
        {
            tracing::warn!(
                "Queue channel closed: Message queued but won't be sent until next restart."
            );
        }

        true
    }
}
