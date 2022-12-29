use std::{path::PathBuf, sync::atomic::Ordering, time::Instant};

use tokio::{fs, io::AsyncWriteExt};

use crate::core::QueueCore;

use super::{Event, Message, Schedule};

impl QueueCore {
    pub async fn queue_message(&self, mut message: Box<Message>, message_bytes: Vec<u8>) -> bool {
        // Generate id
        message.id = message.created.saturating_sub(946684800) << 32
            | self.id_seq.fetch_add(1, Ordering::Relaxed) as u64;

        // Build path
        let mut path = self.build_base_path(message.id);
        let _ = fs::create_dir(&path).await;

        // Save message
        path.push(format!("{}_{}.msg", message.id, message.size));
        let mut file = match fs::File::create(&path).await {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("Failed to create file {}: {}", path.display(), err);
                return false;
            }
        };
        for bytes in [&message_bytes] {
            if let Err(err) = file.write_all(bytes).await {
                tracing::error!("Failed to write to file {}: {}", path.display(), err);
                return false;
            }
        }
        if let Err(err) = file.flush().await {
            tracing::error!("Failed to flush file {}: {}", path.display(), err);
            return false;
        }

        // Queue the message
        if self
            .tx
            .send(Event::Queue(Schedule {
                due: Instant::now(),
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

    pub fn build_base_path(&self, id: u64) -> PathBuf {
        let mut path = self.config.path.clone();
        path.push((id & self.config.hash).to_string());
        path
    }
}
