use tokio::sync::oneshot;

use super::Core;

impl Core {
    pub async fn spawn_worker<U, V>(&self, f: U) -> Option<V>
    where
        U: FnOnce() -> V + Send + 'static,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.spawn(move || {
            tx.send(f()).ok();
        });

        match rx.await {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(
                    context = "worker-pool",
                    event = "error",
                    reason = %err,
                );
                None
            }
        }
    }
}
