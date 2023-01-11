use std::sync::Arc;

use tokio::sync::mpsc;

use crate::core::Core;

use super::Event;

impl SpawnReport for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<Core>) {
        tokio::spawn(async move {});
    }
}

pub trait SpawnReport {
    fn spawn(self, core: Arc<Core>);
}
