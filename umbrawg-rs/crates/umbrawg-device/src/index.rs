use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rand_core::RngCore;

use crate::keypair::{Keypair, RemovedIndexes};
use crate::peer::Peer;

#[derive(Clone)]
pub struct IndexEntry {
    pub peer: Arc<Peer>,
    pub keypair: Option<Arc<Keypair>>,
}

pub struct IndexTable {
    entries: ArcSwap<HashMap<u32, IndexEntry>>,
    update: Mutex<()>,
}

impl IndexTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: ArcSwap::from_pointee(HashMap::new()),
            update: Mutex::new(()),
        }
    }

    pub fn allocate(&self, rng: &mut impl RngCore, peer: &Arc<Peer>) -> u32 {
        let _guard = self.update.lock();
        let mut entries = (**self.entries.load()).clone();
        let index = loop {
            let candidate = rng.next_u32();
            if candidate != 0 && !entries.contains_key(&candidate) {
                break candidate;
            }
        };
        entries.insert(
            index,
            IndexEntry {
                peer: Arc::clone(peer),
                keypair: None,
            },
        );
        self.entries.store(Arc::new(entries));
        index
    }

    pub fn replace_keypair(
        &self,
        removed: &RemovedIndexes,
        peer: &Arc<Peer>,
        keypair: &Arc<Keypair>,
    ) {
        let _guard = self.update.lock();
        let mut entries = (**self.entries.load()).clone();
        for index in removed.iter() {
            entries.remove(&index);
        }
        entries.insert(
            keypair.local_index(),
            IndexEntry {
                peer: Arc::clone(peer),
                keypair: Some(Arc::clone(keypair)),
            },
        );
        self.entries.store(Arc::new(entries));
    }

    pub fn remove(&self, index: u32) {
        let _guard = self.update.lock();
        let mut entries = (**self.entries.load()).clone();
        entries.remove(&index);
        self.entries.store(Arc::new(entries));
    }

    pub fn remove_many(&self, indexes: &RemovedIndexes) {
        if indexes.is_empty() {
            return;
        }
        let _guard = self.update.lock();
        let mut entries = (**self.entries.load()).clone();
        for index in indexes.iter() {
            entries.remove(&index);
        }
        self.entries.store(Arc::new(entries));
    }

    pub fn clear(&self) {
        let _guard = self.update.lock();
        self.entries.store(Arc::new(HashMap::new()));
    }

    #[must_use]
    pub fn lookup(&self, index: u32) -> Option<IndexEntry> {
        self.entries.load().get(&index).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.load().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IndexTable {
    fn default() -> Self {
        Self::new()
    }
}
