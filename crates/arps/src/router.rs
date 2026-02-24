use arp_common::Pubkey;
use dashmap::DashMap;
use std::time::Instant;
use tokio::sync::mpsc;

/// Handle held in the routing table — used to send frames to a connection.
#[derive(Clone, Debug)]
pub struct ConnHandle {
    /// Channel sender for delivering frames to this connection's task.
    pub tx: mpsc::Sender<Vec<u8>>,
    /// Ed25519 public key identifying this connection.
    pub pubkey: Pubkey,
    /// Instant when this connection was admitted (used for eviction guards).
    pub admitted_at: Instant,
}

/// Concurrent pubkey → connection routing table.
#[derive(Debug)]
pub struct Router {
    routes: DashMap<Pubkey, ConnHandle>,
    _max_capacity: usize,
}

impl Router {
    /// Create an empty router with the given maximum capacity.
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            routes: DashMap::new(),
            _max_capacity: max_capacity,
        }
    }

    /// Insert a connection handle, returning any previous handle for the same key.
    #[must_use]
    pub fn insert(&self, pubkey: Pubkey, handle: ConnHandle) -> Option<ConnHandle> {
        self.routes.insert(pubkey, handle)
    }

    /// Remove entry only if it was admitted at the given instant.
    pub fn remove_if(&self, pubkey: &Pubkey, admitted_at: Instant) {
        self.routes
            .remove_if(pubkey, |_k, v| v.admitted_at == admitted_at);
    }

    /// Look up a connection handle by public key.
    #[must_use]
    pub fn get(&self, pubkey: &Pubkey) -> Option<ConnHandle> {
        self.routes.get(pubkey).map(|entry| entry.value().clone())
    }

    /// Number of active routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handle(pubkey: Pubkey) -> (ConnHandle, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(1);
        let handle = ConnHandle {
            tx,
            pubkey,
            admitted_at: Instant::now(),
        };
        (handle, rx)
    }

    fn make_pubkey(id: u8) -> Pubkey {
        let mut key = [0u8; 32];
        key[0] = id;
        key
    }

    #[test]
    fn test_insert_and_get_returns_handle() {
        let router = Router::new(100_000);
        let pubkey = make_pubkey(1);
        let (handle, _rx) = make_handle(pubkey);

        let old = router.insert(pubkey, handle);
        assert!(old.is_none());

        let retrieved = router.get(&pubkey);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.pubkey, pubkey);
    }

    #[test]
    fn test_get_on_missing_key_returns_none() {
        let router = Router::new(100_000);
        let pubkey = make_pubkey(1);

        let result = router.get(&pubkey);
        assert!(result.is_none());
    }

    #[test]
    fn test_insert_same_key_replaces_old_handle() {
        let router = Router::new(100_000);
        let pubkey = make_pubkey(1);
        let (handle1, _rx1) = make_handle(pubkey);
        let (handle2, _rx2) = make_handle(pubkey);

        let old1 = router.insert(pubkey, handle1);
        assert!(old1.is_none());

        let old2 = router.insert(pubkey, handle2);
        assert!(old2.is_some());
    }

    #[test]
    fn test_remove_if_with_matching_admitted_at_removes_entry() {
        let router = Router::new(100_000);
        let pubkey = make_pubkey(1);
        let admitted_at = Instant::now();
        let (tx, _rx) = mpsc::channel(1);
        let handle = ConnHandle {
            tx,
            pubkey,
            admitted_at,
        };

        let _ = router.insert(pubkey, handle);
        assert_eq!(router.len(), 1);

        router.remove_if(&pubkey, admitted_at);
        assert_eq!(router.len(), 0);
        assert!(router.get(&pubkey).is_none());
    }

    #[test]
    fn test_remove_if_with_non_matching_admitted_at_keeps_entry() {
        let router = Router::new(100_000);
        let pubkey = make_pubkey(1);
        let admitted_at1 = Instant::now();
        let (tx, _rx) = mpsc::channel(1);
        let handle = ConnHandle {
            tx,
            pubkey,
            admitted_at: admitted_at1,
        };

        let _ = router.insert(pubkey, handle);
        assert_eq!(router.len(), 1);

        let admitted_at2 = admitted_at1 + std::time::Duration::from_secs(1);
        router.remove_if(&pubkey, admitted_at2);
        assert_eq!(router.len(), 1);
        assert!(router.get(&pubkey).is_some());
    }

    #[test]
    fn test_len_and_is_empty() {
        let router = Router::new(100_000);
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);

        let pubkey1 = make_pubkey(1);
        let (handle1, _rx1) = make_handle(pubkey1);
        let _ = router.insert(pubkey1, handle1);

        assert!(!router.is_empty());
        assert_eq!(router.len(), 1);

        let pubkey2 = make_pubkey(2);
        let (handle2, _rx2) = make_handle(pubkey2);
        let _ = router.insert(pubkey2, handle2);

        assert_eq!(router.len(), 2);
    }

    #[test]
    fn test_default_impl_creates_empty_router() {
        let router: Router = Router::default();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
    }
}
