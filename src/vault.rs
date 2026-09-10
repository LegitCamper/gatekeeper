//! Bounded in-memory storage for session-scoped PII mappings.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    pub ttl: Duration,
    pub max_sessions: usize,
    pub max_entries_per_session: usize,
}

struct Session {
    mappings: HashMap<String, String>,
    /// Insertion order of tokens, oldest first, used to evict over-cap entries.
    order: Vec<String>,
    stored_at: Instant,
}

impl Session {
    fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        now.duration_since(self.stored_at) > ttl
    }
}

/// Process-local session store with a TTL and hard memory bounds.
///
/// Reads go straight to the concurrent map. Writes take `maintenance` so that
/// expiry sweeps and eviction observe a consistent session count and cannot
/// race past `max_sessions`.
pub struct MemoryVault {
    sessions: DashMap<String, Session>,
    config: VaultConfig,
    maintenance: Mutex<()>,
}

impl MemoryVault {
    pub fn new(config: VaultConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
            maintenance: Mutex::new(()),
        }
    }

    /// Merge `mappings` into `session`, refreshing its TTL.
    ///
    /// Mappings from this call are kept in preference to older ones when the
    /// per-session cap is hit, so the request currently in flight can always be
    /// restored.
    pub fn store(&self, session: &str, mappings: HashMap<String, String>) {
        if mappings.is_empty()
            || self.config.max_sessions == 0
            || self.config.max_entries_per_session == 0
        {
            return;
        }

        let _guard = self.maintenance.lock().unwrap_or_else(|error| {
            self.maintenance.clear_poison();
            error.into_inner()
        });
        let now = Instant::now();
        self.sessions
            .retain(|_, entry| !entry.is_expired(self.config.ttl, now));

        let known = self.sessions.contains_key(session);
        if !known {
            while self.sessions.len() >= self.config.max_sessions {
                let Some(oldest) = self.oldest_session() else {
                    break;
                };
                self.sessions.remove(&oldest);
            }
        }

        let mut entry = self.sessions.entry(session.to_owned()).or_insert(Session {
            mappings: HashMap::new(),
            order: Vec::new(),
            stored_at: now,
        });
        entry.stored_at = now;

        for (token, value) in mappings {
            if entry.mappings.insert(token.clone(), value).is_none() {
                entry.order.push(token);
            }
        }

        while entry.order.len() > self.config.max_entries_per_session {
            let evicted = entry.order.remove(0);
            entry.mappings.remove(&evicted);
        }
    }

    /// Mappings for `session`, or an empty map when it is absent or expired.
    pub fn lookup(&self, session: &str) -> HashMap<String, String> {
        let now = Instant::now();
        self.sessions
            .get(session)
            .filter(|entry| !entry.is_expired(self.config.ttl, now))
            .map(|entry| entry.mappings.clone())
            .unwrap_or_default()
    }

    fn oldest_session(&self) -> Option<String> {
        self.sessions
            .iter()
            .min_by_key(|entry| entry.stored_at)
            .map(|entry| entry.key().clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn config(ttl: Duration, max_sessions: usize, max_entries: usize) -> VaultConfig {
        VaultConfig {
            ttl,
            max_sessions,
            max_entries_per_session: max_entries,
        }
    }

    fn mappings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(token, value)| ((*token).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn stores_and_merges_session_mappings() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 10, 10));
        vault.store("s1", mappings(&[("[A_1]", "alice")]));
        vault.store("s1", mappings(&[("[B_2]", "bob")]));

        let found = vault.lookup("s1");
        assert_eq!(found.len(), 2);
        assert_eq!(found["[A_1]"], "alice");
        assert_eq!(found["[B_2]"], "bob");
        assert!(vault.lookup("missing").is_empty());
    }

    #[test]
    fn expired_sessions_are_not_returned() {
        let vault = MemoryVault::new(config(Duration::ZERO, 10, 10));
        vault.store("s1", mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(5));

        assert!(vault.lookup("s1").is_empty());
    }

    #[test]
    fn storing_refreshes_the_ttl() {
        let vault = MemoryVault::new(config(Duration::from_millis(60), 10, 10));
        vault.store("s1", mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(40));
        vault.store("s1", mappings(&[("[B_2]", "bob")]));
        thread::sleep(Duration::from_millis(40));

        assert_eq!(vault.lookup("s1").len(), 2);
    }

    #[test]
    fn evicts_the_oldest_session_at_capacity() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 2, 10));
        vault.store("s1", mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(5));
        vault.store("s2", mappings(&[("[B_2]", "bob")]));
        thread::sleep(Duration::from_millis(5));
        vault.store("s3", mappings(&[("[C_3]", "carol")]));

        assert!(vault.lookup("s1").is_empty());
        assert_eq!(vault.lookup("s2").len(), 1);
        assert_eq!(vault.lookup("s3").len(), 1);
    }

    #[test]
    fn evicts_oldest_entries_over_the_session_cap() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 10, 2));
        vault.store("s1", mappings(&[("[A_1]", "alice")]));
        vault.store("s1", mappings(&[("[B_2]", "bob")]));
        vault.store("s1", mappings(&[("[C_3]", "carol")]));

        let found = vault.lookup("s1");
        assert_eq!(found.len(), 2);
        assert!(!found.contains_key("[A_1]"));
        assert!(found.contains_key("[C_3]"));
    }

    #[test]
    fn zero_limits_disable_storage() {
        let no_sessions = MemoryVault::new(config(Duration::from_secs(60), 0, 10));
        no_sessions.store("s1", mappings(&[("[A_1]", "alice")]));
        assert!(no_sessions.lookup("s1").is_empty());

        let no_entries = MemoryVault::new(config(Duration::from_secs(60), 10, 0));
        no_entries.store("s1", mappings(&[("[A_1]", "alice")]));
        assert!(no_entries.lookup("s1").is_empty());
    }

    #[test]
    fn concurrent_stores_respect_the_session_bound() {
        let vault = Arc::new(MemoryVault::new(config(Duration::from_secs(60), 4, 10)));
        let workers: Vec<_> = (0..16)
            .map(|index| {
                let vault = Arc::clone(&vault);
                thread::spawn(move || {
                    let session = format!("s{index}");
                    vault.store(&session, mappings(&[("[A_1]", "alice")]));
                    vault.lookup(&session);
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker thread panicked");
        }

        assert!(vault.sessions.len() <= 4);
    }
}
