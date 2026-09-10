//! Bounded in-memory storage for token-to-PII mappings.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    pub ttl: Duration,
    pub max_entries: usize,
}

struct Entry {
    value: String,
    seen_at: Instant,
}

/// Process-local global token store with a TTL and hard memory bound.
///
/// Reads refresh all mappings so active traffic keeps the vault alive. Writes
/// take `maintenance` so expiry and capacity eviction stay consistent.
pub struct MemoryVault {
    mappings: DashMap<String, Entry>,
    config: VaultConfig,
    maintenance: Mutex<()>,
}

impl MemoryVault {
    pub fn new(config: VaultConfig) -> Self {
        Self {
            mappings: DashMap::new(),
            config,
            maintenance: Mutex::new(()),
        }
    }

    /// Merge mappings into the global store, refreshing their TTL.
    pub fn store(&self, mappings: HashMap<String, String>) {
        if mappings.is_empty() || self.config.max_entries == 0 {
            return;
        }

        let _guard = self.maintenance.lock().unwrap_or_else(|error| {
            self.maintenance.clear_poison();
            error.into_inner()
        });
        let now = Instant::now();
        self.mappings
            .retain(|_, entry| !is_expired(entry.seen_at, self.config.ttl, now));

        for (token, value) in mappings {
            self.mappings.insert(
                token,
                Entry {
                    value,
                    seen_at: now,
                },
            );
        }

        while self.mappings.len() > self.config.max_entries {
            let Some(oldest) = self.oldest_mapping() else {
                break;
            };
            self.mappings.remove(&oldest);
        }
    }

    /// Return all live mappings and refresh their TTL.
    pub fn lookup(&self) -> HashMap<String, String> {
        let now = Instant::now();
        let _guard = self.maintenance.lock().unwrap_or_else(|error| {
            self.maintenance.clear_poison();
            error.into_inner()
        });
        self.mappings
            .retain(|_, entry| !is_expired(entry.seen_at, self.config.ttl, now));
        self.mappings
            .iter_mut()
            .map(|mut entry| {
                entry.seen_at = now;
                (entry.key().clone(), entry.value().value.clone())
            })
            .collect()
    }

    fn oldest_mapping(&self) -> Option<String> {
        self.mappings
            .iter()
            .min_by_key(|entry| entry.value().seen_at)
            .map(|entry| entry.key().clone())
    }
}

fn is_expired(seen_at: Instant, ttl: Duration, now: Instant) -> bool {
    now.duration_since(seen_at) > ttl
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn config(ttl: Duration, max_entries: usize) -> VaultConfig {
        VaultConfig { ttl, max_entries }
    }

    fn mappings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(token, value)| ((*token).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn stores_and_merges_global_mappings() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 10));
        vault.store(mappings(&[("[A_1]", "alice")]));
        vault.store(mappings(&[("[B_2]", "bob")]));

        let found = vault.lookup();
        assert_eq!(found.len(), 2);
        assert_eq!(found["[A_1]"], "alice");
        assert_eq!(found["[B_2]"], "bob");
    }

    #[test]
    fn expired_mappings_are_not_returned() {
        let vault = MemoryVault::new(config(Duration::ZERO, 10));
        vault.store(mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(5));

        assert!(vault.lookup().is_empty());
    }

    #[test]
    fn lookup_refreshes_mapping_ttl() {
        let vault = MemoryVault::new(config(Duration::from_millis(60), 10));
        vault.store(mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(40));
        assert_eq!(vault.lookup()["[A_1]"], "alice");
        thread::sleep(Duration::from_millis(40));

        assert_eq!(vault.lookup()["[A_1]"], "alice");
    }

    #[test]
    fn evicts_oldest_mapping_at_capacity() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 2));
        vault.store(mappings(&[("[A_1]", "alice")]));
        thread::sleep(Duration::from_millis(5));
        vault.store(mappings(&[("[B_2]", "bob")]));
        thread::sleep(Duration::from_millis(5));
        vault.store(mappings(&[("[C_3]", "carol")]));

        let found = vault.lookup();
        assert!(!found.contains_key("[A_1]"));
        assert!(found.contains_key("[B_2]"));
        assert!(found.contains_key("[C_3]"));
    }

    #[test]
    fn zero_limit_disables_storage() {
        let vault = MemoryVault::new(config(Duration::from_secs(60), 0));
        vault.store(mappings(&[("[A_1]", "alice")]));
        assert!(vault.lookup().is_empty());
    }

    #[test]
    fn concurrent_stores_respect_entry_bound() {
        let vault = Arc::new(MemoryVault::new(config(Duration::from_secs(60), 4)));
        let workers: Vec<_> = (0..16)
            .map(|index| {
                let vault = Arc::clone(&vault);
                thread::spawn(move || {
                    let token = format!("[A_{index}]");
                    vault.store(mappings(&[(&token, "alice")]));
                    vault.lookup();
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker thread panicked");
        }

        assert!(vault.mappings.len() <= 4);
    }
}
