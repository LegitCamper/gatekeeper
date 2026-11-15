use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::Duration;

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

const APPLICATION_ID: i64 = 0x474b5052;
const SCHEMA_VERSION: i64 = 3;
const DIGEST_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid persistent storage configuration: {0}")]
    Configuration(&'static str),
    #[error("mapping database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("mapping database contains inconsistent data")]
    Integrity,
    #[error("could not generate database seed")]
    Random,
    #[error("mapping store lock failed")]
    Lock,
    #[error("placeholder collision; request was not forwarded")]
    Collision,
    #[error("mapping worker failed")]
    Worker,
    #[error("mapping database file could not be created")]
    File(#[from] std::io::Error),
}

/// One global digest-to-original table. Placeholders are keyed HMACs of the
/// value, so the same value gets the same placeholder in every request and
/// session, and a placeholder cannot be derived or reversed without the seed.
pub struct MappingStore {
    database: Mutex<Connection>,
    // ponytail: the whole table lives in memory for streaming lookups; move to an
    // LRU over SQLite once it outgrows RAM.
    index: RwLock<BTreeMap<String, String>>,
    tokens: hmac::Key,
    decoys: hmac::Key,
}

fn derive(master: &[u8; 32], domain: &[u8]) -> hmac::Key {
    hmac::Key::new(
        hmac::HMAC_SHA256,
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, master), domain).as_ref(),
    )
}

/// Lowercase 12-hex digest of a `[KIND_xxxxxxxxxxxx]` placeholder.
fn digest_of(token: &str) -> Option<String> {
    let (_, digest) = token.strip_suffix(']')?.rsplit_once('_')?;
    (digest.len() == DIGEST_LEN && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| digest.to_ascii_lowercase())
}

impl MappingStore {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let tables: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )?;
        if application == APPLICATION_ID && version == 1 {
            return Err(StorageError::Configuration(
                "encrypted schema v1 requires explicit migration; existing database left intact",
            ));
        }
        if !((application == 0 && version == 0 && tables == 0)
            || (application == APPLICATION_ID && matches!(version, 2 | SCHEMA_VERSION)))
        {
            return Err(StorageError::Configuration("unsupported database schema"));
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS storage_metadata (
                id INTEGER PRIMARY KEY CHECK(id=1),
                seed BLOB NOT NULL CHECK(typeof(seed)='blob' AND length(seed)=32)
            );
            CREATE TABLE IF NOT EXISTS mappings (
                digest TEXT PRIMARY KEY, original TEXT NOT NULL
            ) WITHOUT ROWID;",
        )?;
        if version == 2 {
            // Conversation-scoped placeholders keep restoring after the move to
            // one global table; only their digest is needed to look them up.
            transaction.execute_batch(
                "INSERT OR IGNORE INTO mappings
                 SELECT lower(substr(b.token, -13, 12)), v.original FROM bindings b
                 JOIN vault_values v ON v.owner=b.owner AND v.fingerprint=b.fingerprint;
                 DROP TABLE bindings; DROP TABLE conversations; DROP TABLE vault_values;",
            )?;
        }
        let seed: Option<Vec<u8>> = transaction
            .query_row("SELECT seed FROM storage_metadata WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let master: [u8; 32] = match seed {
            Some(seed) => seed.try_into().map_err(|_| StorageError::Integrity)?,
            None if version == 0 => {
                let mut seed = [0; 32];
                SystemRandom::new()
                    .fill(&mut seed)
                    .map_err(|_| StorageError::Random)?;
                transaction.execute(
                    "INSERT INTO storage_metadata(id,seed) VALUES(1,?1)",
                    params![seed.as_slice()],
                )?;
                seed
            }
            None => return Err(StorageError::Integrity),
        };
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        let index = connection
            .prepare("SELECT digest, original FROM mappings")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(Self {
            database: Mutex::new(connection),
            index: RwLock::new(index),
            tokens: derive(&master, b"gatekeeper/tokens/v2"),
            decoys: derive(&master, b"gatekeeper/decoys/v1"),
        })
    }

    pub(crate) fn token(&self, kind: &str, original: &str) -> String {
        let mut context = hmac::Context::with_key(&self.tokens);
        for field in [kind.as_bytes(), original.as_bytes()] {
            context.update(&(field.len() as u64).to_be_bytes());
            context.update(field);
        }
        let hex: String = context.sign().as_ref()[..DIGEST_LEN / 2]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("[{kind}_{hex}]")
    }

    /// Commit new mappings before the request that introduced them is forwarded.
    pub(crate) fn save(&self, mappings: &HashMap<String, String>) -> Result<(), StorageError> {
        let mut fresh = Vec::new();
        {
            let index = self.index.read().unwrap_or_else(PoisonError::into_inner);
            for (token, original) in mappings {
                let digest = digest_of(token).ok_or(StorageError::Collision)?;
                match index.get(&digest) {
                    Some(stored) if stored == original => {}
                    Some(_) => return Err(StorageError::Collision),
                    None => fresh.push((digest, original.clone())),
                }
            }
        }
        if fresh.is_empty() {
            return Ok(());
        }
        let mut database = self.database.lock().map_err(|_| StorageError::Lock)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (digest, original) in &fresh {
            let stored: Option<String> = transaction
                .query_row(
                    "SELECT original FROM mappings WHERE digest=?1",
                    [digest],
                    |row| row.get(0),
                )
                .optional()?;
            match stored {
                Some(stored) if stored != *original => return Err(StorageError::Collision),
                Some(_) => {}
                None => {
                    transaction.execute(
                        "INSERT INTO mappings(digest, original) VALUES(?1, ?2)",
                        params![digest, original],
                    )?;
                }
            }
        }
        transaction.commit()?;
        self.index
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(fresh);
        Ok(())
    }

    pub(crate) fn original(&self, digest: &str) -> Option<String> {
        self.index
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&digest.to_ascii_lowercase())
            .cloned()
    }

    /// Does any stored digest start with `prefix`? Lets streams hold a split digest.
    pub(crate) fn has_prefix(&self, prefix: &str) -> bool {
        let prefix = prefix.to_ascii_lowercase();
        self.index
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(digest, _)| digest.starts_with(&prefix))
    }

    /// Stable randomness for an unknown digest. Nothing is stored, so probing
    /// unknown placeholders costs no disk, yet repeats give the same answer.
    pub(crate) fn decoy_seed(&self, digest: &str) -> [u8; 32] {
        hmac::sign(&self.decoys, digest.to_ascii_lowercase().as_bytes())
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 tags are 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "gatekeeper-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            Self(directory)
        }

        fn path(&self) -> PathBuf {
            self.0.join("mappings.sqlite3")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn global_tokens_deduplicate_survive_restart_and_reject_collisions() {
        let fixture = Fixture::new();
        let original = "DurableFixtureValue";
        let token = {
            let store = MappingStore::open(&fixture.path()).unwrap();
            let token = store.token("CUSTOM", original);
            for _ in 0..2 {
                store
                    .save(&HashMap::from([(token.clone(), original.to_owned())]))
                    .unwrap();
            }
            assert!(matches!(
                store.save(&HashMap::from([(token.clone(), "other".to_owned())])),
                Err(StorageError::Collision)
            ));
            token
        };
        let store = MappingStore::open(&fixture.path()).unwrap();
        assert_eq!(store.token("CUSTOM", original), token);
        let digest = digest_of(&token).unwrap();
        assert_eq!(store.original(&digest).as_deref(), Some(original));
        assert!(store.has_prefix(&digest[..5]));
        let rows: i64 = store
            .database
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM mappings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(store.decoy_seed("abc"), store.decoy_seed("ABC"));
        assert_ne!(store.decoy_seed("abc"), store.decoy_seed("abd"));
    }

    #[test]
    fn conversation_schema_migrates_into_global_table() {
        let fixture = Fixture::new();
        {
            let connection = Connection::open(fixture.path()).unwrap();
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection.pragma_update(None, "user_version", 2).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE storage_metadata(id INTEGER PRIMARY KEY, seed BLOB NOT NULL);
                     INSERT INTO storage_metadata VALUES(1, zeroblob(32));
                     CREATE TABLE vault_values(owner TEXT, fingerprint BLOB, original TEXT);
                     CREATE TABLE conversations(owner TEXT, id TEXT);
                     CREATE TABLE bindings(owner TEXT, conversation TEXT, token TEXT, digest TEXT, fingerprint BLOB);
                     INSERT INTO vault_values VALUES('local', X'01', 'OldValue');
                     INSERT INTO bindings VALUES('local', 't', '[CUSTOM_ABCDEF012345]', 'abcdef012345', X'01');",
                )
                .unwrap();
        }
        let store = MappingStore::open(&fixture.path()).unwrap();
        assert_eq!(store.original("abcdef012345").as_deref(), Some("OldValue"));
    }

    #[test]
    fn encrypted_schema_is_rejected_without_changing_existing_bytes() {
        let fixture = Fixture::new();
        {
            let connection = Connection::open(fixture.path()).unwrap();
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection.pragma_update(None, "user_version", 1).unwrap();
            connection
                .execute_batch("CREATE TABLE vault_values(encrypted BLOB NOT NULL);")
                .unwrap();
        }
        let before = std::fs::read(fixture.path()).unwrap();
        assert!(matches!(
            MappingStore::open(&fixture.path()),
            Err(StorageError::Configuration(_))
        ));
        assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
    }

    #[test]
    fn missing_seed_is_not_silently_regenerated() {
        let fixture = Fixture::new();
        MappingStore::open(&fixture.path())
            .unwrap()
            .database
            .lock()
            .unwrap()
            .execute("DELETE FROM storage_metadata", [])
            .unwrap();
        assert!(matches!(
            MappingStore::open(&fixture.path()),
            Err(StorageError::Integrity)
        ));
    }
}
