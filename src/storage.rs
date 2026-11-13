use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

const APPLICATION_ID: i64 = 0x474b5052;
const CACHE_BYTES: usize = 1024 * 1024;
const MAX_BINDINGS: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid persistent storage configuration: {0}")]
    Configuration(&'static str),
    #[error("mapping database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("mapping database contains inconsistent data")]
    Integrity,
    #[error("could not generate database identifier seed")]
    Random,
    #[error("mapping store lock failed")]
    Lock,
    #[error("conversation mapping limit exceeded")]
    Limit,
    #[error("placeholder collision; request was not forwarded")]
    Collision,
    #[error("mapping worker failed")]
    Worker,
    #[error("mapping database file could not be created")]
    File(#[from] std::io::Error),
}

struct CachedValue {
    original: String,
    used: u64,
}

struct Database {
    connection: Connection,
    cache: HashMap<Vec<u8>, CachedValue>,
    cache_bytes: usize,
    clock: u64,
}

pub struct MappingStore {
    database: Mutex<Database>,
    fingerprints: hmac::Key,
    tokens: hmac::Key,
    authentication: hmac::Key,
    client_tag: hmac::Tag,
    owner: String,
    snapshot_limit: usize,
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn valid_scope(value: &str) -> bool {
    valid_id(value)
        || value
            .split_once('~')
            .is_some_and(|(conversation, lane)| valid_id(conversation) && valid_id(lane))
}

fn sign(key: &hmac::Key, fields: &[&[u8]]) -> hmac::Tag {
    let mut context = hmac::Context::with_key(key);
    for field in fields {
        context.update(&(field.len() as u64).to_be_bytes());
        context.update(field);
    }
    context.sign()
}

fn derive(master: &[u8; 32], domain: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, master), domain)
}

impl MappingStore {
    pub fn open(
        path: &Path,
        owner: &str,
        client_token: &str,
        snapshot_limit: usize,
    ) -> Result<Self, StorageError> {
        if !valid_id(owner)
            || client_token.len() < 32
            || !client_token.bytes().all(|byte| byte.is_ascii_graphic())
            || snapshot_limit == 0
        {
            return Err(StorageError::Configuration(
                "owner, client token, or mapping limit",
            ));
        }
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
            || (application == APPLICATION_ID && version == 2))
        {
            return Err(StorageError::Configuration("unsupported database schema"));
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS storage_metadata (
                id INTEGER PRIMARY KEY CHECK(id=1),
                seed BLOB NOT NULL CHECK(typeof(seed)='blob' AND length(seed)=32)
            );
            CREATE TABLE IF NOT EXISTS vault_values (
                owner TEXT NOT NULL, fingerprint BLOB NOT NULL, original TEXT NOT NULL,
                PRIMARY KEY(owner, fingerprint)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS conversations (
                owner TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(owner, id)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS bindings (
                owner TEXT NOT NULL, conversation TEXT NOT NULL, token TEXT NOT NULL,
                digest TEXT NOT NULL, fingerprint BLOB NOT NULL,
                PRIMARY KEY(owner, conversation, token), UNIQUE(owner, conversation, digest),
                FOREIGN KEY(owner, conversation) REFERENCES conversations(owner, id) ON DELETE CASCADE,
                FOREIGN KEY(owner, fingerprint) REFERENCES vault_values(owner, fingerprint)
            ) WITHOUT ROWID;"
        )?;
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
        transaction.pragma_update(None, "user_version", 2)?;
        transaction.commit()?;
        let authentication = hmac::Key::new(
            hmac::HMAC_SHA256,
            derive(&master, b"gatekeeper/auth/v1").as_ref(),
        );
        let client_tag = hmac::sign(&authentication, client_token.as_bytes());
        Ok(Self {
            database: Mutex::new(Database {
                connection,
                cache: HashMap::new(),
                cache_bytes: 0,
                clock: 0,
            }),
            fingerprints: hmac::Key::new(
                hmac::HMAC_SHA256,
                derive(&master, b"gatekeeper/fingerprints/v1").as_ref(),
            ),
            tokens: hmac::Key::new(
                hmac::HMAC_SHA256,
                derive(&master, b"gatekeeper/tokens/v1").as_ref(),
            ),
            authentication,
            client_tag,
            owner: owner.to_owned(),
            snapshot_limit,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Database>, StorageError> {
        self.database.lock().map_err(|_| StorageError::Lock)
    }

    pub(crate) fn authenticate(&self, token: &[u8]) -> bool {
        hmac::verify(&self.authentication, token, self.client_tag.as_ref()).is_ok()
    }

    pub(crate) fn token(&self, conversation: &str, kind: &str, original: &str) -> String {
        let digest = sign(
            &self.tokens,
            &[
                self.owner.as_bytes(),
                conversation.as_bytes(),
                kind.as_bytes(),
                original.as_bytes(),
            ],
        );
        let hex: String = digest.as_ref()[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("[{kind}_{hex}]")
    }

    pub(crate) fn lane(conversation: &str, lane: &str) -> String {
        if lane.is_empty() {
            return conversation.to_owned();
        }
        format!("{conversation}~{lane}")
    }

    fn fingerprint(&self, original: &str) -> Vec<u8> {
        sign(
            &self.fingerprints,
            &[self.owner.as_bytes(), original.as_bytes()],
        )
        .as_ref()
        .to_vec()
    }

    // ponytail: bounded snapshots reuse the streaming restorer; use scoped lazy lookup beyond these limits.
    pub(crate) fn load(&self, conversation: &str) -> Result<HashMap<String, String>, StorageError> {
        if !valid_scope(conversation) {
            return Err(StorageError::Configuration("conversation ID"));
        }
        let mut database = self.lock()?;
        let rows = {
            let mut statement = database.connection.prepare(
                "SELECT b.token, v.fingerprint, length(CAST(v.original AS BLOB)) FROM bindings b
                 JOIN vault_values v ON v.owner=b.owner AND v.fingerprint=b.fingerprint
                 WHERE b.owner=?1 AND b.conversation=?2 LIMIT ?3",
            )?;
            let mut rows =
                statement.query(params![self.owner, conversation, (MAX_BINDINGS + 1) as i64])?;
            let mut records = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = rows.next()? {
                let token: String = row.get(0)?;
                let fingerprint: Vec<u8> = row.get(1)?;
                let size =
                    usize::try_from(row.get::<_, i64>(2)?).map_err(|_| StorageError::Integrity)?;
                bytes = bytes
                    .saturating_add(token.len())
                    .saturating_add(size)
                    .saturating_add(128);
                if records.len() >= MAX_BINDINGS || bytes > self.snapshot_limit {
                    return Err(StorageError::Limit);
                }
                records.push((token, fingerprint));
            }
            records
        };
        let mut mappings = HashMap::new();
        for (token, fingerprint) in rows {
            database.clock = database.clock.wrapping_add(1);
            let used = database.clock;
            let original = if let Some(cached) = database.cache.get_mut(&fingerprint) {
                cached.used = used;
                cached.original.clone()
            } else {
                let original: String = database.connection.query_row(
                    "SELECT original FROM vault_values WHERE owner=?1 AND fingerprint=?2",
                    params![self.owner, fingerprint],
                    |row| row.get(0),
                )?;
                let size = original.len() + fingerprint.len() + 128;
                if size <= CACHE_BYTES {
                    while database.cache_bytes + size > CACHE_BYTES {
                        let oldest = database
                            .cache
                            .iter()
                            .min_by_key(|(_, value)| value.used)
                            .map(|(key, _)| key.clone());
                        let Some(oldest) = oldest else {
                            break;
                        };
                        if let Some(removed) = database.cache.remove(&oldest) {
                            database.cache_bytes -= removed.original.len() + oldest.len() + 128;
                        }
                    }
                    database.cache_bytes += size;
                    database.cache.insert(
                        fingerprint.clone(),
                        CachedValue {
                            original: original.clone(),
                            used,
                        },
                    );
                }
                original
            };
            let kind = token
                .strip_prefix('[')
                .and_then(|token| token.rsplit_once('_'))
                .map(|(kind, _)| kind)
                .ok_or(StorageError::Integrity)?;
            if self.token(conversation, kind, &original) != token
                || self.fingerprint(&original) != fingerprint
            {
                return Err(StorageError::Integrity);
            }
            mappings.insert(token, original);
        }
        Ok(mappings)
    }

    pub(crate) fn save(
        &self,
        conversation: &str,
        mappings: &HashMap<String, String>,
    ) -> Result<(), StorageError> {
        if !valid_scope(conversation) {
            return Err(StorageError::Configuration("conversation ID"));
        }
        let mut database = self.lock()?;
        let transaction = database
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO conversations(owner,id) VALUES(?1,?2)",
            params![self.owner, conversation],
        )?;
        for (token, original) in mappings {
            let digest = token
                .strip_suffix(']')
                .and_then(|token| token.rsplit_once('_'))
                .map(|(_, digest)| digest)
                .filter(|digest| {
                    digest.len() == 12 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .ok_or(StorageError::Collision)?;
            let fingerprint = self.fingerprint(original);
            let existing: Option<(String, Vec<u8>)> = transaction.query_row(
                "SELECT token,fingerprint FROM bindings WHERE owner=?1 AND conversation=?2 AND digest=?3",
                params![self.owner, conversation, digest], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            if let Some((existing_token, existing_fingerprint)) = existing {
                if existing_token != *token || existing_fingerprint != fingerprint {
                    return Err(StorageError::Collision);
                }
                continue;
            }
            let stored: Option<String> = transaction
                .query_row(
                    "SELECT original FROM vault_values WHERE owner=?1 AND fingerprint=?2",
                    params![self.owner, fingerprint],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(stored) = stored {
                if stored != *original {
                    return Err(StorageError::Collision);
                }
            } else {
                transaction.execute(
                    "INSERT INTO vault_values(owner,fingerprint,original) VALUES(?1,?2,?3)",
                    params![self.owner, fingerprint, original],
                )?;
            }
            transaction.execute(
                "INSERT INTO bindings(owner,conversation,token,digest,fingerprint) VALUES(?1,?2,?3,?4,?5)",
                params![self.owner, conversation, token, digest, fingerprint],
            )?;
        }
        let (count, size): (i64, i64) = transaction.query_row(
            "SELECT count(*), coalesce(sum(length(b.token)+length(CAST(v.original AS BLOB))+128),0)
             FROM bindings b JOIN vault_values v ON b.owner=v.owner AND b.fingerprint=v.fingerprint
             WHERE b.owner=?1 AND b.conversation=?2",
            params![self.owner, conversation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if usize::try_from(count).map_err(|_| StorageError::Limit)? > MAX_BINDINGS
            || usize::try_from(size).map_err(|_| StorageError::Limit)? > self.snapshot_limit
        {
            return Err(StorageError::Limit);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn delete(&self, conversation: &str) -> Result<(), StorageError> {
        let mut database = self.lock()?;
        let transaction = database
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM conversations WHERE owner=?1 AND (id=?2 OR substr(id,1,length(?2)+1)=?2||'~')", params![self.owner, conversation])?;
        transaction.execute(
            "DELETE FROM vault_values WHERE owner=?1 AND NOT EXISTS (
                SELECT 1 FROM bindings WHERE bindings.owner=vault_values.owner AND bindings.fingerprint=vault_values.fingerprint
            )", [&self.owner],
        )?;
        transaction.commit()?;
        database.cache.clear();
        database.cache_bytes = 0;
        Ok(())
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

        fn open(&self, owner: &str, limit: usize) -> MappingStore {
            MappingStore::open(
                &self.0.join("mappings.sqlite3"),
                owner,
                &"test".repeat(16),
                limit,
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn counts(store: &MappingStore) -> (i64, i64) {
        store
            .lock()
            .unwrap()
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM vault_values), (SELECT count(*) FROM bindings)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn deduplicates_values_but_not_conversation_authority() {
        let fixture = Fixture::new();
        let store = fixture.open("owner", 1_000_000);
        let original = "RepeatedFixtureValue";
        let first = store.token("first", "CUSTOM", original);
        let second = store.token("second", "CUSTOM", original);
        assert_ne!(first, second);
        for _ in 0..2 {
            store
                .save(
                    "first",
                    &HashMap::from([(first.clone(), original.to_owned())]),
                )
                .unwrap();
            store
                .save(
                    "second",
                    &HashMap::from([(second.clone(), original.to_owned())]),
                )
                .unwrap();
        }
        assert_eq!(counts(&store), (1, 2));
        assert!(!store.load("first").unwrap().contains_key(&second));
        assert!(store.load("empty").unwrap().is_empty());
        store.delete("first").unwrap();
        assert_eq!(counts(&store), (1, 1));
        assert_eq!(store.load("second").unwrap()[&second], original);
        store.delete("second").unwrap();
        assert_eq!(counts(&store), (0, 0));
    }

    #[test]
    fn restart_recovers_values_and_stable_tokens() {
        let fixture = Fixture::new();
        let original = "DurableFixtureValue";
        let token = {
            let store = fixture.open("owner", 1_000_000);
            let token = store.token("thread", "CUSTOM", original);
            store
                .save(
                    "thread",
                    &HashMap::from([(token.clone(), original.to_owned())]),
                )
                .unwrap();
            token
        };
        let store = fixture.open("owner", 1_000_000);
        assert_eq!(store.token("thread", "CUSTOM", original), token);
        assert_eq!(store.load("thread").unwrap()[&token], original);
        let database = store.lock().unwrap();
        let wal: String = database
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let sync: i64 = database
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!((wal.as_str(), sync), ("wal", 2));
    }

    #[test]
    fn originals_are_plaintext_and_client_token_rotation_preserves_mappings() {
        let fixture = Fixture::new();
        let original = "UniquePlaintextStoredOnDisk";
        let token = {
            let store = fixture.open("owner", 1_000_000);
            let token = store.token("thread", "CUSTOM", original);
            store
                .save(
                    "thread",
                    &HashMap::from([(token.clone(), original.to_owned())]),
                )
                .unwrap();
            let stored: String = store
                .lock()
                .unwrap()
                .connection
                .query_row("SELECT original FROM vault_values", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, original);
            token
        };
        let disk = std::fs::read(fixture.0.join("mappings.sqlite3")).unwrap();
        assert!(
            disk.windows(original.len())
                .any(|bytes| bytes == original.as_bytes())
        );
        let store = MappingStore::open(
            &fixture.0.join("mappings.sqlite3"),
            "owner",
            &"rotated".repeat(16),
            1_000_000,
        )
        .unwrap();
        assert_eq!(store.load("thread").unwrap()[&token], original);
        assert_eq!(store.token("thread", "CUSTOM", original), token);
        assert!(store.authenticate("rotated".repeat(16).as_bytes()));
        assert!(!store.authenticate("test".repeat(16).as_bytes()));
    }

    #[test]
    fn encrypted_schema_is_rejected_without_changing_existing_bytes() {
        let fixture = Fixture::new();
        let path = fixture.0.join("mappings.sqlite3");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection.pragma_update(None, "user_version", 1).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE vault_values(encrypted BLOB NOT NULL);
                 INSERT INTO vault_values VALUES(X'0123456789ABCDEF');",
                )
                .unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            MappingStore::open(&path, "owner", &"test".repeat(16), 1_000_000),
            Err(StorageError::Configuration(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_identifier_seed_is_not_silently_regenerated() {
        let fixture = Fixture::new();
        {
            let store = fixture.open("owner", 1_000_000);
            store
                .lock()
                .unwrap()
                .connection
                .execute("DELETE FROM storage_metadata", [])
                .unwrap();
        }
        assert!(matches!(
            MappingStore::open(
                &fixture.0.join("mappings.sqlite3"),
                "owner",
                &"test".repeat(16),
                1_000_000
            ),
            Err(StorageError::Integrity)
        ));
    }

    #[test]
    fn separate_owners_do_not_share_values_or_authentication() {
        let fixture = Fixture::new();
        let first = fixture.open("first-owner", 1_000_000);
        let second = MappingStore::open(
            &fixture.0.join("mappings.sqlite3"),
            "second-owner",
            &"other".repeat(16),
            1_000_000,
        )
        .unwrap();
        assert!(first.authenticate("test".repeat(16).as_bytes()));
        assert!(!second.authenticate("test".repeat(16).as_bytes()));
        for store in [&first, &second] {
            let token = store.token("thread", "CUSTOM", "SameFixtureValue");
            store
                .save(
                    "thread",
                    &HashMap::from([(token, "SameFixtureValue".to_owned())]),
                )
                .unwrap();
        }
        assert_eq!(counts(&first), (2, 2));
        assert_ne!(
            first.load("thread").unwrap(),
            second.load("thread").unwrap()
        );
        first.delete("thread").unwrap();
        assert_eq!(second.load("thread").unwrap().len(), 1);
    }

    #[test]
    fn cache_is_bounded_and_evicted_values_reload() {
        let fixture = Fixture::new();
        let store = fixture.open("owner", CACHE_BYTES * 4);
        let mut mappings = HashMap::new();
        for index in 0..3 {
            let original = format!("{index}{}", "x".repeat(CACHE_BYTES / 2));
            mappings.insert(store.token("thread", "CUSTOM", &original), original);
        }
        store.save("thread", &mappings).unwrap();
        for _ in 0..2 {
            assert_eq!(store.load("thread").unwrap(), mappings);
            let database = store.lock().unwrap();
            assert!(database.cache_bytes <= CACHE_BYTES);
            assert!(database.cache.len() < mappings.len());
        }
    }

    #[test]
    fn collisions_and_size_limits_roll_back_transactions() {
        let fixture = Fixture::new();
        let store = fixture.open("owner", 512);
        let token = store.token("thread", "CUSTOM", "first");
        store
            .save(
                "thread",
                &HashMap::from([(token.clone(), "first".to_owned())]),
            )
            .unwrap();
        assert!(matches!(
            store.save(
                "thread",
                &HashMap::from([(token.clone(), "second".to_owned())])
            ),
            Err(StorageError::Collision)
        ));
        let large = "x".repeat(1024);
        assert!(matches!(
            store.save(
                "other",
                &HashMap::from([(store.token("other", "CUSTOM", &large), large)])
            ),
            Err(StorageError::Limit)
        ));
        assert_eq!(counts(&store), (1, 1));
        assert_eq!(store.load("thread").unwrap()[&token], "first");
    }

    #[test]
    fn inconsistent_values_and_bindings_fail_closed() {
        let fixture = Fixture::new();
        let store = fixture.open("owner", 1_000_000);
        let token = store.token("thread", "CUSTOM", "FixtureValue");
        store
            .save(
                "thread",
                &HashMap::from([(token.clone(), "FixtureValue".to_owned())]),
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .connection
            .execute("UPDATE bindings SET token='[CUSTOM_000000000000]'", [])
            .unwrap();
        assert!(matches!(store.load("thread"), Err(StorageError::Integrity)));
        store
            .lock()
            .unwrap()
            .connection
            .execute("UPDATE bindings SET token=?1", params![token])
            .unwrap();
        store.lock().unwrap().cache.clear();
        store
            .lock()
            .unwrap()
            .connection
            .execute("UPDATE vault_values SET original='ChangedValue'", [])
            .unwrap();
        assert!(matches!(store.load("thread"), Err(StorageError::Integrity)));
    }
}
