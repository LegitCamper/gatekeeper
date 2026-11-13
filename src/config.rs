use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

use http::header::{HeaderName, HeaderValue};
use url::Url;

const DEFAULT_LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_UPSTREAM_AUTH_HEADER: &str = "x-api-key";

/// Login names and host names that are ordinary words. Redacting them would
/// blank out common prose and every container tutorial, so
/// `GATEKEEPER_REDACT_IDENTITY` skips them and says so.
const GENERIC_IDENTITIES: &[&str] = &[
    "root",
    "admin",
    "administrator",
    "user",
    "guest",
    "nobody",
    "ubuntu",
    "node",
    "nextjs",
    "runner",
    "builder",
    "default",
    "docker",
    "app",
    "test",
    "git",
    "postgres",
    "mysql",
    "localhost",
    "ip6-localhost",
    "localhost.localdomain",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub target_url: Url,
    pub max_body_bytes: usize,
    /// Credential injected on every proxied request, replacing whatever the
    /// client sent. `None` forwards the client's own auth headers unchanged.
    pub upstream_auth: Option<(HeaderName, HeaderValue)>,
    /// Literal values redacted as `CUSTOM` on top of the built-in PII rules.
    /// See [`Config::from_env`] for the variables that fill it.
    pub redactions: Vec<String>,
    pub storage: Option<StorageConfig>,
}

#[derive(Clone)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub owner: String,
    pub client_token: String,
}

impl std::fmt::Debug for StorageConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageConfig")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn storage() -> Result<Option<StorageConfig>, ConfigError> {
    let Some(path) = optional_env("GATEKEEPER_DB_PATH")? else {
        return Ok(None);
    };
    let owner = optional_env("GATEKEEPER_OWNER_ID")?.unwrap_or_else(|| "local".to_owned());
    if !crate::storage::valid_id(&owner) {
        return Err(storage_error(
            "GATEKEEPER_OWNER_ID",
            "expected 1-256 ASCII letters, digits, dots, underscores, or hyphens",
        ));
    }
    let client_token = optional_env("GATEKEEPER_CLIENT_TOKEN")?.ok_or_else(|| {
        storage_error(
            "GATEKEEPER_CLIENT_TOKEN",
            "required when GATEKEEPER_DB_PATH is set",
        )
    })?;
    if client_token.len() < 32 || !client_token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(storage_error(
            "GATEKEEPER_CLIENT_TOKEN",
            "expected at least 32 printable ASCII characters without whitespace",
        ));
    }
    Ok(Some(StorageConfig {
        path: path.into(),
        owner,
        client_token,
    }))
}

fn optional_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => Ok((!value.is_empty()).then_some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(source) => Err(ConfigError::Environment { name, source }),
    }
}

fn storage_error(name: &'static str, reason: &str) -> ConfigError {
    ConfigError::InvalidValue {
        name,
        value: "<redacted>".to_owned(),
        reason: reason.to_owned(),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = parse_env("LISTEN_ADDR", DEFAULT_LISTEN_ADDR)?;
        let target_url = env::var("TARGET_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_owned())
            .parse()
            .map_err(ConfigError::TargetUrl)?;
        let max_body_bytes = parse_env("GATEKEEPER_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?;
        let upstream_auth = upstream_auth()?;
        let redactions = redactions()?;
        let storage = storage()?;

        Ok(Self {
            listen_addr,
            target_url,
            max_body_bytes,
            upstream_auth,
            redactions,
            storage,
        })
    }
}

/// Literal values blanked in addition to the built-in PII rules.
/// `GATEKEEPER_REDACT` is a comma-separated list of values used verbatim;
/// `GATEKEEPER_REDACT_IDENTITY` names values to read from this machine instead, so
/// a login or host name never has to be written into an env file: `user` for the
/// account name, `host` for the hostname.
///
/// Home-directory paths need neither — `/home/<user>` and `/var/home/<user>` are
/// already redacted by the detector.
fn redactions() -> Result<Vec<String>, ConfigError> {
    let mut values = split_list(env::var("GATEKEEPER_REDACT").ok().as_deref());

    for identity in split_list(env::var("GATEKEEPER_REDACT_IDENTITY").ok().as_deref()) {
        let (value, source) = match identity.as_str() {
            "user" | "username" => (
                first_env(&["USER", "LOGNAME"]).or_else(|| command_output("whoami")),
                "user",
            ),
            "host" | "hostname" => (
                first_env(&["HOSTNAME"])
                    .or_else(|| read_file("/etc/hostname"))
                    .or_else(|| command_output("hostname")),
                "host",
            ),
            other => {
                return Err(ConfigError::InvalidValue {
                    name: "GATEKEEPER_REDACT_IDENTITY",
                    value: other.to_owned(),
                    reason: "expected `user` or `host`".to_owned(),
                });
            }
        };

        match value {
            // A generic name identifies nobody here, and blanking it would mangle
            // ordinary prose, so say why nothing happened.
            Some(value) if GENERIC_IDENTITIES.contains(&value.as_str()) => {
                tracing::warn!(%value, identity = source, "skipping generic identity redaction");
            }
            Some(value) => {
                values.push(value.clone());
                // A hostname is usually typed as its first label, and the model
                // repeats whichever form it saw.
                if let Some(short) = value.split('.').next().filter(|short| *short != value) {
                    values.push(short.to_owned());
                }
            }
            None => {
                return Err(ConfigError::InvalidValue {
                    name: "GATEKEEPER_REDACT_IDENTITY",
                    value: source.to_owned(),
                    reason: "not available from this environment".to_owned(),
                });
            }
        }
    }

    Ok(values)
}

/// Comma-separated list, trimmed, empties dropped. A value that itself contains a
/// comma cannot be expressed this way; that is a known limit, not a parser bug.
fn split_list(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|name| env::var(name).ok())
        .map(|value| value.trim().to_owned())
        .find(|value| !value.is_empty())
}

fn read_file(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn command_output(program: &str) -> Option<String> {
    let output = Command::new(program).output().ok()?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Read the upstream credential. `UPSTREAM_API_KEY` (or `ANTHROPIC_API_KEY`) is
/// sent under `UPSTREAM_AUTH_HEADER`, which defaults to Anthropic's `x-api-key`.
/// Set it to `authorization` for Bearer gateways; the value is sent verbatim, so
/// include the `Bearer ` prefix yourself.
fn upstream_auth() -> Result<Option<(HeaderName, HeaderValue)>, ConfigError> {
    let key = ["UPSTREAM_API_KEY", "ANTHROPIC_API_KEY"]
        .into_iter()
        .find_map(|name| env::var(name).ok())
        .filter(|key| !key.trim().is_empty());
    let Some(key) = key else {
        return Ok(None);
    };

    let header = env::var("UPSTREAM_AUTH_HEADER")
        .unwrap_or_else(|_| DEFAULT_UPSTREAM_AUTH_HEADER.to_owned());
    let name = HeaderName::try_from(header.trim()).map_err(|error| ConfigError::InvalidValue {
        name: "UPSTREAM_AUTH_HEADER",
        value: header,
        reason: error.to_string(),
    })?;
    let mut value =
        HeaderValue::try_from(key.trim()).map_err(|error| ConfigError::InvalidValue {
            name: "UPSTREAM_API_KEY",
            value: "<redacted>".to_owned(),
            reason: error.to_string(),
        })?;
    value.set_sensitive(true);

    Ok(Some((name, value)))
}

fn parse_env<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value
            .parse::<T>()
            .map_err(|error: T::Err| ConfigError::InvalidValue {
                name,
                value,
                reason: error.to_string(),
            }),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(ConfigError::Environment {
            name,
            source: error,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {name}: {source}")]
    Environment {
        name: &'static str,
        #[source]
        source: env::VarError,
    },
    #[error("invalid {name} value {value:?}: {reason}")]
    InvalidValue {
        name: &'static str,
        value: String,
        reason: String,
    },
    #[error("invalid TARGET_URL: {0}")]
    TargetUrl(url::ParseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_debug_does_not_leak_client_token() {
        let config = StorageConfig {
            path: "fixture.sqlite3".into(),
            owner: "owner".to_owned(),
            client_token: "private-fixture-token".to_owned(),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains(&config.client_token));
    }

    #[test]
    fn redaction_lists_trim_and_drop_empties() {
        assert_eq!(
            split_list(Some(" acme-corp ,, Project Chimney,")),
            ["acme-corp", "Project Chimney"]
        );
        assert!(split_list(Some(" , ")).is_empty());
        assert!(split_list(None).is_empty());
    }
}
