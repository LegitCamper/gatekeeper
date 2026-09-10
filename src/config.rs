use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use url::Url;

use crate::vault::VaultConfig;

const DEFAULT_LISTEN_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
const DEFAULT_VAULT_TTL_SECS: u64 = 30 * 60;
const DEFAULT_MAX_SESSIONS: usize = 10_000;
const DEFAULT_MAX_ENTRIES_PER_SESSION: usize = 1_000;
const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_UPSTREAM_AUTH_HEADER: &str = "x-api-key";

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub target_url: Url,
    pub vault: VaultConfig,
    pub max_body_bytes: usize,
    /// Credential injected on every proxied request, replacing whatever the
    /// client sent. `None` forwards the client's own auth headers unchanged.
    pub upstream_auth: Option<(HeaderName, HeaderValue)>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = parse_env("LISTEN_ADDR", DEFAULT_LISTEN_ADDR)?;
        let target_url = env::var("TARGET_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_owned())
            .parse()
            .map_err(ConfigError::TargetUrl)?;
        let ttl_secs = parse_env("GATEKEEPER_VAULT_TTL_SECS", DEFAULT_VAULT_TTL_SECS)?;
        let max_sessions = parse_env("GATEKEEPER_MAX_SESSIONS", DEFAULT_MAX_SESSIONS)?;
        let max_entries_per_session = parse_env(
            "GATEKEEPER_MAX_ENTRIES_PER_SESSION",
            DEFAULT_MAX_ENTRIES_PER_SESSION,
        )?;
        let max_body_bytes = parse_env("GATEKEEPER_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?;
        let upstream_auth = upstream_auth()?;

        Ok(Self {
            listen_addr,
            target_url,
            vault: VaultConfig {
                ttl: Duration::from_secs(ttl_secs),
                max_sessions,
                max_entries_per_session,
            },
            max_body_bytes,
            upstream_auth,
        })
    }
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
