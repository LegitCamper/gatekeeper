//! PII detection, anonymization, and restoration.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use serde::Serialize;

/// Category of a detected value. Ordering of [`Kind::priority`] decides which
/// category wins when two candidate spans overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ApiKey,
    Email,
    CreditCard,
    Ssn,
    Ip,
    Dob,
    Phone,
    Address,
    Name,
    /// Home-directory path: the account name is the path segment after `/home`.
    Path,
    /// Value supplied through `GATEKEEPER_REDACT` / `GATEKEEPER_REDACT_IDENTITY`.
    Custom,
}

impl Kind {
    /// Token prefix, also used as part of the token hash input.
    fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API_KEY",
            Self::Email => "EMAIL",
            Self::CreditCard => "CARD",
            Self::Ssn => "SSN",
            Self::Ip => "IP",
            Self::Dob => "DOB",
            Self::Phone => "PHONE",
            Self::Address => "ADDRESS",
            Self::Name => "NAME",
            Self::Path => "PATH",
            Self::Custom => "CUSTOM",
        }
    }

    /// Lower values win an overlap.
    fn priority(self) -> u8 {
        match self {
            Self::ApiKey => 0,
            Self::Email => 1,
            Self::CreditCard => 2,
            Self::Ssn => 3,
            Self::Ip => 4,
            Self::Dob => 5,
            Self::Phone => 6,
            Self::Address => 7,
            Self::Path => 8,
            Self::Name => 9,
            // Configured last: a custom value overlapping a real credential or
            // address must not be the only thing tokenized.
            Self::Custom => 10,
        }
    }
}

/// One detected value and its byte span in the scanned text.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub kind: Kind,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

/// Anonymized text plus the token-to-original mappings needed to restore it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Anonymized {
    pub text: String,
    pub mappings: HashMap<String, String>,
}

const DIGEST_LEN: usize = 12;
const MAX_TOKEN_CARRY: usize = 64;
const TOKEN_DECORATION_LABELS: &[&str] = &[
    "API_KEY",
    "EMAIL",
    "CARD",
    "CREDIT_CARD",
    "SSN",
    "IP",
    "DOB",
    "PHONE",
    "ADDRESS",
    "NAME",
    "PATH",
    "CUSTOM",
    "CONTACT",
    "REDACTED",
];

/// Multi-origin given names, one per line. Entries that are also ordinary
/// English dictionary words were removed unless they are common enough as names
/// to be worth the occasional false positive, so a bare match here is a strong
/// signal — but a name is still only reported when a capitalized surname
/// follows it.
const GIVEN_NAMES: &str = include_str!("given_names.txt");

/// Words that introduce a person, letting a `Capitalized Capitalized` pair be
/// reported even when the given name is absent from [`GIVEN_NAMES`].
///
/// Deliberately excludes `to` and `from`: they precede a capitalized pair far
/// too often in ordinary prose ("from Redis Cluster", "to New York"), and a
/// person named after one is normally caught by [`GIVEN_NAMES`] anyway.
const NAME_TRIGGERS: &[&str] = &[
    "attn",
    "cc",
    "contact",
    "patient",
    "regards",
    "signed",
    "sincerely",
];

/// Multi-word proper nouns that otherwise satisfy the dictionary-given-name plus
/// capitalized-surname rule but are predictably not people in ordinary text.
const NAME_PHRASE_DENY: &[&str] = &[
    "Robin Hood",
    "Sandy Beach",
    "Sandy Beach Elementary",
    "customer support",
    "medical record",
];

/// Capitalized words that are never part of a person's name here, even when the
/// dictionary lists them as a given name (`April`, `May`, `Monday`).
const NAME_DENY: &[&str] = &[
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
    "North",
    "South",
    "East",
    "West",
    "New",
    // Continents and geographic regions
    "Africa",
    "America",
    "Asia",
    "Europe",
    "Australia",
    // Common nouns/words that are also given names
    "Grace",
    "Hope",
    "Faith",
    "Charity",
    "Joy",
    "Victory",
    "Mark",
    "Bill",
    "Will",
    "Rose",
    "Lily",
    "Iris",
    "Daisy",
    "Violet",
    "Amber",
    "Sage",
    "Angel",
    "Star",
    "Art",
];

pub struct Detector {
    patterns: Vec<(Kind, Regex)>,
    given_names: AhoCorasick,
    /// Configured literal values (login names, internal identifiers) reported as
    /// [`Kind::Custom`]. `None` until [`Detector::with_redactions`] adds them.
    custom: Option<AhoCorasick>,
    tokens: RandomState,
}

impl Default for Detector {
    fn default() -> Self {
        let patterns = vec![
            (
                Kind::ApiKey,
                Regex::new(
                    r"(?x)
                    sk-ant-[A-Za-z0-9_-]{10,}
                  | sk-[A-Za-z0-9_-]{16,}
                  | A(?:KIA|SIA|GPA|IDA|ROA|NPA|NVA)[0-9A-Z]{16}
                  | gh[posur]_[A-Za-z0-9]{20,}
                  | github_pat_[A-Za-z0-9_]{20,}
                  | xox[baprs]-[A-Za-z0-9-]{10,}
                  | AIza[0-9A-Za-z_-]{35}
                  | glpat-[A-Za-z0-9_-]{16,}
                  | [sr]k_(?:live|test)_[A-Za-z0-9]{16,}
                  | shp(?:at|ca|pa|ss)_[A-Za-z0-9]{32}
                  | npm_[A-Za-z0-9]{36}
                  | hf_[A-Za-z0-9]{30,}
                  | dop_v1_[A-Za-z0-9]{40,}
                  | SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}
                  | sq0(?:atp|csp)-[A-Za-z0-9_-]{20,}
                  | dapi[0-9a-f]{32}
                  | pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}
                  | eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{8,}
                ",
                )
                .expect("api key pattern is valid"),
            ),
            (
                // Generic `pat_` personal access tokens. The tail deliberately
                // excludes `_`: a token is alphanumeric, while `pat_matcher_state`
                // and other snake_case identifiers are not, so ordinary source
                // text keeps its names.
                Kind::ApiKey,
                Regex::new(r"\bpat_[A-Za-z0-9]{20,}").expect("pat token pattern is valid"),
            ),
            (
                // PEM private keys, matched on content rather than file name, so
                // key material pasted into a prompt or read out of `backup.txt`,
                // `server.pem.bak`, or any other extension the `.env` guard does
                // not recognize is still removed. The armor line is matched on its
                // own as well: a truncated or quoted block still names a key.
                Kind::ApiKey,
                Regex::new(
                    r"(?x)
                    -----BEGIN[\x20A-Z]{0,20}PRIVATE\x20KEY-----
                    [\s\S]{0,8192}?
                    -----END[\x20A-Z]{0,20}PRIVATE\x20KEY-----
                  | -----BEGIN[\x20A-Z]{0,20}PRIVATE\x20KEY-----
                ",
                )
                .expect("pem private key pattern is valid"),
            ),
            (
                // Labeled secrets that carry no recognizable prefix: a password,
                // bearer token, or house-built key is just a string, so shape
                // alone can never find it. The label is what marks it, and only
                // the value after the separator is captured. Quotes and trailing
                // punctuation are excluded so `password: "hunter2",` tokenizes
                // `hunter2` and leaves the JSON or YAML around it intact.
                //
                // A leading `$` and any `<`/`>` are rejected, so environment
                // references (`api-key: $ANTHROPIC_API_KEY`), placeholders
                // (`<your-key-here>`), and type annotations
                // (`private_key: Option<String>`) stay readable.
                //
                // ponytail: a bare PascalCase type wider than 8 characters
                // (`client_secret: SecretString`) still tokenizes. It round-trips
                // intact, so the cost is model readability, not correctness. Add a
                // type-shape deny list if code-heavy prompts show the noise.
                Kind::ApiKey,
                Regex::new(
                    r#"(?ix:
                        \b(?: password | passwd | secret | api[_-]?key | auth[_-]?token
                             | access[_-]?token | refresh[_-]?token | client[_-]?secret
                             | private[_-]?key | bearer )
                        \b ["']? \s* [:=] \s* ["']?
                    )([^\s"',;$<>][^\s"',;<>]{7,199})"#,
                )
                .expect("labeled secret pattern is valid"),
            ),
            (
                Kind::Email,
                // Small models still understand fullwidth `＠` and zero-width
                // characters around the separator. Treat those as part of the
                // address span instead of handing the obfuscated address upstream.
                Regex::new(
                    r"(?:[A-Za-z0-9._%+-][\x{200B}\x{200C}\x{200D}\x{FEFF}]*)+[@＠][\x{200B}\x{200C}\x{200D}\x{FEFF}]*(?:[A-Za-z0-9-][\x{200B}\x{200C}\x{200D}\x{FEFF}]*)+(?:\.[\x{200B}\x{200C}\x{200D}\x{FEFF}]*(?:[A-Za-z0-9-][\x{200B}\x{200C}\x{200D}\x{FEFF}]*)+)*\.[\x{200B}\x{200C}\x{200D}\x{FEFF}]*(?:[A-Za-z][\x{200B}\x{200C}\x{200D}\x{FEFF}]*){2,}",
                )
                .expect("email pattern is valid"),
            ),
            (
                // A 40-character base64-ish value is common enough that shape
                // alone is unsafe. Require the AWS secret-key label and capture
                // only the credential itself.
                Kind::ApiKey,
                Regex::new(
                    r"(?i:\baws(?:_access)?_secret(?:_access)?_key\b[\s:=]{1,4})([A-Za-z0-9/+=]{40})(?:$|[^A-Za-z0-9/+=])",
                )
                .expect("aws secret key pattern is valid"),
            ),
            (
                Kind::CreditCard,
                // Deliberately allowed to run past a card's own digits: a
                // greedy span that swallows the next number is tightened back
                // to the real card by [`tighten_numeric_span`]. Capped so a
                // pathological digit run cannot blow up that search.
                Regex::new(r"\d(?:[ -]?\d){11,40}").expect("card pattern is valid"),
            ),
            (
                Kind::Ssn,
                Regex::new(r"\b\d{3}[-.]\d{2}[-.]\d{4}\b").expect("ssn pattern is valid"),
            ),
            (
                // Unformatted and space-separated SSNs. Nine bare digits are far
                // too common (order numbers, zip+4, ids) to redact on shape
                // alone, so these forms require a nearby `ssn`/`social security`.
                // The value itself is captured, leaving the label in place.
                Kind::Ssn,
                Regex::new(
                    r"(?i:\b(?:ssn|social security(?: number)?)\b[:=# ]{0,3})(\d{3} \d{2} \d{4}|\d{9})\b",
                )
                .expect("contextual ssn pattern is valid"),
            ),
            (
                Kind::Ip,
                Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("ip pattern is valid"),
            ),
            (
                // Defanged IPs remain intelligible to a model but dodge the
                // ordinary dotted-quad pattern. Preserve the exact input in the
                // mapping; validation normalizes only the separator.
                Kind::Ip,
                Regex::new(r"\b\d{1,3}(?:(?:\[\.\]|\(\.\)|\.)\d{1,3}){3}\b")
                    .expect("defanged ip pattern is valid"),
            ),
            (
                // IPv6: full, leading/trailing/interior compressed, and
                // IPv4-mapped forms. [`IpAddr::parse`] rejects timestamps, ratios,
                // bare `::`, and malformed group counts after this shape filter.
                Kind::Ip,
                Regex::new(
                    r"(?i)(?:\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|::ffff:\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|\b(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b)",
                )
                .expect("ipv6 pattern is valid"),
            ),
            (
                Kind::Dob,
                Regex::new(r"\b(?:(?:19|20)\d{2}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/(?:19|20)\d{2})\b")
                    .expect("date pattern is valid"),
            ),
            (
                Kind::Phone,
                // The optional leading `(` keeps `(415) 555-2671` whole.
                Regex::new(r"\+?\(?\d[\d ().-]{5,20}\d").expect("phone pattern is valid"),
            ),
            (
                Kind::Address,
                Regex::new(
                    r"\b\d{1,5} (?:[A-Z][a-z]+ ){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b",
                )
                .expect("address pattern is valid"),
            ),
            (
                // Home directories carry the account name in the segment right
                // after `home`, so the whole `/home/<user>` prefix is tokenized
                // and the rest of the path stays readable for the model.
                Kind::Path,
                Regex::new(r#"(?:/(?:var/)?home|/Users)/[^/\s"'`]+"#)
                    .expect("home path pattern is valid"),
            ),
            (
                // Strong identity/title context permits three title-cased words
                // for names such as `María José García`.
                Kind::Name,
                Regex::new(
                    r"(?i:\b(?:my name is\b|name:|(?:mr|mrs|ms|dr)\.?) +)((?:\p{Lu}[\p{L}'’-]* +){2}\p{Lu}[\p{L}'’-]*)",
                )
                .expect("three-word name identity pattern is valid"),
            ),
            (
                // Lowercase and all-caps names still work in explicit context,
                // but stop after the given/surname pair so `and`, `called`, etc.
                // are not swallowed as a third name word.
                Kind::Name,
                Regex::new(
                    r"(?i:\b(?:my name is\b|name:|(?:mr|mrs|ms|dr)\.?) +)([\p{L}][\p{L}'’-]* +[\p{L}][\p{L}'’-]*)",
                )
                .expect("name identity pattern is valid"),
            ),
            (
                // Explicit identity/title context is enough for one name word.
                // This catches `My name is Alice.` without restoring the old bare
                // dictionary-name false positives.
                Kind::Name,
                Regex::new(
                    r"(?i:\b(?:my name is\b|name:|(?:mr|mrs|ms|dr)\.?) +)([\p{L}][\p{L}'’-]*)",
                )
                .expect("single-word name identity pattern is valid"),
            ),
            (
                // Common lowercase surname particles belong to the surrounding
                // capitalized name, not a truncated given/particle pair.
                Kind::Name,
                Regex::new(&format!(
                    r"(?i:\b(?:{})\b)[:,]? +(\p{{Lu}}[\p{{L}}'’-]* +(?:van|von|de|del|da|di|du|la|le) +\p{{Lu}}[\p{{L}}'’-]*)",
                    NAME_TRIGGERS.join("|")
                ))
                .expect("name particle trigger pattern is valid"),
            ),
            (
                // General triggers may carry a three-word title-cased name. Keep
                // this case-sensitive so a trailing lowercase verb is not eaten.
                Kind::Name,
                Regex::new(&format!(
                    r"(?i:\b(?:{})\b)[:,]? +((?:\p{{Lu}}[\p{{L}}'’-]* +){{2}}\p{{Lu}}[\p{{L}}'’-]*)",
                    NAME_TRIGGERS.join("|")
                ))
                .expect("three-word name trigger pattern is valid"),
            ),
            (
                // General person triggers capture exactly a given/surname pair,
                // avoiding a trailing lowercase verb (`patient alice johnson
                // called`) while still covering lowercase and all-caps names.
                Kind::Name,
                Regex::new(&format!(
                    r"(?i:\b(?:{})\b)[:,]? +([\p{{L}}][\p{{L}}'’-]* +[\p{{L}}][\p{{L}}'’-]*)",
                    NAME_TRIGGERS.join("|")
                ))
                .expect("name trigger pattern is valid"),
            ),
        ];

        let given_names = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(
                GIVEN_NAMES
                    .lines()
                    .filter(|name| !name.is_empty())
                    .collect::<Vec<_>>(),
            )
            .expect("given name dictionary is valid");

        Self {
            patterns,
            given_names,
            custom: None,
            tokens: RandomState::new(),
        }
    }
}

impl Detector {
    /// Add literal values to redact on top of the built-in patterns, reported as
    /// [`Kind::Custom`]. Matching is case-insensitive and whole-word, so `acme`
    /// catches `Acme` but not `pacman`. Values shorter than two characters are
    /// dropped: a one-character "redaction" would fire on every other token.
    #[must_use]
    pub fn with_redactions(mut self, values: &[String]) -> Self {
        let literals: Vec<String> = values
            .iter()
            .map(|value| value.trim())
            .filter(|value| value.chars().count() > 1)
            .map(str::to_owned)
            .collect();
        if !literals.is_empty() {
            self.custom = Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .ascii_case_insensitive(true)
                    .build(literals)
                    .expect("literal redactions are valid"),
            );
        }
        self
    }
    /// Find every supported value in `text`, resolving overlaps by category
    /// priority and then by span length. Results are ordered by position.
    pub fn scan(&self, text: &str) -> Vec<Detection> {
        let mut candidates = Vec::new();

        for (kind, pattern) in &self.patterns {
            for found in pattern.captures_iter(text) {
                // Context name patterns report the captured name, not the trigger.
                let span = found
                    .get(1)
                    .unwrap_or_else(|| found.get(0).expect("capture group 0 always matches"));
                if let Some((start, end)) = validate(*kind, text, span.start(), span.end()) {
                    candidates.push(Detection {
                        kind: *kind,
                        value: text[start..end].to_owned(),
                        start,
                        end,
                    });
                }
            }
        }

        candidates.extend(self.dictionary_names(text));
        candidates.extend(self.custom_literals(text));
        resolve(candidates)
    }

    /// Configured literal values, matched whole: `acme` fires in `Acme Corp` but
    /// not in `pacman`, so an operator cannot blank out ordinary prose by typing
    /// a short fragment.
    fn custom_literals(&self, text: &str) -> Vec<Detection> {
        let Some(custom) = &self.custom else {
            return Vec::new();
        };

        custom
            .find_iter(text)
            .filter(|found| {
                let word = |c: char| c.is_alphanumeric() || c == '_';
                !text[..found.start()].chars().next_back().is_some_and(word)
                    && !text[found.end()..].chars().next().is_some_and(word)
            })
            .map(|found| Detection {
                kind: Kind::Custom,
                value: text[found.start()..found.end()].to_owned(),
                start: found.start(),
                end: found.end(),
            })
            .collect()
    }

    /// Replace every detected value with an opaque token, returning the token
    /// mappings required to restore the original text.
    pub fn anonymize(&self, text: &str) -> Anonymized {
        let detections = self.scan(text);
        if detections.is_empty() {
            return Anonymized {
                text: text.to_owned(),
                mappings: HashMap::new(),
            };
        }

        let mut output = String::with_capacity(text.len());
        let mut mappings = HashMap::new();
        let mut cursor = 0;
        for detection in detections {
            output.push_str(&text[cursor..detection.start]);
            let token = self.token(detection.kind, &detection.value);
            output.push_str(&token);
            mappings.insert(token, detection.value);
            cursor = detection.end;
        }
        output.push_str(&text[cursor..]);

        Anonymized {
            text: output,
            mappings,
        }
    }

    /// Token for a value. The hash is keyed by a per-process random seed, so
    /// tokens are stable for the life of this detector (letting the same value
    /// in separate JSON strings share one token) without being reversible by an
    /// upstream that only sees the token.
    fn token(&self, kind: Kind, value: &str) -> String {
        let digest = self.tokens.hash_one((kind.label(), value));
        format!("[{}_{:012x}]", kind.label(), digest & 0xffff_ffff_ffff)
    }

    /// Dictionary given name, optionally followed by capitalized words (middle name, surname).
    /// Reports single first names or multi-word name sequences.
    fn dictionary_names(&self, text: &str) -> Vec<Detection> {
        let bytes = text.as_bytes();
        let mut found = Vec::new();

        for candidate in self.given_names.find_iter(text) {
            let (start, given_end) = (candidate.start(), candidate.end());
            // Ensure not matched mid-word (check both before and after)
            if start > 0 && is_word_byte(bytes[start - 1]) {
                continue;
            }
            if given_end < text.len() && is_word_byte(bytes[given_end]) {
                continue; // Given name is followed by more word characters (e.g., "Rus" in "Rust")
            }

            // A dictionary given name is not enough by itself: Ruby, Jordan,
            // Frank, Max, Sandy, and Dell are all ordinary words or brands. A
            // following surname is the second signal that makes a bare-text hit
            // worth redacting. Explicit person-context patterns above still catch
            // a full name regardless of dictionary membership or casing.
            let compound_given_end = end_of_hyphenated_word(text, given_end).unwrap_or(given_end);
            let Some(end) = end_of_name(text, compound_given_end) else {
                continue;
            };

            // Validate the detected name
            if validate(Kind::Name, text, start, end).is_none() {
                continue;
            }

            found.push(Detection {
                kind: Kind::Name,
                value: text[start..end].to_owned(),
                start,
                end,
            });
        }

        found
    }
}

/// Restores values using canonical tokens or their request-local 12-hex digest.
pub(crate) struct Restorer {
    tokens: HashMap<String, String>,
    digests: HashMap<String, Option<String>>,
    digests_with_case: Vec<String>,
}

#[derive(Default)]
pub(crate) struct RestoreCarry {
    pub(crate) text: String,
    pub(crate) skip_closing_bracket: bool,
}

impl Restorer {
    pub(crate) fn new(mappings: &HashMap<String, String>) -> Self {
        let mut digests: HashMap<String, Option<String>> = HashMap::new();
        for (token, original) in mappings {
            let Some(digest) = token
                .strip_suffix(']')
                .and_then(|token| token.rsplit_once('_'))
                .map(|(_, digest)| digest)
                .filter(|digest| {
                    digest.len() == DIGEST_LEN
                        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            else {
                continue;
            };
            let digest = digest.to_ascii_lowercase();
            digests
                .entry(digest)
                .and_modify(|stored| {
                    if stored.as_deref() != Some(original) {
                        *stored = None;
                    }
                })
                .or_insert_with(|| Some(original.clone()));
        }

        let digests_with_case = digests
            .iter()
            .filter(|(_, original)| original.is_some())
            .flat_map(|(digest, _)| [digest.clone(), digest.to_ascii_uppercase()])
            .collect();

        Self {
            tokens: mappings.clone(),
            digests,
            digests_with_case,
        }
    }

    pub(crate) fn restore(&self, text: &str) -> String {
        let mut carry = RestoreCarry::default();
        let mut restored = self.restore_fragment(text, &mut carry);
        restored.push_str(&carry.text);
        restored
    }

    pub(crate) fn restore_fragment(&self, text: &str, carry: &mut RestoreCarry) -> String {
        if self.tokens.is_empty() {
            return text.to_owned();
        }

        let text = if carry.skip_closing_bracket {
            carry.skip_closing_bracket = false;
            text.strip_prefix(']').unwrap_or(text)
        } else {
            text
        };
        let full_text = if carry.text.is_empty() {
            text.to_owned()
        } else {
            let mut combined = std::mem::take(&mut carry.text);
            combined.push_str(text);
            combined
        };
        let bytes = full_text.as_bytes();
        let mut output = String::with_capacity(full_text.len());
        let mut cursor = 0;

        while cursor < full_text.len() {
            if let Some((token, original)) = self
                .tokens
                .iter()
                .find(|(token, _)| full_text[cursor..].starts_with(token.as_str()))
            {
                output.push_str(original);
                cursor += token.len();
                continue;
            }

            // A digest only counts when the hex run is exactly DIGEST_LEN long:
            // the same 12 hex characters inside a commit sha or checksum belong
            // to that value, and splicing PII into it corrupts the response.
            let hex_run_bounded = cursor + DIGEST_LEN <= full_text.len()
                && bytes[cursor..cursor + DIGEST_LEN]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
                && !bytes
                    .get(cursor + DIGEST_LEN)
                    .is_some_and(u8::is_ascii_alphanumeric);
            let found = if hex_run_bounded {
                Some((
                    full_text[cursor..cursor + DIGEST_LEN].to_ascii_lowercase(),
                    cursor + DIGEST_LEN,
                ))
            } else {
                split_digest(&full_text, cursor)
            };
            // Either way the run has to start on a boundary, so a digest sitting
            // inside a longer hex value stays part of that value.
            let on_boundary = !(cursor > 0 && bytes[cursor - 1].is_ascii_alphanumeric());
            if on_boundary
                && let Some((digest, digest_end)) = found
                && let Some(Some(original)) = self.digests.get(&digest)
            {
                let decorated = decoration_start(&full_text, cursor);
                let bracketed =
                    cursor > 0 && bytes[cursor - 1] == b'[' && bytes.get(digest_end) == Some(&b']');
                let start = decorated.or_else(|| bracketed.then(|| cursor - 1));
                if let Some(start) = start {
                    let decoration = &full_text[start..cursor];
                    if output.ends_with(decoration) {
                        output.truncate(output.len() - decoration.len());
                    }
                }
                output.push_str(original);
                cursor = digest_end;
                if start.is_some() {
                    if bytes.get(cursor) == Some(&b']') {
                        cursor += 1;
                    } else if cursor == full_text.len() {
                        carry.skip_closing_bracket = true;
                    }
                }
                continue;
            }

            let next = full_text[cursor..]
                .chars()
                .next()
                .expect("cursor is before string end")
                .len_utf8();
            output.push_str(&full_text[cursor..cursor + next]);
            cursor += next;
        }

        let keep = partial_suffix_len(&output, &self.tokens, &self.digests_with_case);
        if keep > 0 {
            carry.text.push_str(&output[output.len() - keep..]);
            output.truncate(output.len() - keep);
        }
        output
    }
}

/// Characters a model inserts *into* a digest while formatting it — markdown
/// emphasis, a line wrap, spacing between characters. Not `-` or `_`: those carry
/// meaning inside real identifiers (`abc-123`, commit ranges), and treating them
/// as noise would let unrelated text collapse into a digest.
const DIGEST_NOISE: &[u8] = b"* \t\n\r`";

/// Read a digest whose hex characters a model broke up with formatting, e.g.
/// `894e**a3db5**2e8`, `894ea3d\nb52e8`, or `8 9 4 e a 3 d b 5 2 e 8`.
///
/// Small models reformat tokens freely, and an unrecovered digest reaches the
/// client as a live hash — deleting the inserted characters recovers the value it
/// stood for. Returns the digest plus the byte offset just past it.
///
/// Requires the run to *start* with a hex digit and to hold exactly
/// [`DIGEST_LEN`] of them, and stops at the first noise run longer than three
/// bytes, so ordinary prose containing scattered hex letters cannot be stitched
/// into a token.
fn split_digest(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if !bytes.get(start).is_some_and(u8::is_ascii_hexdigit) {
        return None;
    }

    let mut digest = String::with_capacity(DIGEST_LEN);
    let mut cursor = start;
    let mut end = start;
    while cursor < bytes.len() && digest.len() < DIGEST_LEN {
        if bytes[cursor].is_ascii_hexdigit() {
            digest.push(bytes[cursor].to_ascii_lowercase() as char);
            cursor += 1;
            end = cursor;
            continue;
        }
        let noise = bytes[cursor..]
            .iter()
            .take_while(|byte| DIGEST_NOISE.contains(byte))
            .count();
        if noise == 0 || noise > 3 {
            break;
        }
        cursor += noise;
    }

    if digest.len() != DIGEST_LEN || bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }

    // The run must also *end* where the hex does, looking past trailing noise:
    // `0 1 2 3 4 5 6 7 8 9 a b c d` holds a digest's worth of characters in its
    // first twelve, and without this it would restore and leave `c d` behind.
    let trailing_noise = bytes[end..]
        .iter()
        .take_while(|byte| DIGEST_NOISE.contains(byte))
        .count();
    if (1..=3).contains(&trailing_noise)
        && bytes
            .get(end + trailing_noise)
            .is_some_and(u8::is_ascii_hexdigit)
    {
        return None;
    }

    Some((digest, end))
}

fn decoration_start(text: &str, digest_start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let separator = digest_start.checked_sub(1)?;
    if !matches!(bytes[separator], b'_' | b':' | b'-') {
        return None;
    }

    let mut label_start = separator;
    while label_start > 0 {
        let byte = bytes[label_start - 1];
        if byte.is_ascii_uppercase() || byte == b'_' {
            label_start -= 1;
        } else {
            break;
        }
    }
    if label_start == separator {
        return None;
    }
    if label_start > 0 && bytes[label_start - 1].is_ascii_alphanumeric() {
        return None;
    }
    Some(if label_start > 0 && bytes[label_start - 1] == b'[' {
        label_start - 1
    } else {
        label_start
    })
}

fn partial_suffix_len(text: &str, tokens: &HashMap<String, String>, digests: &[String]) -> usize {
    let mut starts: Vec<usize> = text
        .char_indices()
        .map(|(index, _)| index)
        .filter(|index| text.len() - index <= MAX_TOKEN_CARRY)
        .collect();
    starts.push(text.len());
    starts
        .into_iter()
        .find(|start| {
            let suffix = &text[*start..];
            if suffix.is_empty() {
                return false;
            }
            if tokens.keys().any(|token| token.starts_with(suffix)) {
                return true;
            }
            digests.iter().any(|digest| digest.starts_with(suffix))
                // A digest a model split with formatting can also straddle a
                // chunk boundary (`012345**67` then `89ab**`). Without this the
                // carry ends at the `*` and the two halves are emitted verbatim,
                // putting a live hash in the client's view — streaming is the
                // normal path, so the noise-tolerant match has to apply here too.
                || noise_stripped_digest_prefix(suffix, digests)
                || ((*start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric())
                    && token_decoration_prefix(suffix, digests))
        })
        .map_or(0, |start| text.len() - start)
}

/// Is `text`, once formatting characters are dropped, the start of a known digest?
///
/// Lets [`partial_suffix_len`] hold back a digest that a model both split with
/// formatting and left straddling a chunk boundary. Requires at least one hex
/// character so a lone `*` or space is never carried.
fn noise_stripped_digest_prefix(text: &str, digests: &[String]) -> bool {
    if text.len() > DIGEST_LEN * 4 {
        return false;
    }
    let mut hex = String::with_capacity(DIGEST_LEN);
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            hex.push(byte.to_ascii_lowercase() as char);
        } else if !DIGEST_NOISE.contains(&byte) {
            return false;
        }
        if hex.len() > DIGEST_LEN {
            return false;
        }
    }

    !hex.is_empty() && digests.iter().any(|digest| digest.starts_with(&hex))
}

fn token_decoration_prefix(text: &str, digests: &[String]) -> bool {
    let text = text.strip_prefix('[').unwrap_or(text);
    if text.is_empty() {
        return true;
    }

    TOKEN_DECORATION_LABELS.iter().any(|label| {
        if label.starts_with(text) {
            return true;
        }
        let Some(suffix) = text
            .strip_prefix(label)
            .and_then(|text| text.strip_prefix(['_', ':', '-']))
        else {
            return false;
        };
        suffix.is_empty() || digests.iter().any(|digest| digest.starts_with(suffix))
    })
}

/// Replace known tokens and model-mutated forms with original values.
pub fn restore(text: &str, mappings: &HashMap<String, String>) -> String {
    Restorer::new(mappings).restore(text)
}

/// Does `at` fall on a `.` boundary inside a dotted number such as `203.0.113.55`?
///
/// Used to reject tightened spans that would keep only part of a neighbouring IP
/// or version string.
fn splits_dotted_number(text: &str, at: usize) -> bool {
    let bytes = text.as_bytes();
    let dot_before = at >= 2 && bytes[at - 1] == b'.' && bytes[at - 2].is_ascii_digit();
    let dot_after = bytes.get(at) == Some(&b'.')
        && bytes.get(at + 1).is_some_and(u8::is_ascii_digit)
        && at > 0
        && bytes[at - 1].is_ascii_digit();
    dot_before || dot_after
}

/// Take the matched span when `accept` recognizes it and it does not straddle a
/// neighbouring dotted number, otherwise tighten it.
///
/// The straddle check has to happen *before* the whole-span accept: `is_phone`
/// returns true for `+1 (415) 555-2671 203` (14 digits, `+`-prefixed, parses as
/// dialable), so accepting the greedy span produced a Phone that overlapped the
/// IP — and [`Kind::Ip`] outranks [`Kind::Phone`], so the phone was discarded
/// and reached the upstream in plaintext.
fn accept_or_tighten(
    text: &str,
    start: usize,
    end: usize,
    accept: impl Fn(&str) -> bool,
) -> Option<(usize, usize)> {
    if !splits_dotted_number(text, start)
        && !splits_dotted_number(text, end)
        && accept(&text[start..end])
    {
        return Some((start, end));
    }
    tighten_numeric_span(text, start, end, accept)
}

/// Trim a numeric span until `accept` recognizes it, so a greedy match that ran
/// into a neighbouring number still yields the value it started on.
///
/// `\d(?:[ -]?\d){11,40}` cannot tell a card's internal space from the space
/// before the next number, so `4111-1111-1111-1111 203.0.113.55` matches as one
/// 19-digit span that fails Luhn. Dropping the candidate there left the card in
/// plaintext; instead, retry shorter prefixes (then suffixes, for a leading
/// `ref 99 4111-...`) and report the first span that validates.
fn tighten_numeric_span(
    text: &str,
    start: usize,
    end: usize,
    accept: impl Fn(&str) -> bool,
) -> Option<(usize, usize)> {
    // Split the span into digit groups. Only whole groups are dropped: trimming
    // mid-run would let an arbitrary 16-digit order number yield whichever
    // 13-digit substring happens to satisfy Luhn.
    let groups: Vec<(usize, usize)> = text[start..end]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|group| !group.is_empty())
        .map(|group| {
            let offset = start + (group.as_ptr() as usize - text[start..end].as_ptr() as usize);
            (offset, offset + group.len())
        })
        .collect();

    // Longest first, preferring spans that keep the original start, so the
    // value the match began on wins over a shorter tail inside it.
    for count in (1..=groups.len()).rev() {
        for window in groups.windows(count) {
            let (digits_from, stop) = (window[0].0, window[count - 1].1);
            // Reclaim any `+` or `(` the first digit group left behind, so a
            // parenthesized or country-prefixed number keeps the shape its
            // validator recognizes.
            let mut from = digits_from;
            while from > start && matches!(text.as_bytes()[from - 1], b'+' | b'(') {
                from -= 1;
            }
            // A span that stops mid-way through a dotted number has eaten part
            // of an IP or version string. `is_phone` happily accepts
            // `+1 (415) 555-2671 203`, and that span overlaps the IP, so the
            // higher-priority IP wins the overlap and the phone is dropped
            // entirely. Anchor to a boundary the neighbour does not straddle.
            if splits_dotted_number(text, stop) || splits_dotted_number(text, digits_from) {
                continue;
            }
            for candidate in [from, digits_from] {
                if (candidate, stop) != (start, end) && accept(&text[candidate..stop]) {
                    return Some((candidate, stop));
                }
            }
        }
    }

    None
}

/// Reject candidates that only look like the category, and tighten spans.
fn validate(kind: Kind, text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let value = &text[start..end];
    match kind {
        Kind::CreditCard => accept_or_tighten(text, start, end, is_payment_card),
        // Loopback and `0.0.0.0` identify nobody; tokenizing them breaks config
        // and bind-address round-trips.
        // Same loopback/unspecified exemption for both families: `::1` and
        // `0.0.0.0` identify nobody, and tokenizing them breaks bind-address and
        // config round-trips.
        Kind::Ip => value
            .replace("[.]", ".")
            .replace("(.)", ".")
            .parse::<IpAddr>()
            .ok()
            .filter(|address| !(address.is_loopback() || address.is_unspecified()))
            .map(|_| (start, end)),
        Kind::Path => {
            // `./home/../bin` is a relative path, not an account: judge the
            // segment as matched, before any trimming.
            let segment = text[start..end].rsplit('/').next().unwrap_or("");
            if segment.is_empty() || segment.chars().all(|c| c == '.') {
                return None;
            }
            // The greedy last segment also swallows sentence punctuation and
            // markdown, so `fix /home/sawyer.` must not map a token to a trailing
            // period. Interior dots (`/home/j.doe`) are safe: only the tail goes.
            let mut end = end;
            while end > start {
                let last = text[..end].chars().next_back().unwrap_or('\0');
                if last.is_alphanumeric() || matches!(last, '_' | '-') {
                    break;
                }
                end -= last.len_utf8();
            }
            (end > start).then_some((start, end))
        }
        Kind::Phone => {
            let preceded_by_word = start > 0 && is_word_byte(text.as_bytes()[start - 1]);
            if preceded_by_word {
                return None;
            }
            // Same greedy-span problem as cards: `415-555-2671 203.0.113.55`
            // matches as one run, so retry shorter spans before giving up.
            accept_or_tighten(text, start, end, is_phone)
        }
        // Reject when any word of the pair is a calendar or direction word.
        Kind::Name => (!NAME_PHRASE_DENY.contains(&value)
            && value.split(' ').all(|word| !NAME_DENY.contains(&word)))
        .then_some((start, end)),
        _ => Some((start, end)),
    }
}

/// Length plus Luhn check, so ordinary long digit runs are not tokenized.
fn is_payment_card(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 0 {
                *digit
            } else if *digit > 4 {
                digit * 2 - 9
            } else {
                digit * 2
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Phone-number shape regexes for values the `phonenumber` metadata rejects.
/// Placeholder-looking numbers such as `000-000-0000` or `555-0100` are still
/// redacted: a caller who wrote a phone number into a prompt gets it removed
/// whether or not it happens to be dialable.
static PHONE_SHAPES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        // North American, optionally country-prefixed or parenthesized, plus
        // Vietnamese 3-3-2-2 national grouping.
        Regex::new(
            r"^(?:1[ .-])?(?:\d{3}[ .-]\d{3}[ .-]\d{4}|\(\d{3}\) ?\d{3}[ .-]\d{4}|0\d{2}[ .-]\d{3}[ .-]\d{2}[ .-]\d{2})$",
        )
        .expect("grouped phone shape is valid"),
        // Bare 10 digits, or 11 with a leading country digit.
        Regex::new(r"^\+?1?\d{10}$").expect("bare phone shape is valid"),
        // International: + and 8..15 digits in any grouping.
        Regex::new(r"^\+\d[\d ().-]{6,}\d$").expect("international phone shape is valid"),
    ]
});

fn has_phone_punctuation(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'.' | b'-' | b'(' | b')'))
}

/// Accept a number the `phonenumber` metadata considers valid (trying a bare
/// international parse, then North American and Vietnamese hints), or one that
/// matches an unambiguous phone shape.
fn is_phone(value: &str) -> bool {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits) {
        return false;
    }

    let dialable = [
        None,
        Some(phonenumber::country::US),
        Some(phonenumber::country::VN),
    ]
    .into_iter()
    .any(|hint| phonenumber::parse(hint, value).is_ok_and(|number| number.is_valid()));

    // National numbers accepted via metadata must be bare digits or match a
    // known grouping. This avoids redacting arbitrary version/range strings
    // such as `1234-56-78901` merely because their digits parse as dialable.
    let structured = !has_phone_punctuation(value)
        || value.starts_with('+')
        || PHONE_SHAPES.iter().any(|shape| shape.is_match(value));

    (dialable && structured) || PHONE_SHAPES.iter().any(|shape| shape.is_match(value))
}

fn person_word_len(text: &str) -> usize {
    text.char_indices()
        .find(|(_, c)| !(c.is_alphabetic() || matches!(c, '\'' | '’' | '-')))
        .map_or(text.len(), |(offset, _)| offset)
}

/// Extend a dictionary given name through a capitalized hyphen suffix, turning
/// the `Jean` dictionary hit in `Jean-Luc Picard` into the complete given name.
fn end_of_hyphenated_word(text: &str, start: usize) -> Option<usize> {
    let rest = text.get(start..)?.strip_prefix('-')?;
    if !rest.chars().next()?.is_uppercase() {
        return None;
    }
    let length = person_word_len(rest);
    (length >= 2).then_some(start + 1 + length)
}

/// End position of one or more capitalized surname words following a given name.
/// Unicode case/letters matter here: `Søren Kierkegaard` is no less a name than
/// `Alice Johnson`.
fn end_of_name(text: &str, start: usize) -> Option<usize> {
    let mut current_end = start;
    let mut words = 0;
    while words < 3 {
        let Some(rest) = text
            .get(current_end..)
            .and_then(|rest| rest.strip_prefix(' '))
        else {
            break;
        };
        let Some(first) = rest.chars().next() else {
            break;
        };
        if !first.is_uppercase() {
            break;
        }
        let length = person_word_len(rest);
        if rest[..length].chars().filter(|c| c.is_alphabetic()).count() < 2 {
            break;
        }
        current_end += 1 + length;
        words += 1;
    }
    (words > 0).then_some(current_end)
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Greedily keep the highest priority, then longest, non-overlapping spans.
fn resolve(mut candidates: Vec<Detection>) -> Vec<Detection> {
    candidates.sort_by(|left, right| {
        left.kind
            .priority()
            .cmp(&right.kind.priority())
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
            .then_with(|| left.start.cmp(&right.start))
    });

    let mut accepted: Vec<Detection> = Vec::new();
    for candidate in candidates {
        let overlaps = accepted
            .iter()
            .any(|kept| candidate.start < kept.end && kept.start < candidate.end);
        if !overlaps {
            accepted.push(candidate);
        }
    }

    accepted.sort_by_key(|detection| detection.start);
    accepted
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn kinds(detector: &Detector, text: &str) -> Vec<Kind> {
        detector.scan(text).into_iter().map(|d| d.kind).collect()
    }

    fn values(detector: &Detector, text: &str) -> Vec<String> {
        detector.scan(text).into_iter().map(|d| d.value).collect()
    }

    #[test]
    fn detects_each_supported_category() {
        let detector = Detector::default();

        assert_eq!(
            values(&detector, "reach me at a.b+c@example.co.uk."),
            ["a.b+c@example.co.uk"]
        );
        assert_eq!(
            values(&detector, "ssn 123-45-6789 on file"),
            ["123-45-6789"]
        );
        assert_eq!(
            values(&detector, "card 4111 1111 1111 1111 ok"),
            ["4111 1111 1111 1111"]
        );
        assert_eq!(
            values(&detector, "host 192.168.1.20 down"),
            ["192.168.1.20"]
        );
        assert_eq!(values(&detector, "born 1988-04-02 in Ohio"), ["1988-04-02"]);
        assert_eq!(
            values(&detector, "ships to 1600 Pennsylvania Ave now"),
            ["1600 Pennsylvania Ave"]
        );
        assert_eq!(
            values(&detector, "key sk-ant-api03-abcdefghijklmnop here"),
            ["sk-ant-api03-abcdefghijklmnop"]
        );
        assert_eq!(
            values(&detector, "ping Alice Johnson today"),
            ["Alice Johnson"]
        );
        assert_eq!(
            values(&detector, "my name is Quentin Farsworth"),
            ["Quentin Farsworth"]
        );
    }

    #[test]
    fn detects_pat_tokens_and_pem_private_keys() {
        let detector = Detector::default();

        // `pat_` tokens, but not snake_case source identifiers sharing the prefix.
        assert_eq!(
            values(&detector, "token pat_A1b2C3d4E5f6G7h8I9j0K1 here"),
            ["pat_A1b2C3d4E5f6G7h8I9j0K1"]
        );
        assert!(values(&detector, "let pat_matcher_state = 1;").is_empty());

        // Stripe live and test secrets.
        assert_eq!(
            values(&detector, "sk_live_51H8xQzJK9mNpQrStUvWxYz0123456789"),
            ["sk_live_51H8xQzJK9mNpQrStUvWxYz0123456789"]
        );

        // A whole PEM block is one detection, regardless of the file it came
        // from: content, not extension, is what marks it as key material.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nb2FuZHNvb24=\n-----END RSA PRIVATE KEY-----";
        assert_eq!(values(&detector, &format!("key:\n{pem}\ndone")), [pem]);

        // A bare armor line still names a key when the block is truncated.
        assert_eq!(
            values(&detector, "starts -----BEGIN PRIVATE KEY----- then stops"),
            ["-----BEGIN PRIVATE KEY-----"]
        );

        // Every armor variant in common use, not just RSA.
        for label in ["RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED ", ""] {
            let armor = format!("-----BEGIN {label}PRIVATE KEY-----");
            assert_eq!(
                values(&detector, &format!("k {armor} z")),
                [armor.as_str()],
                "{armor}"
            );
        }

        // Round-trip: a redacted key comes back byte-identical.
        let original = format!("deploy with\n{pem}\n");
        let anonymized = detector.anonymize(&original);
        assert!(!anonymized.text.contains("MIIEowIBAAKCAQEA"));
        assert_eq!(restore(&anonymized.text, &anonymized.mappings), original);
    }

    #[test]
    fn detects_vendor_key_prefixes() {
        let detector = Detector::default();

        for key in [
            "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",
            "npm_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
            "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            "dop_v1_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
            "dapi0123456789abcdef0123456789abcdef",
            "ASIAQRSTUVWXYZ234567",
        ] {
            assert_eq!(values(&detector, &format!("key {key} end")), [key], "{key}");
        }
    }

    #[test]
    fn detects_labeled_secrets_without_a_known_prefix() {
        let detector = Detector::default();

        // The value is taken, the label stays readable for the model.
        assert_eq!(
            values(&detector, "password: hunter2CorrectHorse!"),
            ["hunter2CorrectHorse!"]
        );
        assert_eq!(
            values(&detector, r#"{"client_secret": "s3rv1ce-w1de-value"}"#),
            ["s3rv1ce-w1de-value"]
        );
        assert_eq!(
            values(&detector, "API_KEY=ZmFrZS12YWx1ZS1mb3ItdGVzdA"),
            ["ZmFrZS12YWx1ZS1mb3ItdGVzdA"]
        );

        // Prose about secrets is not a secret: no separator, nothing taken.
        assert!(values(&detector, "rotate the password before Friday").is_empty());

        // Environment references, placeholders, and type annotations name no
        // value, so they stay readable.
        assert!(values(&detector, "-H \"x-api-key: $ANTHROPIC_API_KEY\"").is_empty());
        assert!(values(&detector, "api_key: <your-key-here>").is_empty());
        assert!(values(&detector, "private_key: Option<String>").is_empty());
    }

    #[test]
    fn detects_phone_formats() {
        let detector = Detector::default();

        for number in [
            // North American, dialable and placeholder alike.
            "+1 (415) 555-2671",
            "415-555-2671",
            "415.555.2671",
            "(415) 555-2671",
            "000-000-0000",
            // 10 and 11 bare digits, with and without a `+`.
            "4155552671",
            "14155552671",
            "+14155552671",
            // Other international prefixes.
            "+44 20 7946 0958",
            "+33 6 12 34 56 78",
            "+84 91 234 56 78",
            "+84 912 345 678",
            "0912345678",
        ] {
            assert_eq!(
                values(&detector, &format!("call {number} now")),
                [number],
                "failed to detect {number}"
            );
        }
    }

    #[test]
    fn detects_names_outside_the_dictionary_after_a_trigger_word() {
        let detector = Detector::default();

        assert_eq!(
            values(&detector, "contact Zephyr Quixotic"),
            ["Zephyr Quixotic"]
        );
        assert_eq!(values(&detector, "cc: Hiroshi Tanaka"), ["Hiroshi Tanaka"]);
        assert_eq!(values(&detector, "regards, Priya Sharma"), ["Priya Sharma"]);
        // Present in the dictionary, so no trigger word is needed.
        assert_eq!(values(&detector, "ping Xiulan Wang today"), ["Xiulan Wang"]);
        assert_eq!(
            values(&detector, "ping Dmitri Volkov today"),
            ["Dmitri Volkov"]
        );
    }

    #[test]
    fn leaves_capitalized_technical_prose_alone() {
        let detector = Detector::default();

        for text in [
            "Deploy to New York using Docker Compose",
            "Error: Connection Refused from Redis Cluster",
            "The Rust Foundation released Cargo Nightly",
            "Meeting on Monday March about the migration",
            "North America and South Africa regions",
            "Pull Request Merged by GitHub Actions",
            "port 8080 timeout 30000 retries 5",
            "version 1.2.3 build 20240101",
        ] {
            assert!(
                kinds(&detector, text).is_empty(),
                "false positive in {text}"
            );
        }
    }

    #[test]
    fn rejects_lookalikes() {
        let detector = Detector::default();

        // Fails Luhn, and too short/structureless to be a valid phone number.
        assert!(kinds(&detector, "order 1234567812345678 shipped").is_empty());
        assert!(kinds(&detector, "build 999.999.999.999 failed").is_empty());
        assert!(kinds(&detector, "count 12345 items").is_empty());
        // A bare dictionary name without a surname stays untouched.
        assert!(kinds(&detector, "grace under pressure, Grace").is_empty());
    }

    #[test]
    fn home_paths_lose_the_account_name_and_keep_the_rest() {
        let detector = Detector::default();

        // The username is the leak; the path below it is ordinary context.
        for text in [
            "edit /home/sawyer/.bashrc please",
            "edit /var/home/sawyer/.bashrc please",
            "edit /Users/Sawyer/.bashrc please",
        ] {
            let anonymized = detector.anonymize(text);
            assert!(
                !anonymized.text.contains("sawyer") && !anonymized.text.contains("Sawyer"),
                "leaked the account name: {}",
                anonymized.text
            );
            assert!(anonymized.text.contains("/.bashrc"), "{anonymized:?}");
            assert_eq!(restore(&anonymized.text, &anonymized.mappings), text);
        }

        // Trailing punctuation stays outside the token, so the sentence survives.
        assert_eq!(
            values(&detector, "fix /home/sawyer."),
            ["/home/sawyer".to_owned()]
        );
        // A relative path names no account.
        assert!(kinds(&detector, "run ./home/../bin/tool").is_empty());
    }

    #[test]
    fn configured_literals_are_redacted_whole_word() {
        let configured = ["acme-corp".to_owned(), "Quentin Farsworth".to_owned()];
        let detector = Detector::default().with_redactions(&configured);

        let anonymized = detector.anonymize("Invoice from Acme-Corp, cc Quentin Farsworth");
        assert!(!anonymized.text.contains("Acme"), "{anonymized:?}");
        assert!(!anonymized.text.contains("Farsworth"), "{anonymized:?}");
        assert_eq!(
            restore(&anonymized.text, &anonymized.mappings),
            "Invoice from Acme-Corp, cc Quentin Farsworth"
        );

        // Whole-word only: a configured value must not fire inside a longer word.
        assert!(
            detector
                .scan("the pacman game and an acronym")
                .iter()
                .all(|detection| detection.kind != Kind::Custom),
        );
        // Unconfigured text is untouched, and so is a one-character value.
        assert!(
            Detector::default()
                .with_redactions(&["x".to_owned()])
                .scan("x marks the spot")
                .is_empty(),
        );
    }

    #[test]
    fn loopback_and_unspecified_addresses_are_not_redacted() {
        let detector = Detector::default();

        for address in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST] {
            let text = format!("bind {address} port 8100");
            assert!(kinds(&detector, &text).is_empty(), "redacted {address}");
        }

        // A routable address is still redacted. TEST-NET-3, never routed.
        let routable = Ipv4Addr::new(203, 0, 113, 5).to_string();
        assert_eq!(
            values(&detector, &format!("host {routable} down")),
            [routable]
        );
    }

    #[test]
    fn resolves_overlapping_candidates_by_priority() {
        let detector = Detector::default();
        let text = "card 4111 1111 1111 1111 today";

        assert_eq!(kinds(&detector, text), [Kind::CreditCard]);
    }

    #[test]
    fn repeated_values_share_one_token() {
        let detector = Detector::default();
        let first = detector.anonymize("mail a@example.com");
        let second = detector.anonymize("again a@example.com");

        assert_eq!(first.mappings.len(), 1);
        let token = first.mappings.keys().next().expect("one mapping");
        assert!(second.text.contains(token.as_str()));
    }

    #[test]
    fn anonymize_handles_unicode_and_round_trips() {
        let detector = Detector::default();
        let original = "Chào Alice Johnson — thư a@example.com, số +1 (415) 555-2671 ✅";
        let anonymized = detector.anonymize(original);

        assert!(!anonymized.text.contains("a@example.com"));
        assert!(!anonymized.text.contains("Alice Johnson"));
        assert!(anonymized.text.contains('✅'));
        assert_eq!(restore(&anonymized.text, &anonymized.mappings), original);
    }

    #[test]
    fn restore_recognizes_hash_despite_model_formatting() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "a@example.com".to_owned(),
        )]);

        for text in [
            "[EMAIL_0123456789ab]",
            "EMAIL_0123456789ab",
            "CONTACT:0123456789ab",
            "REDACTED-0123456789ab",
            "[0123456789ab]",
            "0123456789ab",
            "0123456789AB",
        ] {
            assert_eq!(
                restore(text, &mappings),
                "a@example.com",
                "failed for {text}"
            );
        }
    }

    #[test]
    fn restore_replaces_known_hash_inside_model_text() {
        let mappings = HashMap::from([(
            "[CARD_0123456789ab]".to_owned(),
            "4111 1111 1111 1111".to_owned(),
        )]);

        assert_eq!(
            restore("Card: ref=0123456789ab.", &mappings),
            "Card: ref=4111 1111 1111 1111."
        );
    }

    #[test]
    fn restore_leaves_unknown_and_nearby_hashes_alone() {
        let mappings = HashMap::from([(
            "[EMAIL_0123456789ab]".to_owned(),
            "a@example.com".to_owned(),
        )]);
        let text = "[NAME_ffffffffffff] 0123456789aa 0123456789a abcdef0123456789ac";

        assert_eq!(restore(text, &mappings), text);
        assert_eq!(restore("plain text", &mappings), "plain text");
        assert_eq!(
            restore("[EMAIL_0123456789ab]", &HashMap::new()),
            "[EMAIL_0123456789ab]"
        );
    }

    #[test]
    fn restore_does_not_rescan_original_values() {
        let mappings = HashMap::from([
            (
                "[EMAIL_0123456789ab]".to_owned(),
                "original-fedcba987654".to_owned(),
            ),
            ("[NAME_fedcba987654]".to_owned(), "wrong".to_owned()),
        ]);

        assert_eq!(restore("0123456789ab", &mappings), "original-fedcba987654");
    }

    #[test]
    fn restore_fails_closed_for_colliding_hashes() {
        let mappings = HashMap::from([
            ("[EMAIL_0123456789ab]".to_owned(), "first".to_owned()),
            ("[NAME_0123456789ab]".to_owned(), "second".to_owned()),
        ]);

        assert_eq!(restore("0123456789ab", &mappings), "0123456789ab");
        assert_eq!(restore("[EMAIL_0123456789ab]", &mappings), "first");
    }

    #[test]
    fn text_without_pii_is_unchanged() {
        let detector = Detector::default();
        let anonymized = detector.anonymize("summarize the quarterly report");

        assert_eq!(anonymized.text, "summarize the quarterly report");
        assert!(anonymized.mappings.is_empty());
    }

    #[test]
    fn debug_detect_token() {
        let detector = Detector::default();
        let text = "reach me at [EMAIL_9c0343c78a5f].";
        let detections = detector.scan(text);
        println!("\nScanning: '{}'", text);
        for d in &detections {
            println!(
                "  Found: kind={:?}, value='{}', span=[{}..{}]",
                d.kind, d.value, d.start, d.end
            );
        }
        if detections.is_empty() {
            println!("  NO detections!");
        }
    }
}
