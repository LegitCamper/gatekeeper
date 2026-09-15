//! PII detection, anonymization, and restoration.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::Ipv4Addr;
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
            Self::Name => 8,
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
const NAME_TRIGGERS: &[&str] = &["attn", "cc", "contact", "regards", "signed", "sincerely"];

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
                  | AKIA[0-9A-Z]{16}
                  | gh[posur]_[A-Za-z0-9]{20,}
                  | github_pat_[A-Za-z0-9_]{20,}
                  | xox[baprs]-[A-Za-z0-9-]{10,}
                  | AIza[0-9A-Za-z_-]{35}
                ",
                )
                .expect("api key pattern is valid"),
            ),
            (
                Kind::Email,
                Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
                    .expect("email pattern is valid"),
            ),
            (
                Kind::CreditCard,
                Regex::new(r"\d(?:[ -]?\d){11,18}").expect("card pattern is valid"),
            ),
            (
                Kind::Ssn,
                Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn pattern is valid"),
            ),
            (
                Kind::Ip,
                Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("ip pattern is valid"),
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
                Kind::Name,
                Regex::new(r"(?:[Mm]y name is|[Nn]ame:|Mr\.|Mrs\.|Ms\.|Dr\.) ?([A-Z][a-z]+(?: [A-Z][a-z]+)?)")
                    .expect("name context pattern is valid"),
            ),
            (
                // A trigger word introducing a capitalized pair, catching names
                // that are absent from the given-name dictionary.
                Kind::Name,
                Regex::new(&format!(
                    r"(?i:\b(?:{})\b)[:,]? +(?-i:([A-Z][a-z]+ [A-Z][a-z]+))",
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
            tokens: RandomState::new(),
        }
    }
}

impl Detector {
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
        resolve(candidates)
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

            // Try to extend name with following capitalized words (surnames, middle names)
            let end = match end_of_name(text, given_end) {
                Some(e) => e,      // Has following capitalized word(s)
                None => given_end, // No following word, just use given name
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

            if cursor + DIGEST_LEN <= full_text.len()
                && bytes[cursor..cursor + DIGEST_LEN]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
            {
                let digest = full_text[cursor..cursor + DIGEST_LEN].to_ascii_lowercase();
                if let Some(Some(original)) = self.digests.get(&digest) {
                    let decorated = decoration_start(&full_text, cursor);
                    let bracketed = cursor > 0
                        && bytes[cursor - 1] == b'['
                        && bytes.get(cursor + DIGEST_LEN) == Some(&b']');
                    let start = decorated.or_else(|| bracketed.then(|| cursor - 1));
                    if let Some(start) = start {
                        let decoration = &full_text[start..cursor];
                        if output.ends_with(decoration) {
                            output.truncate(output.len() - decoration.len());
                        }
                    }
                    output.push_str(original);
                    cursor += DIGEST_LEN;
                    if start.is_some() {
                        if bytes.get(cursor) == Some(&b']') {
                            cursor += 1;
                        } else if cursor == full_text.len() {
                            carry.skip_closing_bracket = true;
                        }
                    }
                    continue;
                }
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
                || ((*start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric())
                    && token_decoration_prefix(suffix, digests))
        })
        .map_or(0, |start| text.len() - start)
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

/// Reject candidates that only look like the category, and tighten spans.
fn validate(kind: Kind, text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let value = &text[start..end];
    match kind {
        Kind::CreditCard => is_payment_card(value).then_some((start, end)),
        // Loopback and `0.0.0.0` identify nobody; tokenizing them breaks config
        // and bind-address round-trips.
        Kind::Ip => value
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|address| !(address.is_loopback() || address.is_unspecified()))
            .map(|_| (start, end)),
        Kind::Phone => {
            let preceded_by_word = start > 0 && is_word_byte(text.as_bytes()[start - 1]);
            (!preceded_by_word && is_phone(value)).then_some((start, end))
        }
        // Reject when any word of the pair is a calendar or direction word.
        Kind::Name => value
            .split(' ')
            .all(|word| !NAME_DENY.contains(&word))
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
    sum % 10 == 0
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

/// End position of capitalized word(s) following position, or None if not capitalized.
/// Captures multi-word names like "Joe Smith" or "Joe Marie Smith".
fn end_of_name(text: &str, start: usize) -> Option<usize> {
    let rest = text.get(start..)?;
    let rest = rest.strip_prefix(' ')?;
    let first_word_start = start + 1;

    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }

    // Find the end of the first capitalized word
    let end = rest
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic())
        .map_or(rest.len(), |(offset, _)| offset);

    // Require at least 2 characters for a valid word
    if end < 2 {
        return None;
    }

    let mut current_end = first_word_start + end;

    // Try to extend with additional capitalized words (middle names, surnames, etc.)
    loop {
        let next_rest = text.get(current_end..)?;
        let next_rest = match next_rest.strip_prefix(' ') {
            Some(r) => r,
            None => break, // No space after current word, stop
        };

        // Check if next word starts with capital
        let mut chars = next_rest.char_indices();
        let (_, first_char) = chars.next()?;
        if !first_char.is_ascii_uppercase() {
            break; // Next word not capitalized, stop
        }

        // Find end of this word
        let next_len = next_rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_alphabetic())
            .map_or(next_rest.len(), |(offset, _)| offset);

        // Require at least 2 characters
        if next_len < 2 {
            break;
        }

        current_end += 1 + next_len; // space + word
    }

    Some(current_end)
}

/// End offset of a `Given Surname` pair, or `None` when no surname follows.
#[allow(dead_code)]
fn surname_end(text: &str, given_end: usize) -> Option<usize> {
    let rest = text.get(given_end..)?;
    let rest = rest.strip_prefix(' ')?;
    let surname_start = given_end + 1;

    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }

    let length = rest
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic())
        .map_or(rest.len(), |(offset, _)| offset);
    (length >= 2).then_some(surname_start + length)
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
