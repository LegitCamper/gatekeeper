//! Formats that reached the upstream in plaintext during the adversarial review,
//! plus the lookalikes each new pattern must not claim.

use gatekeeper::detector::{Detector, Kind};

fn kinds(text: &str) -> Vec<Kind> {
    Detector::default()
        .scan(text)
        .into_iter()
        .map(|found| found.kind)
        .collect()
}

fn detected(text: &str, kind: Kind) -> bool {
    kinds(text).contains(&kind)
}

#[test]
fn newly_covered_secret_formats_are_detected() {
    // Fixture credentials: structurally valid, not real.
    let cases = [
        ("glpat-ABCDEFGHIJKLMNOPQRST", Kind::ApiKey),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            Kind::ApiKey,
        ),
        (
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Kind::ApiKey,
        ),
        (
            "AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
            Kind::ApiKey,
        ),
        (
            "AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
            Kind::ApiKey,
        ),
    ];
    for (value, kind) in cases {
        assert!(
            detected(&format!("token {value} rotated"), kind),
            "undetected: {value}"
        );
    }
}

#[test]
fn unformatted_ssn_is_detected_with_context() {
    for text in [
        "ssn 123456789 on file",
        "SSN: 123456789",
        "ssn 123 45 6789 on file",
        "social security number 123456789",
        "Social Security: 123-45-6789",
        "ssn 123.45.6789 on file",
    ] {
        assert!(detected(text, Kind::Ssn), "undetected ssn: {text:?}");
    }
}

/// Nine bare digits are ordinary data. Without an SSN cue nearby they must not be
/// redacted, or every order number and zip+4 becomes a token.
#[test]
fn bare_nine_digit_runs_are_not_ssns() {
    for text in [
        "order 123456789 shipped",
        "invoice 987654321 paid",
        "part 123 45 6789 in stock",
        "zip 12345 6789",
    ] {
        assert!(
            !detected(text, Kind::Ssn),
            "false positive ssn: {text:?} -> {:?}",
            kinds(text)
        );
    }
}

#[test]
fn obfuscated_emails_and_ips_are_detected() {
    for text in [
        "mail alice\u{200b}@example.com now",
        "mail alice＠example.com now",
        "mail alice@\u{200d}example.com now",
        "mail alice@exa\u{200b}mple.com now",
        "mail alice@example.c\u{200b}om now",
    ] {
        assert!(detected(text, Kind::Email), "undetected email: {text:?}");
    }
    for text in [
        "host 203.0.113[.]55 down",
        "host 203(.)0(.)113(.)55 down",
        "host 203[.]0.113(.)55 down",
    ] {
        assert!(detected(text, Kind::Ip), "undetected ip: {text:?}");
    }
}

#[test]
fn ipv6_addresses_are_detected() {
    for text in [
        "host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 down",
        "host 2001:db8:85a3::8a2e:370:7334 down",
        "peer fe80::1ff:fe23:4567:890a responded",
        "peer ::dead:beef responded",
        "peer ::ffff:192.0.2.128 responded",
        "peer 2001:db8:: responded",
    ] {
        assert!(detected(text, Kind::Ip), "undetected ipv6: {text:?}");
    }
}

/// The IPv6 pattern sits next to timestamps, ratios, and code. Those must stay
/// untouched, and loopback stays exempt so bind addresses round-trip.
#[test]
fn ipv6_lookalikes_are_not_detected() {
    for text in [
        "at 12:30:45 today",
        "ratio 1:2:3:4 observed",
        "bind ::1 for tests",
        "listen on :: for tests",
        "time 2024-01-01T00:00:00Z",
        "range a:b:c:d:e:f:g:h",
    ] {
        assert!(
            !detected(text, Kind::Ip),
            "false positive ip: {text:?} -> {:?}",
            kinds(text)
        );
    }
}
