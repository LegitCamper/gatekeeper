//! Throwaway adversarial harness: how does `restore` behave on mangled token
//! forms a small model might emit? Not a correctness assertion suite — it prints
//! a table and only fails on the outcomes that are unambiguously bugs.

use std::collections::HashMap;

use gatekeeper::detector::restore;

const DIGEST: &str = "0123456789ab";
const VALUE: &str = "alice@example.com";

fn mappings() -> HashMap<String, String> {
    HashMap::from([(format!("[EMAIL_{DIGEST}]"), VALUE.to_owned())])
}

#[test]
fn mangled_token_forms() {
    let maps = mappings();
    let d = DIGEST;

    // (name, text the model emitted, should the original be recovered?)
    let cases: Vec<(&str, String, bool)> = vec![
        ("canonical", format!("[EMAIL_{d}]"), true),
        ("label-stripped", d.to_owned(), true),
        ("bare-bracket", format!("[{d}]"), true),
        (
            "uppercase-hash",
            format!("[EMAIL_{}]", d.to_uppercase()),
            true,
        ),
        ("colon-sep", format!("EMAIL:{d}"), true),
        ("dash-sep", format!("EMAIL-{d}"), true),
        ("redacted-label", format!("REDACTED_{d}"), true),
        ("contact-label", format!("CONTACT:{d}"), true),
        ("md-bold-hash", format!("**{d}**"), true),
        ("md-code-token", format!("`[EMAIL_{d}]`"), true),
        ("backtick-hash", format!("`{d}`"), true),
        ("hash-in-sentence", format!("The id is {d} ok"), true),
        ("hash-comma", format!("{d},"), true),
        ("hash-period", format!("{d}."), true),
        ("double-token", format!("[EMAIL_{d}] [EMAIL_{d}]"), true),
        ("nested-bracket", format!("[[{d}]]"), true),
        ("lowercase-label", format!("[email_{d}]"), true),
        // Formatting inserted *into* the hash. The characters carry no meaning of
        // their own, so dropping them recovers the digest rather than leaving a
        // live hash in the client's view.
        ("md-bold-split", format!("{}**{}**", &d[..6], &d[6..]), true),
        ("space-in-hash", format!("{} {}", &d[..6], &d[6..]), true),
        ("newline-in-hash", format!("{}\n{}", &d[..6], &d[6..]), true),
        (
            "space-every-char",
            d.chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            true,
        ),
        // Forms that corrupt the hash itself. Restoring these is impossible;
        // the safe outcome is leaving them alone, NOT emitting a wrong value.
        // `-` and `_` stay meaningful inside identifiers, so they are not
        // treated as formatting noise.
        ("hyphen-in-hash", format!("{}-{}", &d[..6], &d[6..]), false),
        ("truncated-hash", d[..11].to_owned(), false),
        ("extra-hex-char", format!("{d}a"), false),
        ("one-digit-changed", format!("{}c", &d[..11]), false),
        ("label-no-separator", format!("EMAIL{d}"), false),
    ];

    println!(
        "\n{:<22} {:<10} {:<9} output",
        "form", "restored", "expected"
    );
    println!("{}", "-".repeat(86));

    let mut surprises = Vec::new();
    for (name, text, expect_restored) in &cases {
        let out = restore(text, &maps);
        let restored = out.contains(VALUE);
        // A leftover 12-hex run that is still the *known* digest means the
        // client sees a hash instead of a value.
        let leaks_hash = out.contains(d) || out.contains(&d.to_uppercase());
        let mark = if restored == *expect_restored {
            ""
        } else {
            " <-- SURPRISE"
        };
        if restored != *expect_restored {
            surprises.push((*name, text.clone(), out.clone(), restored, *expect_restored));
        }
        println!(
            "{:<22} {:<10} {:<9} {:?}{}{}",
            name,
            restored,
            expect_restored,
            out,
            if leaks_hash && !restored {
                "  [HASH REACHES CLIENT]"
            } else {
                ""
            },
            mark
        );
    }

    println!("\n{} surprise(s)", surprises.len());
    for (name, input, output, got, want) in &surprises {
        println!("  {name}: input={input:?} output={output:?} restored={got} expected={want}");
    }

    // The only hard failure: emitting a value for a hash that was corrupted,
    // i.e. restoring something we should not have. Wrong-value output is worse
    // than a visible hash.
    let wrong: Vec<_> = surprises
        .iter()
        .filter(|(_, _, _, got, want)| *got && !*want)
        .map(|(name, ..)| *name)
        .collect();
    assert!(wrong.is_empty(), "restored a corrupted hash: {wrong:?}");
}

/// Multi-token text: does one unrestorable token break its neighbours?
#[test]
fn mixed_known_and_unknown_tokens() {
    let maps = mappings();
    let unknown = "[NAME_ffffffffffff]";
    let text = format!("[EMAIL_{DIGEST}] wrote to {unknown} about [EMAIL_{DIGEST}]");
    let out = restore(&text, &maps);

    println!("\nmixed: {out:?}");
    assert_eq!(out.matches(VALUE).count(), 2, "both known tokens restore");
    assert!(out.contains(unknown), "unknown token left intact");
}

/// A digest that appears inside a longer hex run must not be restored: that run
/// is a commit sha or checksum, not our token.
#[test]
fn digest_inside_longer_hex_run_is_left_alone() {
    let maps = mappings();
    for text in [
        format!("deadbeef{DIGEST}"),
        format!("{DIGEST}deadbeef"),
        format!("sha256:{DIGEST}0123456789abcdef"),
    ] {
        let out = restore(&text, &maps);
        println!("longer-run {text:?} -> {out:?}");
        assert!(
            !out.contains(VALUE),
            "restored a digest embedded in a longer hex run: {text}"
        );
    }
}

/// JSON object *keys* are not walked by `restore_json`, so a token a model
/// emits as a key stays a token in the client's view.
#[test]
fn token_in_json_object_key() {
    let maps = mappings();
    let key_token = format!("[EMAIL_{DIGEST}]");
    let body = serde_json::json!({ key_token: "value" });
    let text = serde_json::to_string(&body).expect("serialized");
    let out = restore(&text, &maps);
    println!("\nkey-token raw restore: {out}");
    // restore() on the raw string does handle it; the gap is restore_json, which
    // is what the proxy actually uses on JSON responses.
    assert!(out.contains(VALUE));
}
