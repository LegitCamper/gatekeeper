//! `split_digest` deletes formatting characters to recover a digest a model broke
//! up. The risk is the inverse: ordinary text whose scattered hex characters get
//! stitched into a token that was never there. These cases must stay untouched.

use std::collections::HashMap;

use gatekeeper::detector::restore;

const DIGEST: &str = "0123456789ab";
const VALUE: &str = "alice@example.com";

fn mappings() -> HashMap<String, String> {
    HashMap::from([(format!("[EMAIL_{DIGEST}]"), VALUE.to_owned())])
}

#[test]
fn prose_is_not_stitched_into_a_digest() {
    let maps = mappings();
    // Each holds the digest's characters in order but separated by text that is
    // not pure formatting, so none should restore.
    let cases = [
        "0 1 2 3 4 5 6 7 8 9 a b c d",      // longer than a digest
        "01 23 45 67 89 a and then b here", // words between groups
        "0123456789abcdef",                 // longer hex run
        "deadbeef0123456789ab",             // digest inside a longer run
        "0123-4567-89ab",                   // `-` is meaningful, not noise
        "0123_4567_89ab",                   // `_` likewise
        "012345      6789ab",               // noise run too long (>3)
        "v0123456789ab",                    // does not start on a boundary
    ];

    for text in cases {
        let out = restore(text, &maps);
        assert!(
            !out.contains(VALUE),
            "stitched a digest out of ordinary text: {text:?} -> {out:?}"
        );
    }
}

#[test]
fn formatting_noise_inside_a_digest_still_recovers() {
    let maps = mappings();
    let d = DIGEST;
    for text in [
        format!("{}**{}**", &d[..6], &d[6..]),
        format!("{} {}", &d[..6], &d[6..]),
        format!("{}\n{}", &d[..6], &d[6..]),
        format!("{}\t{}", &d[..4], &d[4..]),
        format!("`{}` `{}`", &d[..6], &d[6..]),
        d.chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        format!("[EMAIL_{} {}]", &d[..6], &d[6..]),
    ] {
        let out = restore(&text, &maps);
        assert!(
            out.contains(VALUE),
            "left a live hash in the client's view: {text:?} -> {out:?}"
        );
        assert!(
            !out.contains(&d[..6]),
            "hash fragment still reached the client: {text:?} -> {out:?}"
        );
    }
}
