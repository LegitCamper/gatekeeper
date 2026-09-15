//! Name cases from adversarial review: missed casing/scripts and common-word false
//! positives. Names outside an explicit person context still require a dictionary
//! given name plus a surname.

use gatekeeper::detector::{Detector, Kind};

fn names(text: &str) -> Vec<String> {
    Detector::default()
        .scan(text)
        .into_iter()
        .filter(|found| found.kind == Kind::Name)
        .map(|found| found.value)
        .collect()
}

#[test]
fn explicit_person_context_covers_reported_names() {
    for (text, expected) in [
        ("patient María José García called", "María José García"),
        ("patient Søren Kierkegaard called", "Søren Kierkegaard"),
        ("patient ALICE JOHNSON called", "ALICE JOHNSON"),
        ("patient alice johnson called", "alice johnson"),
        ("patient Wanjiru Kamau called", "Wanjiru Kamau"),
        ("patient Oluwaseun Adebayo called", "Oluwaseun Adebayo"),
        ("patient Jean-Luc Picard called", "Jean-Luc Picard"),
        ("my name is María José García", "María José García"),
        ("my name is alice johnson and I called", "alice johnson"),
        ("My name is Alice.", "Alice"),
        ("Alice Johnson", "Alice Johnson"),
    ] {
        assert_eq!(names(text), [expected], "missed or split: {text:?}");
    }
}

#[test]
fn dictionary_names_need_a_surname() {
    for text in [
        "Ruby is installed",
        "Jordan is a country",
        "Frank discussion",
        "Max retries is five",
        "Sandy soil",
        "Dell laptop",
    ] {
        assert!(
            names(text).is_empty(),
            "false positive: {text:?} -> {:?}",
            names(text)
        );
    }
}

#[test]
fn reported_name_phrases_are_not_people_without_context() {
    for text in [
        "Robin Hood is a legend",
        "Sandy Beach Elementary reopened",
        "The name is required",
        "Contact customer support",
    ] {
        assert!(
            names(text).is_empty(),
            "false positive: {text:?} -> {:?}",
            names(text)
        );
    }
}

#[test]
fn capitalized_dictionary_name_with_surname_still_works() {
    assert_eq!(names("Alice Johnson called"), ["Alice Johnson"]);
    assert_eq!(names("Jean-Luc Picard called"), ["Jean-Luc Picard"]);
}
