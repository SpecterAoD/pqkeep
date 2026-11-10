#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{LEVELS, Purpose, for_purpose};
use crate::cli::args::ALGORITHMS;
use pqkeep::crypto::KeyAlgorithm;
use pqkeep::security::Lang;

#[test]
fn every_algorithm_appears_exactly_once_with_valid_id() {
    let mut ids: Vec<&str> = LEVELS.iter().map(|l| l.id).collect();
    ids.sort_unstable();
    let mut all = ALGORITHMS.to_vec();
    all.sort_unstable();
    assert_eq!(ids, all);
    for l in LEVELS {
        assert!(
            KeyAlgorithm::from_id(&l.id.to_uppercase()).is_ok(),
            "{}",
            l.id
        );
    }
}

#[test]
fn categories_match_fips_203_204() {
    let cat = |id: &str| LEVELS.iter().find(|l| l.id == id).unwrap().category;
    assert_eq!(
        [cat("ml-kem-512"), cat("ml-kem-768"), cat("ml-kem-1024")],
        [1, 3, 5]
    );
    assert_eq!(
        [cat("ml-dsa-44"), cat("ml-dsa-65"), cat("ml-dsa-87")],
        [2, 3, 5]
    );
    assert_eq!(cat("aes-256"), 5);
}

#[test]
fn each_purpose_has_one_recommendation_shown_first() {
    for p in [Purpose::Encrypt, Purpose::Sign, Purpose::Symmetric] {
        let levels = for_purpose(p);
        assert!(levels[0].recommended, "{p:?}");
        assert_eq!(levels.iter().filter(|l| l.recommended).count(), 1);
    }
}

#[test]
fn labels_name_the_category_in_both_languages() {
    let l = LEVELS[0];
    assert!(l.label(Lang::De).contains("NIST-Kategorie 5"));
    assert!(l.label(Lang::En).contains("NIST category 5"));
}
