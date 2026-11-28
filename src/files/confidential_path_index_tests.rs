//! DE: Gegenproben und tatsächliche Knoten-/Owner-Sperren des vertraulichen Index.
//! EN: Reference comparisons and actual confidential index node/owner locks.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::hardening::memlock;
use std::collections::BTreeMap;

fn check_balance(state: &State, root: Option<usize>) -> u8 {
    let Some(root) = root else { return 0 };
    let node = &state.nodes.expose()[root];
    let left = check_balance(state, node.left);
    let right = check_balance(state, node.right);
    assert!(left.abs_diff(right) <= 1);
    assert_eq!(node.height, left.max(right) + 1);
    if let Some(left) = node.left {
        assert!(state.nodes.expose()[left].key < node.key);
    }
    if let Some(right) = node.right {
        assert!(state.nodes.expose()[right].key > node.key);
    }
    node.height
}

pub(super) fn assert_storage_locked(index: &Index) {
    let state = index.0.as_ref().unwrap().get();
    let start = std::ptr::from_ref(state).addr();
    assert!(memlock::is_locked(start));
    assert!(memlock::is_locked(start + size_of::<State>() - 1));
    let nodes = state.nodes.expose();
    let start = nodes.as_ptr().addr();
    assert!(memlock::is_locked(start));
    assert!(memlock::is_locked(start + size_of_val(nodes) - 1));
    for node in nodes.iter().take(state.used) {
        let key = node.key.as_ref().unwrap();
        key.assert_owner_locked();
        assert!(memlock::is_locked(key.bytes().as_ptr().addr()));
    }
}

#[test]
fn ascending_descending_and_permuted_growth_match_ordered_reference() {
    for order in 0..3 {
        let mut index = Index::default();
        let mut reference = BTreeMap::new();
        for i in 0..257 {
            let n = match order {
                0 => i,
                1 => 256 - i,
                _ => (i * 97) % 257,
            };
            let name = format!("name-{n:04}");
            let file = n % 3 == 0;
            index
                .insert(ConfidentialText::from_text(&name).unwrap(), file)
                .unwrap();
            reference.insert(name, file);
            let state = index.0.as_ref().unwrap().get();
            assert_eq!(state.used, reference.len());
            assert!(check_balance(state, state.root) <= 10);
            for (key, file) in &reference {
                assert_eq!(index.get(key.as_bytes()), Some(*file));
            }
        }
        for n in 0..300 {
            let query = format!("name-{n:04}a");
            let expected = reference
                .range(query.clone()..)
                .next()
                .map(|(key, _)| key.as_bytes());
            assert_eq!(index.lower_bound(query.as_bytes()), expected);
        }
        assert_storage_locked(&index);
    }
}

#[test]
fn duplicate_and_prefix_queries_preserve_tree_and_confidential_ownership() {
    let mut index = Index::default();
    index
        .insert(ConfidentialText::from_text("a/b").unwrap(), true)
        .unwrap();
    index
        .insert(ConfidentialText::from_text("a-").unwrap(), false)
        .unwrap();
    assert!(index.has_prefix(b"a/"));
    assert!(!index.has_prefix(b"ab/"));
    assert!(
        index
            .insert(ConfidentialText::from_text("a/b").unwrap(), false)
            .is_err()
    );
    assert_eq!(index.len(), 2);
    assert_eq!(index.get(b"a/b"), Some(true));
    assert_storage_locked(&index);
}

#[test]
fn concrete_node_fields_wipe_while_record_allocation_remains_locked() {
    let mut index = Index::default();
    index
        .insert(ConfidentialText::from_text("private-name").unwrap(), true)
        .unwrap();
    let state = index.0.as_mut().unwrap().get_mut();
    let node = &mut state.nodes.expose_mut()[0];
    let address = std::ptr::from_ref(node).addr();
    assert!(memlock::is_locked(address));
    node.zeroize();
    assert!(node.key.is_none());
    assert!(node.left.is_none() && node.right.is_none());
    assert_eq!(node.height, 0);
    assert!(!node.file);
    assert!(memlock::is_locked(address));
}
