//! DE: Balancierter Pfadindex mit vor Befüllung gesperrten Knoten.
//! EN: Balanced path index with nodes locked before population.

use super::{ConfidentialText, paths::MAX_ENTRIES};
use crate::crypto::secret_workspace::SecretWorkspace;
use crate::crypto::{secret_buffer::SecretBuffer, secret_state::SecretState};
use crate::{Error, Result};
use std::cmp::Ordering;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default)]
struct Node {
    key: Option<ConfidentialText>,
    left: Option<usize>,
    right: Option<usize>,
    height: u8,
    file: bool,
}

impl Zeroize for Node {
    fn zeroize(&mut self) {
        self.key.take();
        self.left.zeroize();
        self.right.zeroize();
        self.height.zeroize();
        self.file.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBuffer<Node> {}

struct State {
    nodes: SecretWorkspace<Node>,
    root: Option<usize>,
    used: usize,
}

impl Drop for State {
    fn drop(&mut self) {
        self.nodes.zeroize();
        self.root.zeroize();
        self.used.zeroize();
    }
}
impl ZeroizeOnDrop for State {}

/// DE: Auch Baumwurzel und Belegung bleiben im gesperrten Zustand.
/// EN: Tree root and occupancy also remain in protected state.
#[derive(Default)]
pub(super) struct Index(Option<SecretState<State>>);

impl Index {
    pub(super) fn get(&self, key: &[u8]) -> Option<bool> {
        let state = self.0.as_ref()?.get();
        let mut next = state.root;
        while let Some(index) = next {
            let node = &state.nodes.expose()[index];
            match key.cmp(node.key.as_ref()?.bytes()) {
                Ordering::Equal => return Some(node.file),
                Ordering::Less => next = node.left,
                Ordering::Greater => next = node.right,
            }
        }
        None
    }

    pub(super) fn has_prefix(&self, prefix: &[u8]) -> bool {
        self.lower_bound(prefix)
            .is_some_and(|key| key.starts_with(prefix))
    }

    fn lower_bound(&self, key: &[u8]) -> Option<&[u8]> {
        let state = self.0.as_ref()?.get();
        let (mut next, mut candidate) = (state.root, None);
        while let Some(index) = next {
            let node = &state.nodes.expose()[index];
            let text = node.key.as_ref()?.bytes();
            if text < key {
                next = node.right;
            } else {
                candidate = Some(text);
                next = node.left;
            }
        }
        candidate
    }

    pub(super) fn insert(&mut self, key: ConfidentialText, file: bool) -> Result<()> {
        if self.get(key.bytes()).is_some() {
            return Err(Error::InvalidInput { field: "path" });
        }
        if self.0.is_none() {
            self.0 = Some(SecretState::new(State {
                nodes: SecretWorkspace::zeroed(16)?,
                root: None,
                used: 0,
            })?);
        }
        let state = self.0.as_mut().ok_or(Error::MemoryLock)?.get_mut();
        state.reserve()?;
        let index = state.used;
        let slot = &mut state.nodes.expose_mut()[index];
        slot.key = Some(key);
        slot.file = file;
        slot.height = 1;
        state.used += 1;
        state.root = Some(state.insert_at(state.root, index));
        Ok(())
    }
}

impl State {
    fn reserve(&mut self) -> Result<()> {
        if self.used < self.nodes.expose().len() {
            return Ok(());
        }
        let limit = usize::try_from(MAX_ENTRIES).map_err(|_| Error::MemoryLock)?;
        let capacity = self.used.saturating_mul(2).min(limit);
        if capacity <= self.used {
            return Err(Error::InvalidInput { field: "entries" });
        }
        let mut next = SecretWorkspace::<Node>::zeroed(capacity)?;
        // DE: Fallible Kopien nur zwischen gesperrten Zielen; alter Baum bleibt bei Fehler gültig.
        // EN: Fallible copies only into locked storage; errors leave the old tree intact.
        for (old, new) in self.nodes.expose().iter().zip(next.expose_mut()) {
            new.key = old
                .key
                .as_ref()
                .map(ConfidentialText::try_duplicate)
                .transpose()?;
            new.left = old.left;
            new.right = old.right;
            new.height = old.height;
            new.file = old.file;
        }
        self.nodes = next;
        Ok(())
    }

    fn height(&self, index: Option<usize>) -> u8 {
        index.map_or(0, |i| self.nodes.expose()[i].height)
    }

    fn refresh(&mut self, index: usize) {
        let node = &self.nodes.expose()[index];
        let height = self.height(node.left).max(self.height(node.right)) + 1;
        self.nodes.expose_mut()[index].height = height;
    }

    fn rotate_left(&mut self, root: usize, right: usize) -> usize {
        self.nodes.expose_mut()[root].right = self.nodes.expose()[right].left;
        self.nodes.expose_mut()[right].left = Some(root);
        self.refresh(root);
        self.refresh(right);
        right
    }

    fn rotate_right(&mut self, root: usize, left: usize) -> usize {
        self.nodes.expose_mut()[root].left = self.nodes.expose()[left].right;
        self.nodes.expose_mut()[left].right = Some(root);
        self.refresh(root);
        self.refresh(left);
        left
    }

    fn balance(&mut self, root: usize) -> usize {
        self.refresh(root);
        let node = &self.nodes.expose()[root];
        let (left, right) = (node.left, node.right);
        if self.height(left) > self.height(right) + 1 {
            if let Some(mut left) = left {
                let node = &self.nodes.expose()[left];
                if self.height(node.right) > self.height(node.left)
                    && let Some(right) = node.right
                {
                    left = self.rotate_left(left, right);
                    self.nodes.expose_mut()[root].left = Some(left);
                }
                return self.rotate_right(root, left);
            }
        } else if self.height(right) > self.height(left) + 1
            && let Some(mut right) = right
        {
            let node = &self.nodes.expose()[right];
            if self.height(node.left) > self.height(node.right)
                && let Some(left) = node.left
            {
                right = self.rotate_right(right, left);
                self.nodes.expose_mut()[root].right = Some(right);
            }
            return self.rotate_left(root, right);
        }
        root
    }

    fn insert_at(&mut self, root: Option<usize>, added: usize) -> usize {
        let Some(root) = root else { return added };
        let nodes = self.nodes.expose();
        // DE: Nur bereits befüllte Indizes erreichbar; keine privaten Knoten als Wert bewegen.
        // EN: Only populated indices are reachable; never move a private node by value.
        if nodes[added].key < nodes[root].key {
            let child = self.insert_at(nodes[root].left, added);
            self.nodes.expose_mut()[root].left = Some(child);
        } else {
            let child = self.insert_at(nodes[root].right, added);
            self.nodes.expose_mut()[root].right = Some(child);
        }
        self.balance(root)
    }
}

#[cfg(test)]
#[path = "confidential_path_index_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "confidential_path_index_denial_tests.rs"]
mod denial_tests;

#[cfg(test)]
impl Index {
    pub(super) fn iter(&self) -> impl Iterator<Item = &ConfidentialText> {
        self.0.iter().flat_map(|state| {
            state
                .get()
                .nodes
                .expose()
                .iter()
                .filter_map(|node| node.key.as_ref())
        })
    }

    pub(super) fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |state| state.get().used)
    }

    pub(super) fn file_count(&self) -> usize {
        self.0.as_ref().map_or(0, |state| {
            state
                .get()
                .nodes
                .expose()
                .iter()
                .filter(|node| node.file)
                .count()
        })
    }
}
