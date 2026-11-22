//! A sparse Merkle tree of revoked credential ids. A leaf is 0 until its id is revoked.

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::SynthesisError;

use crate::hash::{Domain, hash, hash_var};

/// One level per bit of a credential id.
pub const DEPTH: usize = 32;

/// The revocation tree. The issuer publishes its root per epoch in the feed, and the holder
/// needs the tree, or at least the revoked ids to rebuild it, to log in.
#[derive(Clone, Debug)]
pub struct RevocationTree {
    /// Nodes that differ from an empty subtree, by `(level, index)`. Leaves are level 0.
    nodes: HashMap<(usize, u64), Fr>,
    /// The value of an empty subtree at each level.
    empty: [Fr; DEPTH + 1],
}

impl Default for RevocationTree {
    fn default() -> Self {
        // Each level hashes two of the level below, so the array fills bottom up.
        let mut empty = [Fr::zero(); DEPTH + 1];
        for level in 0..DEPTH {
            empty[level + 1] = hash(Domain::Node, &[empty[level], empty[level]]);
        }
        Self {
            nodes: HashMap::new(),
            empty,
        }
    }
}

impl RevocationTree {
    fn node(&self, level: usize, index: u64) -> Fr {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.empty[level])
    }

    pub fn root(&self) -> Fr {
        self.node(DEPTH, 0)
    }

    pub fn is_revoked(&self, id: u32) -> bool {
        self.nodes.contains_key(&(0, u64::from(id)))
    }

    pub fn revoke(&mut self, id: u32) {
        let leaf = u64::from(id);
        self.nodes.insert((0, leaf), Fr::one());
        // Each level reads the one below, which the previous step wrote.
        for level in 0..DEPTH {
            let index = leaf >> level;
            let (left, right) = (self.node(level, index & !1), self.node(level, index | 1));
            self.nodes
                .insert((level + 1, index >> 1), hash(Domain::Node, &[left, right]));
        }
    }

    /// The sibling at each level on the way from `id`'s leaf to the root.
    pub fn siblings(&self, id: u32) -> [Fr; DEPTH] {
        std::array::from_fn(|level| self.node(level, (u64::from(id) >> level) ^ 1))
    }
}

/// The root implied by `leaf` sitting at the index whose little-endian bits are `index_bits`.
pub(crate) fn root_var(
    leaf: FpVar<Fr>,
    index_bits: &[Boolean<Fr>],
    siblings: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    assert_eq!(index_bits.len(), DEPTH);
    assert_eq!(siblings.len(), DEPTH);
    index_bits
        .iter()
        .zip(siblings)
        .try_fold(leaf, |node, (is_right, sibling)| {
            let left = is_right.select(sibling, &node)?;
            let right = is_right.select(&node, sibling)?;
            hash_var(Domain::Node, &[&left, &right])
        })
}
