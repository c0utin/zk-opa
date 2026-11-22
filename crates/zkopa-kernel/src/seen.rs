//! The two sets `decide` writes: seen nonces and verified logins.
//!
//! Each is split into shards with one small lock each, so concurrent requests rarely meet on a
//! lock, and no lock is ever held while a proof is verified.

use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, MutexGuard, PoisonError},
};

use ark_bn254::Fr;
use ark_ff::PrimeField;

// Tuning, not protocol: a deployment may change any of these without affecting which requests
// are allowed.

/// Shards per set. More shards mean fewer requests meeting on one lock, and more memory.
const SHARDS: usize = 16;

/// Verified logins kept per shard. Beyond this a shard is emptied: evicting is safe because the
/// login proof arrives with every request, so it only costs a login proof verification.
const LOGINS_PER_SHARD: usize = 4096;

/// Nonces a shard holds before it first sweeps out expired ones.
const NONCES_SWEEP_MIN: usize = 1024;

/// After a sweep, a shard sweeps again once it holds this many times the nonces it kept.
const NONCES_SWEEP_GROWTH: usize = 2;

/// Picks a shard from a value that is uniformly distributed: a nonce or a commitment.
fn shard(value: &Fr) -> usize {
    (value.into_bigint().0[0] % SHARDS as u64) as usize
}

/// A panic while a shard was locked can leave it with an entry too many or too few, never a
/// broken one, so a poisoned lock is still used.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a login proof states, apart from the issuer, which is fixed by the bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Login {
    pub(crate) revocation_root: Fr,
    pub(crate) epoch: u64,
    pub(crate) commitment: Fr,
    pub(crate) tag: Fr,
}

pub(crate) struct Logins([Mutex<HashSet<Login>>; SHARDS]);

impl Logins {
    pub(crate) fn new() -> Self {
        Self(std::array::from_fn(|_| Mutex::default()))
    }

    pub(crate) fn contains(&self, login: &Login) -> bool {
        lock(&self.0[shard(&login.commitment)]).contains(login)
    }

    /// Only for logins whose proof verified.
    pub(crate) fn insert(&self, login: Login) {
        let mut shard = lock(&self.0[shard(&login.commitment)]);
        if shard.len() >= LOGINS_PER_SHARD {
            shard.clear();
        }
        shard.insert(login);
    }
}

#[derive(Default)]
struct NonceShard {
    /// Nonce to the timestamp of the request that used it.
    nonces: HashMap<Fr, u64>,
    /// The size at which the shard next drops expired nonces. Growing it by a factor after each
    /// sweep keeps the cost of sweeping constant per insert.
    sweep_at: usize,
}

pub(crate) struct Nonces([Mutex<NonceShard>; SHARDS]);

impl Nonces {
    pub(crate) fn new() -> Self {
        Self(std::array::from_fn(|_| Mutex::default()))
    }

    pub(crate) fn contains(&self, nonce: &Fr) -> bool {
        lock(&self.0[shard(nonce)]).nonces.contains_key(nonce)
    }

    /// Inserts `nonce` unless it is already present, and reports whether it was inserted.
    /// Nonces with timestamps before `expired_before` are dropped: their requests are outside
    /// the timestamp window and are denied before the nonce is looked at.
    pub(crate) fn insert(&self, nonce: Fr, ts: u64, expired_before: u64) -> bool {
        let mut shard = lock(&self.0[shard(&nonce)]);
        if shard.nonces.contains_key(&nonce) {
            return false;
        }
        if shard.nonces.len() >= shard.sweep_at {
            shard.nonces.retain(|_, ts| *ts >= expired_before);
            shard.sweep_at = NONCES_SWEEP_MIN.max(NONCES_SWEEP_GROWTH * shard.nonces.len());
        }
        shard.nonces.insert(nonce, ts);
        true
    }
}
