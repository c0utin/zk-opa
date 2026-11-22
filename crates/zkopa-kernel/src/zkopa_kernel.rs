//! Verifies proofs and decides allow or deny. No I/O.
//!
//! A service loads a signed bundle into a [`Verifier`], applies signed feed updates as they
//! arrive, and asks [`Verifier::decide`] about each request. Time is always an argument.

mod bundle;
mod feed;
mod groth16;
mod input;
mod seen;
mod token;
pub mod wire;

use std::{
    collections::HashMap,
    panic::{self, AssertUnwindSafe},
    sync::Arc,
};

use arc_swap::{ArcSwap, Guard};
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;

pub use crate::{
    bundle::{Bundle, Policy, Profile},
    feed::FeedUpdate,
    groth16::{PROOF_LEN, PreparedVerifyingKey, Proof, VerifyingKey},
    input::{
        Field, InputMismatch, Issuer, LOGIN_INPUTS, REQUEST_FIXED_INPUTS, Type, Value,
        encode_bytes, login_inputs, request_inputs,
    },
    token::{Claims, TOKEN_LEN, Token},
    wire::{DecodeError, SIGNATURE_LEN, attach_signature},
};
use crate::{
    input::request_inputs_encoded,
    seen::{Login, Logins, Nonces},
    token::Encoded,
    wire::verified_body,
};

/// Why a bundle was not loaded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("the root key is not a valid Ed25519 public key")]
    RootKey,
    #[error("the bundle is not signed by the root key")]
    Signature,
    #[error("the bundle is malformed: {0}")]
    Decode(#[from] DecodeError),
    #[error("the login key takes {actual} public inputs instead of {expected}")]
    LoginInputCount { expected: usize, actual: usize },
    #[error("the key of {policy} takes {actual} public inputs, but its layout implies {expected}")]
    PolicyInputCount {
        policy: String,
        expected: usize,
        actual: usize,
    },
}

/// Why a feed update was not applied. The verifier keeps its previous feed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    #[error("the feed update is not signed by the root key")]
    Signature,
    #[error("the feed update is malformed: {0}")]
    Decode(#[from] DecodeError),
    #[error("the feed update has sequence {update}, not after the applied {applied}")]
    Sequence { applied: u64, update: u64 },
    #[error("the feed update is already stale")]
    Stale,
    #[error("the feed update is issued in the future")]
    Future,
}

/// One question to the kernel: may this token act on this `input` under this decision path?
#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    /// The decision path, as in OPA: `transfers/create/allow`.
    pub policy: &'a str,
    /// The values the handler is about to act on, by layout name.
    pub input: &'a [(&'a str, Value<'a>)],
    /// The encoded [`Token`] the client sent.
    pub token: &'a [u8],
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow(Receipt),
    Deny(Reason),
}

/// Proof that `decide` allowed a request. Only the kernel makes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    nonce: Fr,
    commitment: Fr,
}

impl Receipt {
    /// The request's nonce. Hosts use it as the idempotency key for writes, because replicas do
    /// not share their seen nonces.
    pub fn nonce(&self) -> Fr {
        self.nonce
    }

    /// The session commitment `C`.
    pub fn commitment(&self) -> Fr {
        self.commitment
    }
}

/// Why a request was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    #[error("the token is malformed")]
    BadToken,
    #[error("no policy has this decision path")]
    UnknownPolicy,
    #[error("the input does not match the policy's layout")]
    InputMismatch,
    #[error("the token's timestamp is outside the window")]
    Timestamp,
    #[error("no feed update is applied, or the newest is too old")]
    StaleFeed,
    #[error("the feed requires a newer bundle")]
    OldBundle,
    #[error("the login epoch is too old for the root epoch")]
    SessionExpired,
    #[error("the feed has no revocation root for the token's epoch")]
    RootEpoch,
    #[error("the revocation tag is revoked")]
    Revoked,
    #[error("the nonce was already used")]
    Replay,
    #[error("the login proof does not verify")]
    BadLoginProof,
    #[error("the request proof does not verify")]
    BadRequestProof,
    #[error("the kernel panicked")]
    Panic,
}

/// How many timestamp windows a used nonce is kept for. More than one, because threads pass
/// slightly different clocks.
const NONCE_RETENTION_WINDOWS: u64 = 2;

struct PreparedPolicy {
    /// The decision path, encoded once at load.
    path: Fr,
    layout: Vec<Field>,
    key: PreparedVerifyingKey,
}

/// The kernel. One value serves every request thread through `&self`.
pub struct Verifier {
    root: ed25519_dalek::VerifyingKey,
    start_ms: u64,
    audience: Fr,
    version: u64,
    issuer: Issuer,
    window_ms: u64,
    stale_ms: u64,
    session_epochs: u64,
    login_key: PreparedVerifyingKey,
    policies: HashMap<String, PreparedPolicy>,
    /// Replaced whole by each update, so a decision sees one update or the next, never a mix.
    feed: ArcSwap<FeedUpdate>,
    logins: Logins,
    nonces: Nonces,
}

impl Verifier {
    /// Checks `bundle` (`body || signature`) against the pinned `root_key` and loads it.
    ///
    /// Tokens with timestamps before `now_ms` are denied, so a restarted verifier with an empty
    /// nonce set cannot accept a request it accepted before the restart.
    pub fn new(
        now_ms: u64,
        root_key: &[u8],
        audience: &str,
        bundle: &[u8],
    ) -> Result<Self, BundleError> {
        let root = <&[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::try_from(root_key)
            .ok()
            .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(key).ok())
            .ok_or(BundleError::RootKey)?;
        let body = verified_body(&root, bundle).ok_or(BundleError::Signature)?;
        let Bundle {
            profile: Profile::Groth16Bn254,
            version,
            issuer,
            window_ms,
            stale_ms,
            session_epochs,
            login_key,
            policies,
        } = Bundle::decode(body)?;

        // `ark-groth16` ignores public inputs beyond what the key expects, which would leave an
        // `input` field unbound, so every key must take exactly the inputs the kernel supplies.
        let actual = login_key.inputs();
        if actual != LOGIN_INPUTS {
            return Err(BundleError::LoginInputCount {
                expected: LOGIN_INPUTS,
                actual,
            });
        }
        let policies = policies
            .into_iter()
            .map(|Policy { path, layout, key }| {
                let expected = REQUEST_FIXED_INPUTS + layout.len();
                let actual = key.inputs();
                if actual != expected {
                    return Err(BundleError::PolicyInputCount {
                        policy: path,
                        expected,
                        actual,
                    });
                }
                let prepared = PreparedPolicy {
                    path: encode_bytes(path.as_bytes()),
                    layout,
                    key: PreparedVerifyingKey::new(key),
                };
                Ok((path, prepared))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            root,
            start_ms: now_ms,
            audience: encode_bytes(audience.as_bytes()),
            version,
            issuer,
            window_ms,
            stale_ms,
            session_epochs,
            login_key: PreparedVerifyingKey::new(login_key),
            policies,
            feed: ArcSwap::from_pointee(FeedUpdate::NONE),
            logins: Logins::new(),
            nonces: Nonces::new(),
        })
    }

    /// Checks a feed update (`body || signature`) and makes it the current feed state. Its
    /// sequence number must be above the applied one; concurrent calls apply in sequence order
    /// or fail.
    pub fn apply_feed(&self, now_ms: u64, update: &[u8]) -> Result<(), FeedError> {
        let body = verified_body(&self.root, update).ok_or(FeedError::Signature)?;
        let update = FeedUpdate::decode(body)?;
        if now_ms.saturating_sub(update.issued_ms) > self.stale_ms {
            return Err(FeedError::Stale);
        }
        // Clocks are trusted as far as the timestamp window, here as for tokens. A later issue
        // time would keep the update fresh for longer than `stale_ms`.
        if update.issued_ms > now_ms.saturating_add(self.window_ms) {
            return Err(FeedError::Future);
        }
        let update = Arc::new(update);
        let mut applied = self.feed.load_full();
        loop {
            if update.sequence <= applied.sequence {
                return Err(FeedError::Sequence {
                    applied: applied.sequence,
                    update: update.sequence,
                });
            }
            // The handle is cloned per attempt because a lost race keeps it for the next one.
            let previous = self.feed.compare_and_swap(&applied, Arc::clone(&update));
            if Arc::ptr_eq(&previous, &applied) {
                return Ok(());
            }
            applied = Guard::into_inner(previous);
        }
    }

    /// Decides one request. Never fails: every problem, including a panic, is a deny.
    pub fn decide(&self, now_ms: u64, query: Query<'_>) -> Decision {
        // A panic leaves nothing half-done: the feed is an immutable snapshot, and the sets
        // tolerate poisoned locks.
        match panic::catch_unwind(AssertUnwindSafe(|| self.check(now_ms, query))) {
            Ok(Ok(receipt)) => Decision::Allow(receipt),
            Ok(Err(reason)) => Decision::Deny(reason),
            Err(_) => Decision::Deny(Reason::Panic),
        }
    }

    /// The checks, cheapest first. Proofs are verified with no lock held.
    fn check(&self, now_ms: u64, query: Query<'_>) -> Result<Receipt, Reason> {
        let token = Encoded::decode(query.token).map_err(|_| Reason::BadToken)?;
        let claims = token.claims;
        let policy = self
            .policies
            .get(query.policy)
            .ok_or(Reason::UnknownPolicy)?;
        let request = request_inputs_encoded(
            &claims,
            self.audience,
            policy.path,
            &policy.layout,
            query.input,
        )
        .map_err(|_| Reason::InputMismatch)?;
        if claims.ts < self.start_ms || claims.ts.abs_diff(now_ms) > self.window_ms {
            return Err(Reason::Timestamp);
        }

        let login = {
            let feed = self.feed.load();
            if feed.sequence == 0 || now_ms.saturating_sub(feed.issued_ms) > self.stale_ms {
                return Err(Reason::StaleFeed);
            }
            if self.version < feed.min_bundle_version {
                return Err(Reason::OldBundle);
            }
            match claims.root_epoch.checked_sub(claims.login_epoch) {
                Some(age) if age < self.session_epochs => {}
                _ => return Err(Reason::SessionExpired),
            }
            feed.root(claims.root_epoch).ok_or(Reason::RootEpoch)?;
            let revocation_root = feed.root(claims.login_epoch).ok_or(Reason::RootEpoch)?;
            if feed.is_revoked(&claims.tag) {
                return Err(Reason::Revoked);
            }
            Login {
                revocation_root,
                epoch: claims.login_epoch,
                commitment: claims.commitment,
                tag: claims.tag,
            }
        };
        if self.nonces.contains(&claims.nonce) {
            return Err(Reason::Replay);
        }

        if !self.logins.contains(&login) {
            let inputs = login_inputs(self.issuer, login.revocation_root, &claims);
            if !verify(&self.login_key, token.login_proof, &inputs) {
                return Err(Reason::BadLoginProof);
            }
            self.logins.insert(login);
        }
        if !verify(&policy.key, token.request_proof, &request) {
            return Err(Reason::BadRequestProof);
        }

        // Two identical requests may both get here; only one inserts the nonce.
        let expired_before =
            now_ms.saturating_sub(self.window_ms.saturating_mul(NONCE_RETENTION_WINDOWS));
        if !self.nonces.insert(claims.nonce, claims.ts, expired_before) {
            return Err(Reason::Replay);
        }
        Ok(Receipt {
            nonce: claims.nonce,
            commitment: claims.commitment,
        })
    }
}

fn verify(key: &PreparedVerifyingKey, proof: &[u8], inputs: &[Fr]) -> bool {
    // Decoding checks that each point is on the curve and in the prime-order subgroup.
    Proof::deserialize_compressed(proof).is_ok_and(|proof| key.verify(&proof, inputs))
}
