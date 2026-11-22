//! The client's and the service's commands: prove and verify one request.

use std::path::PathBuf;

use anyhow::Context;
use ark_ff::UniformRand;
use rand::rngs::OsRng;
use zkopa_kernel::{Decision, Query, Verifier};
use zkopa_prove::{Fr, Prover, Request, SignedCredential};

use crate::{files, issuer};

pub struct Prove {
    pub prover: PathBuf,
    pub cred: PathBuf,
    /// The revoked credential ids the feed was built from, so the login proves against its root.
    pub revoke_ids: Vec<u32>,
    /// The epoch to log in at and prove against.
    pub epoch: u64,
    /// The audience of the service the token is for.
    pub audience: String,
    /// The decision path, such as `transfers/create/allow`.
    pub policy: String,
    /// A flat JSON object of field name to number, boolean or string.
    pub input: PathBuf,
    pub out: PathBuf,
}

pub fn prove(args: Prove, now_ms: u64) -> anyhow::Result<()> {
    let prover = Prover::decode(&files::read(&args.prover)?)
        .with_context(|| format!("decoding {}", args.prover.display()))?;
    let credential = SignedCredential::decode(&files::read(&args.cred)?)
        .with_context(|| format!("decoding {}", args.cred.display()))?;
    let json = files::input_json(&args.input)?;
    let input = files::input(&json)?;
    let revoked = issuer::revocation_tree(args.revoke_ids.iter().copied());
    let session = prover
        .login(credential, &revoked, args.epoch, &mut OsRng)
        .with_context(|| format!("logging in with {}", args.cred.display()))?;
    let request = Request {
        audience: &args.audience,
        policy: &args.policy,
        input: &input,
        ts: now_ms,
        nonce: Fr::rand(&mut OsRng),
        root_epoch: args.epoch,
    };
    let token = prover
        .prove(&session, request, &mut OsRng)
        .with_context(|| format!("proving {}", args.policy))?;
    files::write(&args.out, &token.encode())
}

pub struct Verify {
    pub bundle: PathBuf,
    /// The root Ed25519 public key the bundle and the feed are signed with.
    pub root_pub: PathBuf,
    pub feed: PathBuf,
    /// This service's audience.
    pub audience: String,
    /// The decision path, such as `transfers/create/allow`.
    pub policy: String,
    /// A flat JSON object of field name to number, boolean or string.
    pub input: PathBuf,
    pub token: PathBuf,
}

/// Prints the decision and the encoded input, so a client and a service that disagree on a
/// value can compare. Returns whether the request is allowed.
pub fn verify(args: Verify, now_ms: u64) -> anyhow::Result<bool> {
    let root = files::root_public(&args.root_pub)?;
    // A verifier started at 0 accepts any timestamp within the window. That is safe here: the
    // restart rule protects a service's nonce set, and this process has seen no earlier token.
    let verifier = Verifier::new(0, &root, &args.audience, &files::read(&args.bundle)?)
        .with_context(|| format!("loading {}", args.bundle.display()))?;
    verifier
        .apply_feed(now_ms, &files::read(&args.feed)?)
        .with_context(|| format!("applying {}", args.feed.display()))?;
    let json = files::input_json(&args.input)?;
    let input = files::input(&json)?;
    let token = files::read(&args.token)?;
    let query = Query {
        policy: &args.policy,
        input: &input,
        token: &token,
    };
    let allowed = match verifier.decide(now_ms, query) {
        Decision::Allow(_) => {
            println!("allow");
            true
        }
        Decision::Deny(reason) => {
            println!("deny: {reason}");
            false
        }
    };
    for (name, value) in &input {
        println!("  {name} = {}", value.encode());
    }
    Ok(allowed)
}
