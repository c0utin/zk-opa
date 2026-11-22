//! Builds the login circuit and lowers IR policies to request circuits, sets up their Groth16
//! keys, and makes the proofs the kernel checks.
//!
//! The issuer signs a [`Credential`]. [`setup`] turns a schema, the issuer's key and compiled
//! policies into the kernel's [`Bundle`] and the client's [`Prover`]. The client logs in once
//! per session with [`Prover::login`] and proves each request with [`Prover::prove`], which
//! returns the kernel's [`Token`]. Randomness is always an argument, so the crate never reads
//! OS entropy and builds for WebAssembly.

mod hash;
mod issuer;
mod login;
mod request;
mod tree;

use ark_bn254::Bn254;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::rand::{CryptoRng, RngCore};
use zkopa_ir::{FieldType, Policy, Schema};
use zkopa_kernel::{
    Bundle, Claims, Field, Issuer, Profile, Proof, Token, Type, Value, VerifyingKey,
    wire::{self, COUNT_LEN, Magic, Reader, Writer},
};

pub use ark_bn254::Fr;

use crate::issuer::issuer_point;
pub use crate::{
    issuer::{
        Credential, ISSUER_KEY_LEN, IssuerKey, Signature, SignedCredential, commitment,
        revocation_tag,
    },
    login::LoginCircuit,
    request::RequestCircuit,
    tree::{DEPTH, RevocationTree},
};

/// The width of a `u64`, the range every attribute and `u64` input is checked to lie in.
const U64_BITS: usize = u64::BITS as usize;

/// Why setup, a login or a request proof failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the issuer key is not a point of prime order")]
    IssuerKey,
    #[error("expected {expected} attributes, as in the schema, but got {actual}")]
    Schema { expected: usize, actual: usize },
    #[error("two policies have the decision path {0}")]
    DuplicatePolicy(String),
    #[error("the credential is not signed by the issuer")]
    Signature,
    #[error("the credential is revoked")]
    Revoked,
    #[error("the credential has expired at the login epoch")]
    Expired,
    #[error("no policy has the decision path {0}")]
    UnknownPolicy(String),
    #[error("the input does not match the policy's layout")]
    InputMismatch,
    #[error("the policy does not allow this request")]
    Denied,
    #[error("constraint synthesis failed: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Why proving data or a credential could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("the data ends early")]
    Truncated,
    #[error("the data has trailing bytes")]
    Trailing,
    #[error("the data is not of the expected kind")]
    Magic,
    #[error("the data has unknown version {0}")]
    Version(u8),
    #[error("the data holds a value out of range")]
    Invalid,
    #[error("a policy in the data is invalid: {0}")]
    Policy(#[from] zkopa_ir::Error),
}

impl From<wire::DecodeError> for DecodeError {
    fn from(error: wire::DecodeError) -> Self {
        match error {
            wire::DecodeError::Truncated => Self::Truncated,
            wire::DecodeError::Trailing => Self::Trailing,
            wire::DecodeError::Magic => Self::Magic,
            wire::DecodeError::Version(version) => Self::Version(version),
            // The prover's files reject a repeated entry as an invalid value.
            wire::DecodeError::Invalid | wire::DecodeError::Duplicate => Self::Invalid,
        }
    }
}

/// The bundle parameters the kernel enforces. See [`Bundle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub version: u64,
    pub window_ms: u64,
    pub stale_ms: u64,
    pub session_epochs: u64,
}

/// Runs the trusted setup of the login circuit and of one request circuit per policy.
///
/// Returns the bundle body for services (sign it with `Bundle::encode` and
/// `zkopa_kernel::attach_signature`) and the proving data for clients. Whoever learns `rng`'s
/// output can forge proofs.
pub fn setup(
    schema: Schema,
    issuer: Issuer,
    params: Params,
    policies: Vec<Policy>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Bundle, Prover), Error> {
    if issuer_point(issuer).is_none() {
        return Err(Error::IssuerKey);
    }
    let attributes = schema.names().len();
    policies
        .iter()
        .try_for_each(|policy| check_policy(policy, attributes))?;
    if let Some(policy) = duplicate(&policies, Policy::path) {
        return Err(Error::DuplicatePolicy(policy.path().to_owned()));
    }

    let blank = SignedCredential::blank(attributes);
    let login = LoginCircuit::new(issuer, &blank, &RevocationTree::default(), 0, Fr::from(0));
    let login_key = Groth16::<Bn254>::generate_random_parameters_with_reduction(login, rng)?;
    let policies = policies
        .into_iter()
        .map(|policy| {
            let layout = layout(&policy);
            let public = vec![Fr::from(0); zkopa_kernel::REQUEST_FIXED_INPUTS + layout.len()];
            let zeros = vec![0; attributes];
            let circuit = RequestCircuit::new(&policy, &public, &zeros, Fr::from(0))?;
            let key = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)?;
            Ok(Prepared {
                policy,
                layout,
                key,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    // The bundle owns copies of the verifying keys and layouts; this runs once per build.
    let bundle = Bundle {
        profile: Profile::Groth16Bn254,
        version: params.version,
        issuer,
        window_ms: params.window_ms,
        stale_ms: params.stale_ms,
        session_epochs: params.session_epochs,
        login_key: verifying_key(&login_key),
        policies: policies
            .iter()
            .map(|p| zkopa_kernel::Policy {
                path: p.policy.path().to_owned(),
                layout: p.layout.clone(),
                key: verifying_key(&p.key),
            })
            .collect(),
    };
    let prover = Prover {
        schema,
        issuer,
        login_key,
        policies,
    };
    Ok((bundle, prover))
}

/// The first item whose path an earlier item has. Quadratic, for the few policies of a build.
fn duplicate<T>(items: &[T], path: impl Fn(&T) -> &str) -> Option<&T> {
    items
        .iter()
        .enumerate()
        .find(|&(i, item)| items[..i].iter().any(|other| path(other) == path(item)))
        .map(|(_, item)| item)
}

/// The kernel's copy of a proving key's verifying key.
fn verifying_key(key: &ProvingKey<Bn254>) -> VerifyingKey {
    let vk = &key.vk;
    VerifyingKey {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.gamma_abc_g1.clone(),
    }
}

/// The kernel's form of a proof.
fn proof(proof: ark_groth16::Proof<Bn254>) -> Proof {
    Proof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    }
}

fn check_policy(policy: &Policy, attributes: usize) -> Result<(), Error> {
    if policy.attributes() as usize != attributes {
        return Err(Error::Schema {
            expected: attributes,
            actual: policy.attributes() as usize,
        });
    }
    Ok(())
}

/// The kernel's layout for a policy.
fn layout(policy: &Policy) -> Vec<Field> {
    let field = |f: &zkopa_ir::Field| Field {
        name: f.name.clone(),
        ty: match f.ty {
            FieldType::U64 => Type::U64,
            FieldType::Bool => Type::Bool,
            FieldType::Bytes => Type::Bytes,
        },
    };
    policy.inputs().iter().map(field).collect()
}

/// One policy ready to prove: its IR, its kernel layout and its proving key.
struct Prepared {
    policy: Policy,
    layout: Vec<Field>,
    key: ProvingKey<Bn254>,
}

/// What a client needs to prove: the schema, the issuer key, the IR policies and the proving
/// keys. Public, but large.
pub struct Prover {
    schema: Schema,
    issuer: Issuer,
    login_key: ProvingKey<Bn254>,
    policies: Vec<Prepared>,
}

/// A logged-in session: the credential, the blinding of `C`, and the login proof that every
/// request token carries. Keep it secret: it holds the credential.
pub struct Session {
    credential: SignedCredential,
    blinding: Fr,
    login_proof: Proof,
    commitment: Fr,
    tag: Fr,
    epoch: u64,
}

impl Session {
    /// The session commitment `C`.
    pub fn commitment(&self) -> Fr {
        self.commitment
    }

    /// The revocation tag `T`. The issuer revokes the session by putting it in the feed.
    pub fn tag(&self) -> Fr {
        self.tag
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// One request to prove, with the values the service's handler will build.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub audience: &'a str,
    /// The decision path, such as `transfers/create/allow`.
    pub policy: &'a str,
    pub input: &'a [(&'a str, Value<'a>)],
    pub ts: u64,
    /// Unique per request: the kernel denies a nonce it has seen.
    pub nonce: Fr,
    /// The feed epoch whose revocation root the service will accept.
    pub root_epoch: u64,
}

const MAGIC: &Magic = b"ZKPV";

/// The fewest bytes a policy takes in proving data: the length prefixes of its IR and its key.
const POLICY_MIN_LEN: usize = 2 * COUNT_LEN;

impl Prover {
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn issuer(&self) -> Issuer {
        self.issuer
    }

    /// The compiled policies, in bundle order.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.iter().map(|p| &p.policy)
    }

    /// Proves the credential at `epoch` against `revoked`, whose root the feed publishes for
    /// that epoch. Every condition the circuit enforces is checked first, so a bad credential
    /// gets an error instead of a proof the kernel rejects.
    pub fn login(
        &self,
        credential: SignedCredential,
        revoked: &RevocationTree,
        epoch: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Session, Error> {
        let expected = self.schema.names().len();
        let actual = credential.credential.attributes.len();
        if actual != expected {
            return Err(Error::Schema { expected, actual });
        }
        if !credential.verify(self.issuer) {
            return Err(Error::Signature);
        }
        if revoked.is_revoked(credential.credential.id) {
            return Err(Error::Revoked);
        }
        if epoch >= credential.credential.exp {
            return Err(Error::Expired);
        }
        let blinding = Fr::rand(rng);
        let circuit = LoginCircuit::new(self.issuer, &credential, revoked, epoch, blinding);
        let (commitment, tag) = (circuit.commitment, circuit.tag);
        let login_proof = proof(Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
            &self.login_key,
            rng,
        )?);
        Ok(Session {
            credential,
            blinding,
            login_proof,
            commitment,
            tag,
            epoch,
        })
    }

    /// Proves one request and returns the token for it.
    ///
    /// The public inputs come from `zkopa_kernel::request_inputs`, the encoder the kernel uses,
    /// and the policy is evaluated in the clear first, so a request it does not allow is
    /// [`Error::Denied`] rather than a proof that fails to verify.
    pub fn prove(
        &self,
        session: &Session,
        request: Request<'_>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Token, Error> {
        let prepared = self
            .policies
            .iter()
            .find(|p| p.policy.path() == request.policy)
            .ok_or_else(|| Error::UnknownPolicy(request.policy.to_owned()))?;
        let claims = Claims {
            commitment: session.commitment,
            tag: session.tag,
            login_epoch: session.epoch,
            ts: request.ts,
            nonce: request.nonce,
            root_epoch: request.root_epoch,
        };
        let public = zkopa_kernel::request_inputs(
            &claims,
            request.audience,
            request.policy,
            &prepared.layout,
            request.input,
        )
        .map_err(|_| Error::InputMismatch)?;

        // `request_inputs` accepted the input, so every layout name has exactly one entry
        // of its type.
        let values: Vec<zkopa_ir::Value<'_>> = prepared
            .layout
            .iter()
            .filter_map(|field| request.input.iter().find(|(name, _)| *name == field.name))
            .map(|&(_, value)| match value {
                Value::U64(v) => zkopa_ir::Value::U64(v),
                Value::Bool(v) => zkopa_ir::Value::Bool(v),
                Value::Bytes(v) => zkopa_ir::Value::Bytes(v),
            })
            .collect();
        let attributes = &session.credential.credential.attributes;
        match prepared.policy.eval(&values, attributes) {
            Ok(true) => {}
            Ok(false) => return Err(Error::Denied),
            Err(_) => return Err(Error::InputMismatch),
        }

        let circuit = RequestCircuit::new(&prepared.policy, &public, attributes, session.blinding)?;
        let request_proof = proof(Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit,
            &prepared.key,
            rng,
        )?);
        Ok(Token {
            claims,
            login_proof: session.login_proof,
            request_proof,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        // No capacity hint: the proving keys dominate, and the data is encoded once.
        let mut writer = Writer::new(MAGIC);
        writer.count(self.schema.names().len());
        for name in self.schema.names() {
            writer.bytes(name.as_bytes());
        }
        writer.ark(&self.issuer.x);
        writer.ark(&self.issuer.y);
        writer.ark_bytes(&self.login_key);
        writer.count(self.policies.len());
        for prepared in &self.policies {
            writer.bytes(&prepared.policy.encode());
            writer.ark_bytes(&prepared.key);
        }
        writer.finish()
    }

    /// Decodes and checks proving data: every key point is on its curve and in the prime-order
    /// subgroup, and every policy passes the IR type check and fits the schema.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes, MAGIC)?;
        // Each name takes at least its length prefix.
        let names = (0..reader.bounded_count(COUNT_LEN)?)
            .map(|_| Ok(reader.str()?.to_owned()))
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let schema = Schema::new(names)?;
        let issuer = Issuer {
            x: reader.field()?,
            y: reader.field()?,
        };
        if issuer_point(issuer).is_none() {
            return Err(DecodeError::Invalid);
        }
        let login_key = reader.ark_bytes()?;
        let attributes = schema.names().len();
        let policies = (0..reader.bounded_count(POLICY_MIN_LEN)?)
            .map(|_| {
                let policy = Policy::decode(reader.bytes()?)?;
                check_policy(&policy, attributes).map_err(|_| DecodeError::Invalid)?;
                Ok(Prepared {
                    layout: layout(&policy),
                    key: reader.ark_bytes()?,
                    policy,
                })
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        if duplicate(&policies, |p| p.policy.path()).is_some() {
            return Err(DecodeError::Invalid);
        }
        reader.finish()?;
        Ok(Self {
            schema,
            issuer,
            login_key,
            policies,
        })
    }
}

/// Builds a circuit's constraints without proving and reports whether its values satisfy
/// them. Much faster than proving, for tests and diagnostics.
pub fn is_satisfied(circuit: impl ConstraintSynthesizer<Fr>) -> Result<bool, Error> {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    Ok(cs.is_satisfied()?)
}

// Allocation takes the constraint system by value, so the handle is cloned here once instead of
// at every call site. It is a reference-counted pointer.

fn input(cs: &ConstraintSystemRef<Fr>, value: impl Into<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_input(cs.clone(), || Ok(value.into()))
}

fn witness(
    cs: &ConstraintSystemRef<Fr>,
    value: impl Into<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || Ok(value.into()))
}

/// Enforces `x < 2^bits`.
fn enforce_bits(x: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    x.to_bits_le_with_top_bits_zero(bits).map(drop)
}
