//! How the handler's `input` and the token's claims become public inputs.
//!
//! The encoding is injective: the type of each position comes from the layout, never from the
//! value, `u64` and `bool` map to the integer itself, and `bytes` map to a 248-bit hash.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::{
    token::Claims,
    wire::{DecodeError, FIELD_LEN},
};

/// The number of public inputs of every login proof.
pub const LOGIN_INPUTS: usize = 6;

/// The number of public inputs of a request proof before its `input` fields.
pub const REQUEST_FIXED_INPUTS: usize = 6;

/// The type of one `input` field. The discriminant is its tag in a bundle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    U64 = 1,
    Bool = 2,
    Bytes = 3,
}

impl Type {
    const ALL: [Self; 3] = [Self::U64, Self::Bool, Self::Bytes];
}

impl TryFrom<u8> for Type {
    type Error = DecodeError;

    fn try_from(tag: u8) -> Result<Self, DecodeError> {
        Self::ALL
            .into_iter()
            .find(|ty| *ty as u8 == tag)
            .ok_or(DecodeError::Invalid)
    }
}

/// One value the handler puts in `input`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    U64(u64),
    Bool(bool),
    Bytes(&'a [u8]),
}

impl Value<'_> {
    pub fn ty(self) -> Type {
        match self {
            Value::U64(_) => Type::U64,
            Value::Bool(_) => Type::Bool,
            Value::Bytes(_) => Type::Bytes,
        }
    }

    /// The public input this value becomes.
    pub fn encode(self) -> Fr {
        match self {
            Value::U64(value) => Fr::from(value),
            Value::Bool(value) => Fr::from(u64::from(value)),
            Value::Bytes(bytes) => encode_bytes(bytes),
        }
    }
}

/// One named, typed field of a policy's input layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
}

/// The issuer's BabyJubJub public key, as its two affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issuer {
    pub x: Fr,
    pub y: Fr,
}

/// Why an `input` does not match a policy's layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the input does not match the policy's layout")]
pub struct InputMismatch;

/// How many digest bytes `encode_bytes` keeps: one byte short of a field element, so the value
/// is below `2^248` and the modulus.
const ENCODED_BYTES_LEN: usize = FIELD_LEN - 1;

/// The first [`ENCODED_BYTES_LEN`] bytes of the SHA-256 digest, read as a little-endian integer.
/// Below `2^248`, so it is always a canonical field element and never reduced.
pub fn encode_bytes(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Sha256::digest(bytes)[..ENCODED_BYTES_LEN])
}

/// The login proof's public inputs: issuer x, issuer y, the revocation root of the login epoch,
/// the login epoch, `C`, `T`.
pub fn login_inputs(issuer: Issuer, revocation_root: Fr, claims: &Claims) -> [Fr; LOGIN_INPUTS] {
    [
        issuer.x,
        issuer.y,
        revocation_root,
        Fr::from(claims.login_epoch),
        claims.commitment,
        claims.tag,
    ]
}

/// The request proof's public inputs: `C`, audience, decision path, ts, nonce, root epoch, then
/// the `input` fields in layout order.
///
/// Every layout field must appear in `input` exactly once with its type, and nothing else may.
pub fn request_inputs(
    claims: &Claims,
    audience: &str,
    policy: &str,
    layout: &[Field],
    input: &[(&str, Value<'_>)],
) -> Result<Vec<Fr>, InputMismatch> {
    request_inputs_encoded(
        claims,
        encode_bytes(audience.as_bytes()),
        encode_bytes(policy.as_bytes()),
        layout,
        input,
    )
}

/// `request_inputs` with the audience and decision path already encoded, so the verifier hashes
/// them once at load instead of on every request.
pub(crate) fn request_inputs_encoded(
    claims: &Claims,
    audience: Fr,
    policy: Fr,
    layout: &[Field],
    input: &[(&str, Value<'_>)],
) -> Result<Vec<Fr>, InputMismatch> {
    // Layout names are distinct (checked when the bundle is decoded). With equal lengths and each
    // layout name matched by exactly one entry, every entry is used once: none is extra.
    if input.len() != layout.len() {
        return Err(InputMismatch);
    }
    let mut inputs = Vec::with_capacity(REQUEST_FIXED_INPUTS + layout.len());
    inputs.extend([
        claims.commitment,
        audience,
        policy,
        Fr::from(claims.ts),
        claims.nonce,
        Fr::from(claims.root_epoch),
    ]);
    for field in layout {
        let mut matches = input.iter().filter(|(name, _)| *name == field.name);
        let (Some((_, value)), None) = (matches.next(), matches.next()) else {
            return Err(InputMismatch);
        };
        if value.ty() != field.ty {
            return Err(InputMismatch);
        }
        inputs.push(value.encode());
    }
    Ok(inputs)
}
