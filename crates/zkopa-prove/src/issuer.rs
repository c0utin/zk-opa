//! The issuer's side: keys, credentials and their signatures, and the hashes a credential
//! enters.
//!
//! Signatures are Schnorr on BabyJubJub with a Poseidon challenge (`s·G = R + h·A`), which the
//! login circuit checks cheaply. EdDSA-shaped, but this project's own scheme: it is not vetted.

use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as Scalar, constraints::EdwardsVar};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, RngCore},
};
use zkopa_kernel::{
    Issuer,
    wire::{COUNT_LEN, FIELD_LEN, HEADER_LEN, Magic, Reader, U64_LEN, Writer},
};

use crate::{
    DecodeError,
    hash::{Domain, hash, hash_var},
};

/// The number of bits `s` is given to the circuit in.
const SCALAR_BITS: usize = Scalar::MODULUS_BIT_SIZE as usize;

/// The length of an encoded issuer key, a BabyJubJub scalar.
pub const ISSUER_KEY_LEN: usize = 32;

/// The length of an encoded `R`: compressed, a point is one coordinate, a BN254 scalar field
/// element, with its flag in the spare bits.
const POINT_LEN: usize = FIELD_LEN;

/// The length of an encoded signature: `R`, then `s`, a scalar like an issuer key.
const SIGNATURE_LEN: usize = POINT_LEN + ISSUER_KEY_LEN;

/// The length of an encoded credential apart from its attributes: the id and `exp` as `u64`s,
/// the attribute count and the signature.
const CREDENTIAL_FIXED_LEN: usize = HEADER_LEN + 2 * U64_LEN + COUNT_LEN + SIGNATURE_LEN;

/// What the issuer signs: an id, one value per schema attribute, and an expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// Its leaf in the revocation tree.
    pub id: u32,
    /// In schema order.
    pub attributes: Vec<u64>,
    /// The first login epoch at which the credential is no longer valid.
    pub exp: u64,
}

impl Credential {
    /// The message the issuer signs.
    fn digest(&self) -> Fr {
        let fields: Vec<Fr> = [Fr::from(self.id)]
            .into_iter()
            .chain(self.attributes.iter().map(|&a| Fr::from(a)))
            .chain([Fr::from(self.exp)])
            .collect();
        hash(Domain::Credential, &fields)
    }
}

/// The session commitment `C` to a credential's attributes.
pub fn commitment(attributes: &[u64], blinding: Fr) -> Fr {
    let fields: Vec<Fr> = attributes
        .iter()
        .map(|&a| Fr::from(a))
        .chain([blinding])
        .collect();
    hash(Domain::Commitment, &fields)
}

/// The revocation tag `T` of credential `id` for logins at `epoch`. The issuer revokes a live
/// session by putting this tag in the feed, for every epoch the session may still be used in.
pub fn revocation_tag(id: u32, epoch: u64) -> Fr {
    hash(Domain::RevocationTag, &[Fr::from(id), Fr::from(epoch)])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    r: EdwardsAffine,
    s: Scalar,
}

/// The issuer's secret signing key.
pub struct IssuerKey(Scalar);

impl IssuerKey {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(Scalar::rand(rng))
    }

    /// The key's canonical bytes.
    pub fn to_bytes(&self) -> [u8; ISSUER_KEY_LEN] {
        self.0
            .into_bigint()
            .to_bytes_le()
            .try_into()
            .expect("a BabyJubJub scalar fills ISSUER_KEY_LEN bytes")
    }

    /// Rejects anything but the canonical bytes of a key.
    pub fn from_bytes(bytes: &[u8; ISSUER_KEY_LEN]) -> Result<Self, DecodeError> {
        Scalar::deserialize_compressed(&bytes[..])
            .map(Self)
            .map_err(|_| DecodeError::Invalid)
    }

    pub fn public(&self) -> Issuer {
        let point = self.point();
        Issuer {
            x: point.x,
            y: point.y,
        }
    }

    fn point(&self) -> EdwardsAffine {
        (EdwardsAffine::generator() * self.0).into_affine()
    }

    pub fn sign(
        &self,
        credential: Credential,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> SignedCredential {
        let nonce = Scalar::rand(rng);
        let r = (EdwardsAffine::generator() * nonce).into_affine();
        let s = nonce + challenge(&r, &self.point(), credential.digest()) * self.0;
        SignedCredential {
            credential,
            signature: Signature { r, s },
        }
    }
}

/// The issuer key as a curve point, rejecting coordinates that are not a point of prime order.
/// The login circuit relies on that order, so a bad key is refused before any setup or proof.
pub(crate) fn issuer_point(issuer: Issuer) -> Option<EdwardsAffine> {
    let point = EdwardsAffine::new_unchecked(issuer.x, issuer.y);
    let valid = point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve();
    (valid && !point.is_zero()).then_some(point)
}

/// A credential and the issuer's signature on it. The holder keeps it secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCredential {
    pub credential: Credential,
    pub signature: Signature,
}

const MAGIC: &Magic = b"ZKCR";

impl SignedCredential {
    /// A credential of the right shape for key setup, whose values do not matter.
    pub(crate) fn blank(attributes: usize) -> Self {
        Self {
            credential: Credential {
                id: 0,
                attributes: vec![0; attributes],
                exp: 0,
            },
            signature: Signature {
                r: EdwardsAffine::generator(),
                s: Scalar::from(0u64),
            },
        }
    }

    /// Whether `issuer` signed this credential.
    pub fn verify(&self, issuer: Issuer) -> bool {
        let Some(public_key) = issuer_point(issuer) else {
            return false;
        };
        let Signature { r, s } = self.signature;
        let h = challenge(&r, &public_key, self.credential.digest());
        EdwardsAffine::generator() * s == r + public_key * h
    }

    pub fn encode(&self) -> Vec<u8> {
        let Credential {
            id,
            ref attributes,
            exp,
        } = self.credential;
        let len = CREDENTIAL_FIXED_LEN + U64_LEN * attributes.len();
        let mut writer = Writer::with_capacity(MAGIC, len);
        writer.u64(id.into());
        writer.count(attributes.len());
        for &attribute in attributes {
            writer.u64(attribute);
        }
        writer.u64(exp);
        writer.ark(&self.signature.r);
        writer.ark(&self.signature.s);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes, MAGIC)?;
        let id = u32::try_from(reader.u64()?).map_err(|_| DecodeError::Invalid)?;
        let attributes = (0..reader.bounded_count(U64_LEN)?)
            .map(|_| reader.u64())
            .collect::<Result<_, _>>()?;
        let exp = reader.u64()?;
        let signature = Signature {
            r: reader.ark(POINT_LEN)?,
            s: reader.ark(ISSUER_KEY_LEN)?,
        };
        reader.finish()?;
        Ok(Self {
            credential: Credential {
                id,
                attributes,
                exp,
            },
            signature,
        })
    }
}

/// The challenge as a scalar. The circuit multiplies by the hash's integer value, which is the
/// same thing on a point of prime order.
fn challenge(r: &EdwardsAffine, public_key: &EdwardsAffine, message: Fr) -> Scalar {
    let h = hash(
        Domain::Signature,
        &[r.x, r.y, public_key.x, public_key.y, message],
    );
    Scalar::from_le_bytes_mod_order(&h.into_bigint().to_bytes_le())
}

/// The credential digest inside a circuit.
pub(crate) fn digest_var(
    id: &FpVar<Fr>,
    attributes: &[FpVar<Fr>],
    exp: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let fields: Vec<&FpVar<Fr>> = [id].into_iter().chain(attributes).chain([exp]).collect();
    hash_var(Domain::Credential, &fields)
}

/// The commitment inside a circuit.
pub(crate) fn commitment_var(
    attributes: &[FpVar<Fr>],
    blinding: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let fields: Vec<&FpVar<Fr>> = attributes.iter().chain([blinding]).collect();
    hash_var(Domain::Commitment, &fields)
}

pub(crate) fn revocation_tag_var(
    id: &FpVar<Fr>,
    epoch: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var(Domain::RevocationTag, &[id, epoch])
}

/// Allocates a signature as a private witness: `R` with an on-curve check, `s` as bits.
pub(crate) fn signature_var(
    cs: &ConstraintSystemRef<Fr>,
    signature: Signature,
) -> Result<(EdwardsVar, Vec<Boolean<Fr>>), SynthesisError> {
    let r = EdwardsVar::new_variable_omit_prime_order_check(
        cs.clone(),
        || Ok(EdwardsProjective::from(signature.r)),
        AllocationMode::Witness,
    )?;
    let s_bits = Vec::new_witness(cs.clone(), || {
        Ok(signature.s.into_bigint().to_bits_le()[..SCALAR_BITS].to_vec())
    })?;
    Ok((r, s_bits))
}

/// Enforces `s·G = R + h·A`. `public_key` must be a point of prime order, which `issuer_point`
/// checks for every issuer key. `R` then has prime order too, or the equation fails.
pub(crate) fn verify_var(
    public_key: &EdwardsVar,
    message: &FpVar<Fr>,
    r: &EdwardsVar,
    s_bits: &[Boolean<Fr>],
) -> Result<(), SynthesisError> {
    assert_eq!(s_bits.len(), SCALAR_BITS);
    let h = hash_var(
        Domain::Signature,
        &[&r.x, &r.y, &public_key.x, &public_key.y, message],
    )?;
    // `to_bits_le` gives the one canonical decomposition, so the prover cannot pick `h + p`.
    let h_bits = h.to_bits_le()?;
    let generator = EdwardsVar::constant(EdwardsProjective::from(EdwardsAffine::generator()));
    let lhs = generator.scalar_mul_le(s_bits.iter())?;
    let rhs = public_key.scalar_mul_le(h_bits.iter())? + r;
    lhs.enforce_equal(&rhs)
}
