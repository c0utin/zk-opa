//! Poseidon over the BN254 scalar field, domain-separated by use and by input length.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
    constraints::CryptographicSpongeVar,
    poseidon::{
        PoseidonConfig, PoseidonSponge, constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds,
    },
};
use ark_ff::PrimeField;
use ark_r1cs_std::{GR1CSVar, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

// Protocol constants: changing any of them changes every hash, so every credential, commitment,
// revocation tag and tree root, and every key made by setup.

/// Width 4 (rate 3, capacity 1), so the domain plus two inputs cost one permutation.
const RATE: usize = 3;
const CAPACITY: usize = 1;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const ALPHA: u64 = 5;
/// How many of the generated MDS matrices are skipped: none.
const SKIP_MATRICES: u64 = 0;

/// The separator holds the domain in its low bits and the input length above them.
const DOMAIN_BITS: u32 = u8::BITS;

/// What a hash is used for. The discriminant goes into the separator.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Domain {
    Credential = 1,
    Signature = 2,
    Commitment = 3,
    RevocationTag = 4,
    Node = 5,
}

/// The first element absorbed. The sponge does no padding, so the length goes in here: two
/// inputs of different lengths in one domain can never absorb the same sequence.
fn separator(domain: Domain, len: usize) -> Fr {
    Fr::from(((len as u64) << DOMAIN_BITS) | u64::from(domain as u8))
}

fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            SKIP_MATRICES,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

pub(crate) fn hash(domain: Domain, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.absorb(&separator(domain, inputs.len()));
    for input in inputs {
        sponge.absorb(input);
    }
    sponge.squeeze_native_field_elements(1)[0]
}

/// The same hash inside a circuit. The constraints go into the system the inputs belong to.
pub(crate) fn hash_var(domain: Domain, inputs: &[&FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(inputs.cs(), config());
    sponge.absorb(&FpVar::Constant(separator(domain, inputs.len())))?;
    for input in inputs {
        sponge.absorb(*input)?;
    }
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}
