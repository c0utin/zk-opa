//! The login proof: made once per session, it checks the credential and publishes `C` and `T`.

use ark_bn254::Fr;
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zkopa_kernel::Issuer;

use crate::{
    U64_BITS, enforce_bits, input,
    issuer::{
        SignedCredential, commitment, commitment_var, digest_var, revocation_tag,
        revocation_tag_var, signature_var, verify_var,
    },
    tree::{DEPTH, RevocationTree, root_var},
    witness,
};

/// Proves, for a hidden credential:
///
/// 1. the issuer signed it;
/// 2. its id is not in the revocation tree;
/// 3. it has not expired at `epoch`;
/// 4. `commitment` is `C`, a commitment to its attributes;
/// 5. `tag` is `T`, its revocation tag for `epoch`.
///
/// The public inputs are allocated in the kernel's login order (`zkopa_kernel::login_inputs`).
#[derive(Clone, Copy, Debug)]
pub struct LoginCircuit<'a> {
    pub issuer: Issuer,
    pub revocation_root: Fr,
    pub epoch: u64,
    pub commitment: Fr,
    pub tag: Fr,
    pub credential: &'a SignedCredential,
    pub blinding: Fr,
    pub siblings: [Fr; DEPTH],
}

impl<'a> LoginCircuit<'a> {
    /// The honest circuit for logging in with `credential` at `epoch`.
    pub fn new(
        issuer: Issuer,
        credential: &'a SignedCredential,
        revoked: &RevocationTree,
        epoch: u64,
        blinding: Fr,
    ) -> Self {
        let id = credential.credential.id;
        Self {
            issuer,
            revocation_root: revoked.root(),
            epoch,
            commitment: commitment(&credential.credential.attributes, blinding),
            tag: revocation_tag(id, epoch),
            credential,
            blinding,
            siblings: revoked.siblings(id),
        }
    }
}

impl ConstraintSynthesizer<Fr> for LoginCircuit<'_> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // The issuer key comes from the verifier's bundle, and setup checked it is a point of
        // prime order, so it needs no check here.
        let issuer = EdwardsVar::new(input(&cs, self.issuer.x)?, input(&cs, self.issuer.y)?);
        let revocation_root = input(&cs, self.revocation_root)?;
        let epoch = input(&cs, self.epoch)?;
        let commitment = input(&cs, self.commitment)?;
        let tag = input(&cs, self.tag)?;

        let credential = &self.credential.credential;
        let id = witness(&cs, credential.id)?;
        let attributes = credential
            .attributes
            .iter()
            .map(|&a| witness(&cs, a))
            .collect::<Result<Vec<_>, _>>()?;
        let exp = witness(&cs, credential.exp)?;
        let blinding = witness(&cs, self.blinding)?;
        let siblings = Vec::new_witness(cs.clone(), || Ok(self.siblings))?;
        let (r, s_bits) = signature_var(&cs, self.credential.signature)?;

        // 1. The issuer signed this credential. The attributes and `exp` need no range check:
        //    the issuer only signs `u64`s, so a signed value is below 2^64.
        let digest = digest_var(&id, &attributes, &exp)?;
        verify_var(&issuer, &digest, &r, &s_bits)?;

        // 2. The leaf at the credential's id is 0. Splitting the id into exactly `DEPTH` bits
        //    also ties the path to the id.
        let (id_bits, _) = id.to_bits_le_with_top_bits_zero(DEPTH)?;
        root_var(FpVar::zero(), &id_bits, &siblings)?.enforce_equal(&revocation_root)?;

        // 3. `epoch < exp`: both below 2^64 (`epoch` is a u64 from the verifier), so
        //    `exp - epoch - 1` fits in 64 bits exactly when it did not wrap around the field.
        enforce_bits(&(&exp - &epoch - Fr::from(1u64)), U64_BITS)?;

        // 4. and 5.
        commitment_var(&attributes, &blinding)?.enforce_equal(&commitment)?;
        revocation_tag_var(&id, &epoch)?.enforce_equal(&tag)
    }
}
