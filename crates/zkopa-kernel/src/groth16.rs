//! Groth16 verification on BN254, without the prover's dependencies.
//!
//! The types serialize exactly like `ark-groth16` 0.6's, field for field, so keys and proofs
//! made by the prover decode here unchanged.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    CurveGroup, VariableBaseMSM,
    pairing::{Pairing, PairingOutput},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type G1Prepared = <Bn254 as Pairing>::G1Prepared;
type G2Prepared = <Bn254 as Pairing>::G2Prepared;

/// The length of a compressed G1 point: one base-field coordinate and a flag in its spare bits.
const G1_LEN: usize = 32;

/// The length of a compressed G2 point: two base-field elements.
const G2_LEN: usize = 2 * G1_LEN;

/// The length of a compressed proof: two G1 points and one G2 point.
pub const PROOF_LEN: usize = 2 * G1_LEN + G2_LEN;

/// A Groth16 verifying key on BN254.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    /// One point for the constant 1, then one per public input.
    pub gamma_abc_g1: Vec<G1Affine>,
}

impl VerifyingKey {
    /// How many public inputs the key takes.
    pub fn inputs(&self) -> usize {
        self.gamma_abc_g1.len().saturating_sub(1)
    }
}

/// A Groth16 proof on BN254.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// A verifying key with the parts that do not depend on the proof computed once.
pub struct PreparedVerifyingKey {
    gamma_abc_g1: Vec<G1Affine>,
    alpha_g1_beta_g2: PairingOutput<Bn254>,
    gamma_g2_neg: G2Prepared,
    delta_g2_neg: G2Prepared,
}

impl PreparedVerifyingKey {
    pub fn new(key: VerifyingKey) -> Self {
        Self {
            alpha_g1_beta_g2: Bn254::pairing(key.alpha_g1, key.beta_g2),
            gamma_g2_neg: (-key.gamma_g2).into(),
            delta_g2_neg: (-key.delta_g2).into(),
            gamma_abc_g1: key.gamma_abc_g1,
        }
    }

    /// Checks `e(A, B) · e(Σ, -γ) · e(C, -δ) = e(α, β)`, where `Σ` is `gamma_abc[0]` plus each
    /// input times its `gamma_abc` point. The proof's points must have been validated, as
    /// deserializing it does. False if `inputs` is not as long as the key expects.
    pub fn verify(&self, proof: &Proof, inputs: &[Fr]) -> bool {
        let Some((constant, bases)) = self.gamma_abc_g1.split_first() else {
            return false;
        };
        let Ok(sum) = G1Projective::msm(bases, inputs) else {
            return false;
        };
        let g1: [G1Prepared; 3] = [
            proof.a.into(),
            (sum + constant).into_affine().into(),
            proof.c.into(),
        ];
        // The pairing takes its G2 side by value, and the prepared lines are a `Vec`; the copy
        // is small beside the Miller loop.
        let g2: [G2Prepared; 3] = [
            proof.b.into(),
            self.gamma_g2_neg.clone(),
            self.delta_g2_neg.clone(),
        ];
        Bn254::final_exponentiation(Bn254::multi_miller_loop(g1, g2))
            .is_some_and(|product| product == self.alpha_g1_beta_g2)
    }
}
