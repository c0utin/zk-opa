//! The request proof: made for every request, it opens `C` and checks one compiled policy.

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use zkopa_ir::{Node, NodeId, Policy, Type};
use zkopa_kernel::{REQUEST_FIXED_INPUTS, encode_bytes};

use crate::{Error, U64_BITS, enforce_bits, input, issuer::commitment_var, witness};

/// Proves that the attributes committed to in `C` satisfy `policy` for the request's `input`.
///
/// The public inputs are the kernel's request inputs (`zkopa_kernel::request_inputs`): `C`,
/// audience, decision path, ts, nonce, root epoch, then the `input` fields in layout order. All
/// but `C` and the fields appear in no constraint; they are public only to bind the proof.
#[derive(Clone, Copy, Debug)]
pub struct RequestCircuit<'a> {
    policy: &'a Policy,
    public: &'a [Fr],
    attributes: &'a [u64],
    blinding: Fr,
}

impl<'a> RequestCircuit<'a> {
    /// `public` is what `zkopa_kernel::request_inputs` returns for the request; `attributes`
    /// follow the schema and open `C` with `blinding`.
    pub fn new(
        policy: &'a Policy,
        public: &'a [Fr],
        attributes: &'a [u64],
        blinding: Fr,
    ) -> Result<Self, Error> {
        if public.len() != REQUEST_FIXED_INPUTS + policy.inputs().len() {
            return Err(Error::InputMismatch);
        }
        if attributes.len() != policy.attributes() as usize {
            return Err(Error::Schema {
                expected: policy.attributes() as usize,
                actual: attributes.len(),
            });
        }
        Ok(Self {
            policy,
            public,
            attributes,
            blinding,
        })
    }
}

impl ConstraintSynthesizer<Fr> for RequestCircuit<'_> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = self
            .public
            .iter()
            .map(|&value| input(&cs, value))
            .collect::<Result<Vec<_>, _>>()?;
        let (fixed, fields) = public.split_at(REQUEST_FIXED_INPUTS);
        let attributes = self
            .attributes
            .iter()
            .map(|&value| witness(&cs, value))
            .collect::<Result<Vec<_>, _>>()?;
        let blinding = witness(&cs, self.blinding)?;
        commitment_var(&attributes, &blinding)?.enforce_equal(&fixed[0])?;

        // One variable per node. A boolean node is a field element known to be 0 or 1: the
        // inputs are (the kernel encodes `bool` as 0/1), and every gate below keeps it so. That
        // makes `not` free and `and`, `or` and boolean equality one product each.
        let policy = self.policy;
        let width = |id: NodeId| match policy.types()[id.index()] {
            Type::Int { bits } => bits as usize,
            _ => unreachable!("the type check makes this operand an integer"),
        };
        let mut vars: Vec<FpVar<Fr>> = Vec::with_capacity(policy.nodes().len());
        for &node in policy.nodes() {
            let var = |id: NodeId| &vars[id.index()];
            let value = match node {
                Node::Int(c) => FpVar::Constant(Fr::from(c)),
                Node::Bool(b) => FpVar::Constant(Fr::from(b)),
                Node::Bytes(i) => FpVar::Constant(encode_bytes(policy.bytes(i))),
                // Inputs are below 2^64 or 0/1 because the kernel encodes them so. The handle
                // is cloned because the field's variable is also the node's.
                Node::Input(k) => fields[k as usize].clone(),
                // Nodes are shared, so each attribute is range-checked once, and only if the
                // policy reads it.
                Node::Attribute(k) => {
                    let attribute = &attributes[k as usize];
                    enforce_bits(attribute, U64_BITS)?;
                    attribute.clone()
                }
                Node::Add(a, b) => var(a) + var(b),
                Node::MulConst(a, c) => var(a) * Fr::from(c),
                Node::Lt(a, b) => is_le(var(a), var(b), width(a).max(width(b)), true)?,
                Node::Le(a, b) => is_le(var(a), var(b), width(a).max(width(b)), false)?,
                Node::Eq(a, b) => match policy.types()[a.index()] {
                    // 1 - a - b + 2ab is 1 exactly when two bits agree.
                    Type::Bool => (var(a) * var(b)).double()? - var(a) - var(b) + Fr::one(),
                    // Integers below 2^128 and 248-bit hashes are equal as integers exactly
                    // when they are equal in the field.
                    _ => var(a).is_eq(var(b))?.into(),
                },
                Node::And(a, b) => var(a) * var(b),
                Node::Or(a, b) => var(a) + var(b) - var(a) * var(b),
                Node::Not(a) => FpVar::Constant(Fr::one()) - var(a),
                // The product of `x - s` is 0 exactly when `x` is in the set: each factor is
                // a difference of integers below 2^128, so none wraps to 0.
                Node::In(a, s) => {
                    let product = policy
                        .set(s)
                        .iter()
                        .fold(FpVar::Constant(Fr::one()), |product, &member| {
                            product * (var(a) - Fr::from(member))
                        });
                    product.is_zero()?.into()
                }
            };
            vars.push(value);
        }
        match &vars[policy.root().index()] {
            // `enforce_equal` adds nothing for two constants, so a constant false root needs a
            // constraint no assignment satisfies: 0 · 0 = 1.
            FpVar::Constant(root) if root.is_zero() => {
                cs.enforce_r1cs_constraint(|| lc!(), || lc!(), || Variable::One.into())
            }
            root => root.enforce_equal(&FpVar::Constant(Fr::one())),
        }
    }
}

/// `a < b` when `strict`, else `a <= b`, for `a` and `b` below `2^bits`.
///
/// `b - a - strict + 2^bits` lies in `[0, 2^(bits + 1))` with no wrap around the field, and its
/// bit `bits` is set exactly when `b - a - strict >= 0`. Decomposing it into `bits + 1` bits is
/// the range check on the gap; the decomposition is unique because `2^129` is far below the
/// modulus.
fn is_le(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    bits: usize,
    strict: bool,
) -> Result<FpVar<Fr>, SynthesisError> {
    debug_assert!(bits <= zkopa_ir::MAX_BITS as usize);
    let offset = Fr::from(2u64).pow([bits as u64]) - Fr::from(strict);
    let (mut gap, _) = (b - a + offset).to_bits_le_with_top_bits_zero(bits + 1)?;
    Ok(gap.swap_remove(bits).into())
}
