//! The proof token the client sends with each request.

use ark_bn254::Fr;

use crate::{
    groth16::{PROOF_LEN, Proof},
    wire::{DecodeError, FIELD_LEN, HEADER_LEN, Magic, Reader, U64_LEN, Writer},
};

const MAGIC: &Magic = b"ZKTK";

/// The length of encoded [`Claims`]: `commitment`, `tag` and `nonce` are field elements, the
/// rest `u64`s.
const CLAIMS_LEN: usize = 3 * FIELD_LEN + 3 * U64_LEN;

/// The length of an encoded token.
pub const TOKEN_LEN: usize = HEADER_LEN + CLAIMS_LEN + 2 * PROOF_LEN;

/// What a token states, and so what its two proofs are checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claims {
    /// The session commitment `C`.
    pub commitment: Fr,
    /// The revocation tag `T`.
    pub tag: Fr,
    pub login_epoch: u64,
    /// When the client made the request proof, in milliseconds.
    pub ts: u64,
    pub nonce: Fr,
    /// The revocation epoch the request proof was made against.
    pub root_epoch: u64,
}

/// The proof token: the claims, then the login proof and the request proof.
#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub claims: Claims,
    pub login_proof: Proof,
    pub request_proof: Proof,
}

impl Token {
    pub fn encode(&self) -> Vec<u8> {
        let Claims {
            commitment,
            tag,
            login_epoch,
            ts,
            nonce,
            root_epoch,
        } = self.claims;
        let mut writer = Writer::with_capacity(MAGIC, TOKEN_LEN);
        writer.ark(&commitment);
        writer.ark(&tag);
        writer.u64(login_epoch);
        writer.u64(ts);
        writer.ark(&nonce);
        writer.u64(root_epoch);
        writer.ark(&self.login_proof);
        writer.ark(&self.request_proof);
        let bytes = writer.finish();
        assert_eq!(bytes.len(), TOKEN_LEN);
        bytes
    }
}

/// A token with its proofs left undecoded: decompressing and subgroup-checking the points costs
/// more than every other check, so it waits until the proof is verified.
pub(crate) struct Encoded<'a> {
    pub(crate) claims: Claims,
    pub(crate) login_proof: &'a [u8],
    pub(crate) request_proof: &'a [u8],
}

impl<'a> Encoded<'a> {
    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes, MAGIC)?;
        let claims = Claims {
            commitment: reader.field()?,
            tag: reader.field()?,
            login_epoch: reader.u64()?,
            ts: reader.u64()?,
            nonce: reader.field()?,
            root_epoch: reader.u64()?,
        };
        let login_proof = reader.raw(PROOF_LEN)?;
        let request_proof = reader.raw(PROOF_LEN)?;
        reader.finish()?;
        Ok(Self {
            claims,
            login_proof,
            request_proof,
        })
    }
}
