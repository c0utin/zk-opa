//! The binary layout every message shares: a four-byte magic, a version byte, then fields in a
//! fixed order. Integers are little-endian, counts and lengths are `u32`, field elements are
//! [`FIELD_LEN`] canonical little-endian bytes, and a message has no trailing bytes.
//!
//! The prover writes its own files with the same [`Writer`] and [`Reader`].

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::{Signature, VerifyingKey};

/// The only version of each message this kernel reads and writes.
const VERSION: u8 = 1;

/// The length of the magic that names a message's kind.
pub const MAGIC_LEN: usize = 4;

/// A message's kind, its first bytes.
pub type Magic = [u8; MAGIC_LEN];

/// The length of the magic and version that start every message.
pub const HEADER_LEN: usize = MAGIC_LEN + size_of::<u8>();

/// The length of an encoded `u64`.
pub const U64_LEN: usize = size_of::<u64>();

/// The length of an encoded count or length prefix, a `u32`.
pub const COUNT_LEN: usize = size_of::<u32>();

/// The length of an encoded BN254 scalar field element.
pub const FIELD_LEN: usize = 32;

/// The length of the Ed25519 signature that ends a signed bundle or feed update.
pub const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Why a message could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("the message ends early")]
    Truncated,
    #[error("the message has trailing bytes")]
    Trailing,
    #[error("the message is not of the expected kind")]
    Magic,
    #[error("the message has unknown version {0}")]
    Version(u8),
    #[error("the message holds a value out of range")]
    Invalid,
    #[error("the message holds a duplicate entry")]
    Duplicate,
}

/// Appends a signature made elsewhere over `body`, the output of a body type's `encode`, to make
/// the signed message `body || signature` that `Verifier::new` and `Verifier::apply_feed` take.
pub fn attach_signature(mut body: Vec<u8>, signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
    body.extend_from_slice(signature);
    body
}

/// Splits `body || signature` and returns the body if `root` signed it.
///
/// Bodies start with a magic per message kind, so a signature over a feed update can never pass
/// as one over a bundle.
pub(crate) fn verified_body<'a>(root: &VerifyingKey, signed: &'a [u8]) -> Option<&'a [u8]> {
    let split = signed.len().checked_sub(SIGNATURE_LEN)?;
    let (body, signature) = signed.split_at(split);
    let signature = Signature::from_slice(signature).ok()?;
    root.verify_strict(body, &signature).ok()?;
    Some(body)
}

/// Writes one message.
pub struct Writer(Vec<u8>);

impl Writer {
    /// Starts a message of kind `magic`.
    pub fn new(magic: &Magic) -> Self {
        Self::with_capacity(magic, HEADER_LEN)
    }

    /// Starts a message of kind `magic` that will take about `capacity` bytes in total.
    pub fn with_capacity(magic: &Magic, capacity: usize) -> Self {
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(magic);
        bytes.push(VERSION);
        Self(bytes)
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    pub fn count(&mut self, count: usize) {
        let count = u32::try_from(count).expect("a message holds fewer than 2^32 entries");
        self.0.extend_from_slice(&count.to_le_bytes());
    }

    /// Writes `bytes` behind a length prefix.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    /// Writes an arkworks value in its compressed form, with no length prefix.
    pub fn ark(&mut self, value: &impl CanonicalSerialize) {
        value
            .serialize_compressed(&mut self.0)
            .expect("a Vec accepts every write");
    }

    /// Writes an arkworks value in its compressed form behind a length prefix.
    pub fn ark_bytes(&mut self, value: &impl CanonicalSerialize) {
        self.count(value.compressed_size());
        self.ark(value);
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reads one message, front to back.
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Checks that `bytes` starts with `magic` and the version this crate writes.
    pub fn new(bytes: &'a [u8], magic: &Magic) -> Result<Self, DecodeError> {
        let mut reader = Self(bytes);
        if reader.array()? != *magic {
            return Err(DecodeError::Magic);
        }
        match reader.u8()? {
            VERSION => Ok(reader),
            version => Err(DecodeError::Version(version)),
        }
    }

    /// Reads the next `len` bytes as they are.
    pub fn raw(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self.0.split_at_checked(len).ok_or(DecodeError::Truncated)?;
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, tail) = self.0.split_first_chunk().ok_or(DecodeError::Truncated)?;
        self.0 = tail;
        Ok(*head)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        self.array().map(u8::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        self.array().map(u64::from_le_bytes)
    }

    pub fn count(&mut self) -> Result<usize, DecodeError> {
        self.array().map(|count| u32::from_le_bytes(count) as usize)
    }

    /// A count of entries that take at least `min_len` bytes each. A count the remaining bytes
    /// cannot hold is refused, which bounds what decoding allocates.
    pub fn bounded_count(&mut self, min_len: usize) -> Result<usize, DecodeError> {
        let count = self.count()?;
        if count.saturating_mul(min_len) > self.0.len() {
            return Err(DecodeError::Truncated);
        }
        Ok(count)
    }

    /// Reads length-prefixed bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.count()?;
        self.raw(len)
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        str::from_utf8(self.bytes()?).map_err(|_| DecodeError::Invalid)
    }

    /// Reads a field element, rejecting any encoding of a value at or above the modulus.
    pub fn field(&mut self) -> Result<Fr, DecodeError> {
        self.ark(FIELD_LEN)
    }

    /// Reads an arkworks value that must fill exactly `len` bytes. Field elements must be
    /// canonical, and points are checked to be on the curve and in the prime-order subgroup.
    pub fn ark<T: CanonicalDeserialize>(&mut self, len: usize) -> Result<T, DecodeError> {
        let mut bytes = self.raw(len)?;
        let value = T::deserialize_compressed(&mut bytes).map_err(|_| DecodeError::Invalid)?;
        bytes
            .is_empty()
            .then_some(value)
            .ok_or(DecodeError::Invalid)
    }

    /// Reads a length-prefixed arkworks value.
    pub fn ark_bytes<T: CanonicalDeserialize>(&mut self) -> Result<T, DecodeError> {
        let len = self.count()?;
        self.ark(len)
    }

    /// Requires that nothing is left.
    pub fn finish(self) -> Result<(), DecodeError> {
        self.0.is_empty().then_some(()).ok_or(DecodeError::Trailing)
    }
}
