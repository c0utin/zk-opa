//! The signed feed update: revocations and accepted revocation roots.

use ark_bn254::Fr;

use crate::wire::{COUNT_LEN, DecodeError, FIELD_LEN, HEADER_LEN, Magic, Reader, U64_LEN, Writer};

const MAGIC: &Magic = b"ZKFD";

/// The length of the fixed part: three `u64`s and the two list counts.
const FIXED_LEN: usize = HEADER_LEN + 3 * U64_LEN + 2 * COUNT_LEN;

/// The length of one `(epoch, root)` entry.
const ROOT_LEN: usize = U64_LEN + FIELD_LEN;

/// The body of a feed update, before it is signed.
///
/// Each update is a complete snapshot that replaces the previous one, so a verifier that missed
/// an update loses nothing by applying the next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedUpdate {
    /// Strictly increasing from one update to the next, starting at 1.
    pub sequence: u64,
    pub issued_ms: u64,
    /// Verifiers whose bundle is older than this deny every request.
    pub min_bundle_version: u64,
    /// Revoked revocation tags, in any order.
    pub revoked: Vec<Fr>,
    /// Accepted revocation roots as `(epoch, root)`, in any order.
    pub roots: Vec<(u64, Fr)>,
}

impl FeedUpdate {
    /// The state before any update: no update ever reads as fresh.
    pub(crate) const NONE: Self = Self {
        sequence: 0,
        issued_ms: 0,
        min_bundle_version: 0,
        revoked: Vec::new(),
        roots: Vec::new(),
    };

    /// The bytes to sign. Attach the signature with `attach_signature`.
    pub fn encode(&self) -> Vec<u8> {
        let len = FIXED_LEN + FIELD_LEN * self.revoked.len() + ROOT_LEN * self.roots.len();
        let mut writer = Writer::with_capacity(MAGIC, len);
        writer.u64(self.sequence);
        writer.u64(self.issued_ms);
        writer.u64(self.min_bundle_version);
        writer.count(self.revoked.len());
        for tag in &self.revoked {
            writer.ark(tag);
        }
        writer.count(self.roots.len());
        for (epoch, root) in &self.roots {
            writer.u64(*epoch);
            writer.ark(root);
        }
        writer.finish()
    }

    /// Decodes a feed update body. The lists come back sorted.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(body, MAGIC)?;
        let sequence = reader.u64()?;
        let issued_ms = reader.u64()?;
        let min_bundle_version = reader.u64()?;
        let mut revoked = (0..reader.count()?)
            .map(|_| reader.field())
            .collect::<Result<Vec<_>, _>>()?;
        let mut roots = (0..reader.count()?)
            .map(|_| Ok((reader.u64()?, reader.field()?)))
            .collect::<Result<Vec<_>, DecodeError>>()?;
        reader.finish()?;

        // Sorted, so lookups are binary searches and duplicates are neighbours.
        revoked.sort_unstable();
        roots.sort_unstable_by_key(|(epoch, _)| *epoch);
        if revoked.windows(2).any(|pair| pair[0] == pair[1])
            || roots.windows(2).any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(DecodeError::Duplicate);
        }
        Ok(Self {
            sequence,
            issued_ms,
            min_bundle_version,
            revoked,
            roots,
        })
    }

    /// Requires the lists to be sorted, as `decode` leaves them.
    pub(crate) fn root(&self, epoch: u64) -> Option<Fr> {
        self.roots
            .binary_search_by_key(&epoch, |&(epoch, _)| epoch)
            .ok()
            .map(|index| self.roots[index].1)
    }

    pub(crate) fn is_revoked(&self, tag: &Fr) -> bool {
        self.revoked.binary_search(tag).is_ok()
    }
}
