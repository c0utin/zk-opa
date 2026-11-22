//! The signed bundle: the verifying keys, input layouts and parameters a service loads.

use crate::{
    groth16::VerifyingKey,
    input::{Field, Issuer, Type},
    wire::{DecodeError, Magic, Reader, Writer},
};

const MAGIC: &Magic = b"ZKBN";

/// The proof system a bundle's keys belong to. The discriminant is its wire tag.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Groth16Bn254 = 1,
}

impl Profile {
    const ALL: [Self; 1] = [Self::Groth16Bn254];
}

impl TryFrom<u8> for Profile {
    type Error = DecodeError;

    fn try_from(tag: u8) -> Result<Self, DecodeError> {
        Self::ALL
            .into_iter()
            .find(|profile| *profile as u8 == tag)
            .ok_or(DecodeError::Invalid)
    }
}

/// The body of a bundle, before it is signed.
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub profile: Profile,
    pub version: u64,
    pub issuer: Issuer,
    /// How far a token's timestamp may be from the verifier's clock, either way.
    pub window_ms: u64,
    /// How old the newest feed update may be before every decision is a deny.
    pub stale_ms: u64,
    /// How many epochs a login lasts: a login epoch `e` is accepted with root epochs
    /// `e..e + session_epochs`.
    pub session_epochs: u64,
    pub login_key: VerifyingKey,
    pub policies: Vec<Policy>,
}

/// One decision path, its input layout and its request verifying key.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub path: String,
    pub layout: Vec<Field>,
    pub key: VerifyingKey,
}

impl Bundle {
    /// The bytes to sign. Attach the signature with `attach_signature`.
    pub fn encode(&self) -> Vec<u8> {
        // No capacity hint: the verifying keys dominate, and a bundle is encoded once.
        let mut writer = Writer::new(MAGIC);
        writer.u8(self.profile as u8);
        writer.u64(self.version);
        writer.ark(&self.issuer.x);
        writer.ark(&self.issuer.y);
        writer.u64(self.window_ms);
        writer.u64(self.stale_ms);
        writer.u64(self.session_epochs);
        writer.ark_bytes(&self.login_key);
        writer.count(self.policies.len());
        for policy in &self.policies {
            writer.bytes(policy.path.as_bytes());
            writer.count(policy.layout.len());
            for field in &policy.layout {
                writer.bytes(field.name.as_bytes());
                writer.u8(field.ty as u8);
            }
            writer.ark_bytes(&policy.key);
        }
        writer.finish()
    }

    /// Decodes a bundle body without checking any signature, for tools that only display it.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(body, MAGIC)?;
        let profile = Profile::try_from(reader.u8()?)?;
        let version = reader.u64()?;
        let issuer = Issuer {
            x: reader.field()?,
            y: reader.field()?,
        };
        let window_ms = reader.u64()?;
        let stale_ms = reader.u64()?;
        let session_epochs = reader.u64()?;
        let login_key = reader.ark_bytes()?;
        let policies = (0..reader.count()?)
            .map(|_| {
                let path = reader.str()?.to_owned();
                let layout = (0..reader.count()?)
                    .map(|_| {
                        Ok(Field {
                            name: reader.str()?.to_owned(),
                            ty: Type::try_from(reader.u8()?)?,
                        })
                    })
                    .collect::<Result<Vec<_>, DecodeError>>()?;
                if has_duplicate(&layout, |field| &field.name) {
                    return Err(DecodeError::Duplicate);
                }
                let key = reader.ark_bytes()?;
                Ok(Policy { path, layout, key })
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        if has_duplicate(&policies, |policy| &policy.path) {
            return Err(DecodeError::Duplicate);
        }
        reader.finish()?;
        Ok(Self {
            profile,
            version,
            issuer,
            window_ms,
            stale_ms,
            session_epochs,
            login_key,
            policies,
        })
    }
}

/// Whether two items have the same name. Quadratic, which is cheaper than hashing for the few
/// entries of a bundle.
fn has_duplicate<T>(items: &[T], name: impl Fn(&T) -> &str) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(i, item)| items[..i].iter().any(|other| name(other) == name(item)))
}
