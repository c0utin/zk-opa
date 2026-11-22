//! Reading and writing the plain files the commands pass between them.
//!
//! Keys are raw bytes: an Ed25519 secret or public key as `ed25519_dalek` encodes it, an issuer
//! secret key one field element, and an issuer public key its two coordinates.

use std::{fs, io::Write, path::Path};

use anyhow::{Context, bail};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SigningKey};
use serde_json::{Map, Value as Json};
use zkopa_kernel::{Issuer, Value};
use zkopa_prove::{Fr, IssuerKey};

// The kernel does not export these yet; they belong next to `Issuer` and `IssuerKey`.
/// The compressed size of a BN254 scalar, and of a BabyJubJub scalar, which is smaller.
const FIELD_LEN: usize = 32;
/// An issuer secret key is one BabyJubJub scalar.
const ISSUER_SECRET_LEN: usize = FIELD_LEN;
/// An issuer public key is its two affine coordinates, `x` then `y`.
const ISSUER_PUBLIC_LEN: usize = 2 * FIELD_LEN;

/// Only the owner may read or write a secret key file.
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

pub fn read(path: &Path) -> anyhow::Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

pub fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Writes a file only its owner can read.
pub fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, SECRET_FILE_MODE);
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .with_context(|| format!("writing {}", path.display()))
}

/// Reads a file that must be exactly `N` bytes.
fn read_array<const N: usize>(path: &Path) -> anyhow::Result<[u8; N]> {
    <[u8; N]>::try_from(read(path)?.as_slice())
        .map_err(|_| anyhow::anyhow!("{} is not {N} bytes", path.display()))
}

pub fn root_key(path: &Path) -> anyhow::Result<SigningKey> {
    read_array::<SECRET_KEY_LENGTH>(path).map(|bytes| SigningKey::from_bytes(&bytes))
}

pub fn root_public(path: &Path) -> anyhow::Result<[u8; PUBLIC_KEY_LENGTH]> {
    read_array(path)
}

pub fn issuer_key(path: &Path) -> anyhow::Result<IssuerKey> {
    IssuerKey::from_bytes(&read_array::<ISSUER_SECRET_LEN>(path)?)
        .with_context(|| format!("{} is not an issuer key", path.display()))
}

pub fn issuer_public_bytes(issuer: Issuer) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ISSUER_PUBLIC_LEN);
    (issuer.x, issuer.y)
        .serialize_compressed(&mut bytes)
        .expect("writing to a Vec cannot fail");
    debug_assert_eq!(bytes.len(), ISSUER_PUBLIC_LEN);
    bytes
}

pub fn issuer_public(path: &Path) -> anyhow::Result<Issuer> {
    let bytes = read_array::<ISSUER_PUBLIC_LEN>(path)?;
    // Exactly two compressed coordinates, so the pair consumes every byte.
    <(Fr, Fr)>::deserialize_compressed(bytes.as_slice())
        .map(|(x, y)| Issuer { x, y })
        .with_context(|| format!("{} is not an issuer public key", path.display()))
}

/// Puts `--attr` values in schema order, requiring each schema attribute exactly once.
pub fn attributes(schema: &[String], attrs: &[(String, u64)]) -> anyhow::Result<Vec<u64>> {
    if attrs.len() != schema.len() {
        bail!(
            "expected one --attr for each of {}, got {}",
            schema.join(","),
            attrs.len()
        );
    }
    schema
        .iter()
        .map(|name| {
            attrs
                .iter()
                .find(|(attr, _)| attr == name)
                .map(|&(_, value)| value)
                .with_context(|| format!("missing --attr {name}=..."))
        })
        .collect()
}

/// Reads `input.json`: a flat object of field name to number, boolean or string.
pub fn input_json(path: &Path) -> anyhow::Result<Map<String, Json>> {
    let json: Json = serde_json::from_slice(&read(path)?)
        .with_context(|| format!("parsing {}", path.display()))?;
    match json {
        Json::Object(map) => Ok(map),
        _ => bail!("{} is not a JSON object", path.display()),
    }
}

/// The kernel's `input`: a number is `u64`, a boolean `bool` and a string `bytes`.
pub fn input(json: &Map<String, Json>) -> anyhow::Result<Vec<(&str, Value<'_>)>> {
    json.iter()
        .map(|(name, value)| {
            let value = match value {
                Json::Bool(value) => Value::Bool(*value),
                Json::String(value) => Value::Bytes(value.as_bytes()),
                Json::Number(number) => Value::U64(
                    number
                        .as_u64()
                        .with_context(|| format!("input {name} is not a u64"))?,
                ),
                _ => bail!("input {name} is not a number, boolean or string"),
            };
            Ok((name.as_str(), value))
        })
        .collect()
}
