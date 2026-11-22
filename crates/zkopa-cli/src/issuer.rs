//! The issuer's commands: keys, credentials and feed updates.

use std::{collections::BTreeSet, fs, path::Path, path::PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::{SECRET_KEY_LENGTH, Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use zkopa_kernel::{FeedUpdate, attach_signature};
use zkopa_prove::{Credential, IssuerKey, RevocationTree, revocation_tag};

use crate::files;

pub fn keygen(out: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let mut secret = [0; SECRET_KEY_LENGTH];
    OsRng.fill_bytes(&mut secret);
    let root = SigningKey::from_bytes(&secret);
    let issuer = IssuerKey::generate(&mut OsRng);
    files::write_secret(&out.join("root.key"), &root.to_bytes())?;
    files::write(&out.join("root.pub"), &root.verifying_key().to_bytes())?;
    files::write_secret(&out.join("issuer.key"), &issuer.to_bytes())?;
    files::write(
        &out.join("issuer.pub"),
        &files::issuer_public_bytes(issuer.public()),
    )
}

pub fn sign(root: &SigningKey, body: Vec<u8>) -> Vec<u8> {
    let signature = root.sign(&body).to_bytes();
    attach_signature(body, &signature)
}

/// The revocation tree with exactly `ids` revoked.
pub fn revocation_tree(ids: impl IntoIterator<Item = u32>) -> RevocationTree {
    let mut tree = RevocationTree::default();
    for id in ids {
        tree.revoke(id);
    }
    tree
}

pub struct Issue {
    pub issuer_key: PathBuf,
    /// The credential attributes, in the order the bundle was built with.
    pub schema: Vec<String>,
    /// The credential's leaf in the revocation tree.
    pub id: u32,
    /// One attribute value, as name=value.
    pub attrs: Vec<(String, u64)>,
    /// The first login epoch at which the credential is no longer valid.
    pub exp: u64,
    pub out: PathBuf,
}

pub fn issue(args: Issue) -> anyhow::Result<()> {
    let issuer = files::issuer_key(&args.issuer_key)?;
    let credential = Credential {
        id: args.id,
        attributes: files::attributes(&args.schema, &args.attrs)?,
        exp: args.exp,
    };
    files::write_secret(&args.out, &issuer.sign(credential, &mut OsRng).encode())
}

pub struct Feed {
    pub root_key: PathBuf,
    /// Higher than the sequence of every earlier update.
    pub sequence: u64,
    /// The current revocation epoch.
    pub epoch: u64,
    /// Every revoked credential id, not only the new ones: each update is a whole snapshot.
    pub revoke_ids: Vec<u32>,
    /// The bundle's session length, so live sessions of revoked ids are revoked too.
    pub session_epochs: u64,
    pub min_bundle_version: u64,
    pub out: PathBuf,
}

pub fn feed(args: Feed, now_ms: u64) -> anyhow::Result<()> {
    if args.session_epochs == 0 {
        bail!("--session-epochs must be at least 1");
    }
    let root = files::root_key(&args.root_key)?;
    // The kernel rejects a feed listing a tag twice.
    let ids: BTreeSet<u32> = args.revoke_ids.into_iter().collect();
    let revocation_root = revocation_tree(ids.iter().copied()).root();
    // Only the ids are kept, not past trees, so every epoch a live session may have logged in
    // at gets today's root, and a session that logged in before the last revocation logs in
    // again.
    let first_epoch = args.epoch.saturating_sub(args.session_epochs - 1);
    let update = FeedUpdate {
        sequence: args.sequence,
        issued_ms: now_ms,
        min_bundle_version: args.min_bundle_version,
        revoked: ids
            .iter()
            .flat_map(|&id| (first_epoch..=args.epoch).map(move |epoch| revocation_tag(id, epoch)))
            .collect(),
        roots: (first_epoch..=args.epoch)
            .map(|epoch| (epoch, revocation_root))
            .collect(),
    };
    files::write(&args.out, &sign(&root, update.encode()))
}
