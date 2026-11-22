//! The policy author's commands: build, inspect and eval.

use std::{fs, path::Path, path::PathBuf};

use anyhow::{Context, bail};
use rand::rngs::OsRng;
use zkopa_ir::Schema;
use zkopa_kernel::{Bundle, SIGNATURE_LEN, Type, Value};
use zkopa_prove::Params;

use crate::{files, issuer::sign};

fn compile(path: &Path, schema: &Schema) -> anyhow::Result<Vec<zkopa_ir::Policy>> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    zkopa_policy::compile(&source, schema).with_context(|| format!("compiling {}", path.display()))
}

fn schema(names: Vec<String>) -> anyhow::Result<Schema> {
    Schema::new(names).context("invalid --schema")
}

const SECOND_MS: u64 = 1_000;
const HOUR_MS: u64 = 60 * 60 * SECOND_MS;

/// The bundle version `build` signs unless `--version` says otherwise.
pub const DEFAULT_VERSION: u64 = 1;
/// Room for clock skew and network delay between a client and a service.
pub const DEFAULT_WINDOW_MS: u64 = 30 * SECOND_MS;
/// How long a service keeps allowing requests when it stops receiving feed updates.
pub const DEFAULT_STALE_MS: u64 = HOUR_MS;
/// A login covers the epoch it was made in and the next one.
pub const DEFAULT_SESSION_EPOCHS: u64 = 2;

pub struct Build {
    /// Rego v1 modules. Each rule becomes one decision path.
    pub policies: Vec<PathBuf>,
    /// The credential attributes, in order, as `input.subject.<name>`.
    pub schema: Vec<String>,
    /// The root Ed25519 secret key that signs the bundle.
    pub root_key: PathBuf,
    /// The issuer's public key.
    pub issuer: PathBuf,
    pub out: PathBuf,
    pub prover_out: PathBuf,
    pub version: u64,
    /// How far a token's timestamp may be from the service's clock.
    pub window_ms: u64,
    /// How old the newest feed update may be before every request is denied.
    pub stale_ms: u64,
    /// How many epochs a login lasts.
    pub session_epochs: u64,
}

pub fn build(args: Build) -> anyhow::Result<()> {
    let root = files::root_key(&args.root_key)?;
    let issuer = files::issuer_public(&args.issuer)?;
    let schema = schema(args.schema)?;
    // Every module's rules, in the order the modules were given.
    let policies = args
        .policies
        .iter()
        .try_fold(Vec::new(), |mut policies, path| {
            policies.extend(compile(path, &schema)?);
            anyhow::Ok(policies)
        })?;
    let params = Params {
        version: args.version,
        window_ms: args.window_ms,
        stale_ms: args.stale_ms,
        session_epochs: args.session_epochs,
    };
    let (bundle, prover) = zkopa_prove::setup(schema, issuer, params, policies, &mut OsRng)
        .context("running the setup")?;
    files::write(&args.out, &sign(&root, bundle.encode()))?;
    files::write(&args.prover_out, &prover.encode())
}

/// Prints the bundle without checking its signature: it is for reading, not for trusting.
pub fn inspect(path: &Path) -> anyhow::Result<()> {
    let bytes = files::read(path)?;
    let body = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .map(|len| &bytes[..len])
        .with_context(|| format!("{} is too short", path.display()))?;
    let bundle = Bundle::decode(body).with_context(|| format!("decoding {}", path.display()))?;
    println!(
        "version {}, window {} ms, stale after {} ms, sessions last {} epochs",
        bundle.version, bundle.window_ms, bundle.stale_ms, bundle.session_epochs
    );
    for policy in &bundle.policies {
        println!("{}", policy.path);
        for field in &policy.layout {
            let ty = match field.ty {
                Type::U64 => "u64",
                Type::Bool => "bool",
                Type::Bytes => "bytes",
            };
            println!("  {} {ty}", field.name);
        }
    }
    Ok(())
}

pub struct Eval {
    pub policy_file: PathBuf,
    pub schema: Vec<String>,
    /// The decision path, such as `transfers/create/allow`.
    pub policy: String,
    pub input: PathBuf,
    /// One credential attribute, as name=value.
    pub attrs: Vec<(String, u64)>,
}

pub fn eval(args: Eval) -> anyhow::Result<()> {
    let attributes = files::attributes(&args.schema, &args.attrs)?;
    let policies = compile(&args.policy_file, &schema(args.schema)?)?;
    let policy = policies
        .iter()
        .find(|policy| policy.path() == args.policy)
        .with_context(|| format!("{} has no rule {}", args.policy_file.display(), args.policy))?;
    let json = files::input_json(&args.input)?;
    let input = files::input(&json)?;
    // The kernel denies extra fields, so the evaluator refuses them too.
    if input.len() != policy.inputs().len() {
        bail!(
            "{} needs exactly the fields {}",
            args.policy,
            policy
                .inputs()
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let values = policy
        .inputs()
        .iter()
        .map(|field| {
            let (_, value) = input
                .iter()
                .find(|(name, _)| *name == field.name)
                .with_context(|| format!("input has no field {}", field.name))?;
            Ok(match *value {
                Value::U64(v) => zkopa_ir::Value::U64(v),
                Value::Bool(v) => zkopa_ir::Value::Bool(v),
                Value::Bytes(v) => zkopa_ir::Value::Bytes(v),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let allowed = policy
        .eval(&values, &attributes)
        .with_context(|| format!("evaluating {}", args.policy))?;
    println!("{allowed}");
    Ok(())
}
