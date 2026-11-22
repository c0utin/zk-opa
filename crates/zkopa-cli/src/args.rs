//! The command line, parsed by hand into one typed value per command.
//!
//! Every flag takes a value, as `--name value` or `--name=value`, and may appear anywhere after
//! the command, mixed with its positional arguments. Each command's [`Spec`] is the one table
//! of what it accepts: it drives the checks, the defaults and the usage text.

use std::{
    ffi::{OsStr, OsString},
    fmt, iter,
    path::PathBuf,
    str::FromStr,
};

use crate::{issuer, policy, request};

/// A command line that asks for something to run.
pub struct Cli {
    /// The current time in milliseconds since the Unix epoch, instead of the clock.
    pub now_ms: Option<u64>,
    pub command: Command,
}

pub enum Command {
    Keygen { out: PathBuf },
    Build(policy::Build),
    Inspect { bundle: PathBuf },
    Eval(policy::Eval),
    Issue(issuer::Issue),
    Feed(issuer::Feed),
    Prove(request::Prove),
    Verify(request::Verify),
}

pub enum Parsed {
    Run(Cli),
    /// `--help` or `-h` was given: the usage text to print.
    Help(String),
}

/// A command line that does not parse, with the usage text of what it was for.
#[derive(Debug)]
pub struct UsageError {
    message: String,
    usage: String,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {}\n\n{}", self.message, self.usage)
    }
}

/// Parses the arguments after the program name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, UsageError> {
    let general = |message: String| UsageError {
        message,
        usage: general_usage(),
    };
    let tokens = tokens(args).map_err(general)?;
    let mut positionals = tokens.iter().filter_map(Token::positional);
    let spec = positionals
        .next()
        .map(|name| {
            COMMANDS
                .iter()
                .find(|spec| name == spec.name)
                .ok_or_else(|| general(format!("unknown command {}", name.display())))
        })
        .transpose()?;
    let help = tokens.iter().any(|token| matches!(token, Token::Help));
    match (spec, help) {
        (spec, true) => Ok(Parsed::Help(spec.map_or_else(general_usage, usage))),
        (None, false) => Err(general("no command given".to_owned())),
        (Some(spec), false) => {
            let flags = tokens.iter().filter_map(Token::flag).collect();
            Matches::new(spec, flags, positionals.collect())
                .and_then(|matches| {
                    Ok(Cli {
                        now_ms: matches.optional(NOW_MS.name)?,
                        command: (spec.parse)(&matches)?,
                    })
                })
                .map(Parsed::Run)
                .map_err(|message| UsageError {
                    message,
                    usage: usage(spec),
                })
        }
    }
}

enum Token {
    Help,
    Flag { name: String, value: OsString },
    Positional(OsString),
}

impl Token {
    fn flag(&self) -> Option<(&str, &OsStr)> {
        match self {
            Token::Flag { name, value } => Some((name, value)),
            _ => None,
        }
    }

    fn positional(&self) -> Option<&OsStr> {
        match self {
            Token::Positional(arg) => Some(arg),
            _ => None,
        }
    }
}

fn tokens(args: impl IntoIterator<Item = OsString>) -> Result<Vec<Token>, String> {
    let mut args = args.into_iter();
    iter::from_fn(|| args.next().map(|arg| token(arg, &mut args))).collect()
}

/// Reads one token, taking the next argument as the value of a `--name value` flag.
fn token(arg: OsString, rest: &mut impl Iterator<Item = OsString>) -> Result<Token, String> {
    let flag = match arg.to_str() {
        Some("--help" | "-h") => return Ok(Token::Help),
        Some(text) => text.strip_prefix("--"),
        None => None,
    };
    match flag.map(|flag| flag.split_once('=').ok_or(flag)) {
        None => Ok(Token::Positional(arg)),
        Some(Ok((name, value))) => Ok(Token::Flag {
            name: name.to_owned(),
            value: value.into(),
        }),
        Some(Err(name)) => rest
            .next()
            .map(|value| Token::Flag {
                name: name.to_owned(),
                value,
            })
            .ok_or_else(|| format!("--{name} needs a value")),
    }
}

/// What one command accepts.
struct Spec {
    name: &'static str,
    about: &'static str,
    positional: Positional,
    flags: &'static [Flag],
    parse: fn(&Matches<'_>) -> Result<Command, String>,
}

#[derive(Clone, Copy)]
enum Positional {
    None,
    One(&'static str),
    /// At least one.
    Many(&'static str),
}

struct Flag {
    name: &'static str,
    value: &'static str,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Required,
    Optional,
    Default(u64),
    /// Any number of times, each adding one value.
    Repeated,
}

const fn flag(name: &'static str, value: &'static str, kind: Kind) -> Flag {
    Flag { name, value, kind }
}

/// Accepted by every command, before or after its name.
const NOW_MS: Flag = flag("now-ms", "<ms>", Kind::Optional);

const COMMANDS: [Spec; 8] = [
    Spec {
        name: "keygen",
        about: "Writes a root Ed25519 key pair and an issuer key pair.",
        positional: Positional::None,
        flags: &[flag("out", "<dir>", Kind::Required)],
        parse: |m| {
            Ok(Command::Keygen {
                out: m.required("out")?,
            })
        },
    },
    Spec {
        name: "build",
        about: "Compiles policies, runs the trusted setup and signs the bundle.",
        positional: Positional::Many("policy.rego"),
        flags: &[
            flag("schema", "<name,...>", Kind::Required),
            flag("root-key", "<file>", Kind::Required),
            flag("issuer", "<file>", Kind::Required),
            flag("out", "<file>", Kind::Required),
            flag("prover-out", "<file>", Kind::Required),
            flag("version", "<n>", Kind::Default(policy::DEFAULT_VERSION)),
            flag(
                "window-ms",
                "<ms>",
                Kind::Default(policy::DEFAULT_WINDOW_MS),
            ),
            flag("stale-ms", "<ms>", Kind::Default(policy::DEFAULT_STALE_MS)),
            flag(
                "session-epochs",
                "<n>",
                Kind::Default(policy::DEFAULT_SESSION_EPOCHS),
            ),
        ],
        parse: |m| {
            Ok(Command::Build(policy::Build {
                policies: m.positionals(),
                schema: m.required("schema")?,
                root_key: m.required("root-key")?,
                issuer: m.required("issuer")?,
                out: m.required("out")?,
                prover_out: m.required("prover-out")?,
                version: m.defaulted("version")?,
                window_ms: m.defaulted("window-ms")?,
                stale_ms: m.defaulted("stale-ms")?,
                session_epochs: m.defaulted("session-epochs")?,
            }))
        },
    },
    Spec {
        name: "inspect",
        about: "Prints each decision path of a bundle and its input layout.",
        positional: Positional::One("bundle"),
        flags: &[],
        parse: |m| {
            Ok(Command::Inspect {
                bundle: m.positional(),
            })
        },
    },
    Spec {
        name: "eval",
        about: "Evaluates a policy in the clear and prints true or false.",
        positional: Positional::None,
        flags: &[
            flag("policy-file", "<file>", Kind::Required),
            flag("schema", "<name,...>", Kind::Required),
            flag("policy", "<path>", Kind::Required),
            flag("input", "<file.json>", Kind::Required),
            flag("attr", "<name=value>", Kind::Repeated),
        ],
        parse: |m| {
            Ok(Command::Eval(policy::Eval {
                policy_file: m.required("policy-file")?,
                schema: m.required("schema")?,
                policy: m.required("policy")?,
                input: m.required("input")?,
                attrs: m.repeated("attr")?,
            }))
        },
    },
    Spec {
        name: "issue",
        about: "Signs a credential.",
        positional: Positional::None,
        flags: &[
            flag("issuer-key", "<file>", Kind::Required),
            flag("schema", "<name,...>", Kind::Required),
            flag("id", "<n>", Kind::Required),
            flag("attr", "<name=value>", Kind::Repeated),
            flag("exp", "<epoch>", Kind::Required),
            flag("out", "<file>", Kind::Required),
        ],
        parse: |m| {
            Ok(Command::Issue(issuer::Issue {
                issuer_key: m.required("issuer-key")?,
                schema: m.required("schema")?,
                id: m.required("id")?,
                attrs: m.repeated("attr")?,
                exp: m.required("exp")?,
                out: m.required("out")?,
            }))
        },
    },
    Spec {
        name: "feed",
        about: "Signs a feed update listing revocation roots and revoked tags.",
        positional: Positional::None,
        flags: &[
            flag("root-key", "<file>", Kind::Required),
            flag("sequence", "<n>", Kind::Required),
            flag("epoch", "<n>", Kind::Required),
            flag("revoke-id", "<id>", Kind::Repeated),
            flag("session-epochs", "<n>", Kind::Required),
            flag("min-bundle-version", "<n>", Kind::Required),
            flag("out", "<file>", Kind::Required),
        ],
        parse: |m| {
            Ok(Command::Feed(issuer::Feed {
                root_key: m.required("root-key")?,
                sequence: m.required("sequence")?,
                epoch: m.required("epoch")?,
                revoke_ids: m.repeated("revoke-id")?,
                session_epochs: m.required("session-epochs")?,
                min_bundle_version: m.required("min-bundle-version")?,
                out: m.required("out")?,
            }))
        },
    },
    Spec {
        name: "prove",
        about: "Logs in with a credential and proves one request.",
        positional: Positional::None,
        flags: &[
            flag("prover", "<file>", Kind::Required),
            flag("cred", "<file>", Kind::Required),
            flag("revoke-id", "<id>", Kind::Repeated),
            flag("epoch", "<n>", Kind::Required),
            flag("audience", "<name>", Kind::Required),
            flag("policy", "<path>", Kind::Required),
            flag("input", "<file.json>", Kind::Required),
            flag("out", "<file>", Kind::Required),
        ],
        parse: |m| {
            Ok(Command::Prove(request::Prove {
                prover: m.required("prover")?,
                cred: m.required("cred")?,
                revoke_ids: m.repeated("revoke-id")?,
                epoch: m.required("epoch")?,
                audience: m.required("audience")?,
                policy: m.required("policy")?,
                input: m.required("input")?,
                out: m.required("out")?,
            }))
        },
    },
    Spec {
        name: "verify",
        about: "Decides a request as a service would. Exits non-zero on deny.",
        positional: Positional::One("token"),
        flags: &[
            flag("bundle", "<file>", Kind::Required),
            flag("root-pub", "<file>", Kind::Required),
            flag("feed", "<file>", Kind::Required),
            flag("audience", "<name>", Kind::Required),
            flag("policy", "<path>", Kind::Required),
            flag("input", "<file.json>", Kind::Required),
        ],
        parse: |m| {
            Ok(Command::Verify(request::Verify {
                bundle: m.required("bundle")?,
                root_pub: m.required("root-pub")?,
                feed: m.required("feed")?,
                audience: m.required("audience")?,
                policy: m.required("policy")?,
                input: m.required("input")?,
                token: m.positional(),
            }))
        },
    },
];

/// One command's flags and positional arguments, checked against its [`Spec`].
struct Matches<'a> {
    spec: &'static Spec,
    flags: Vec<(&'a str, &'a OsStr)>,
    positionals: Vec<&'a OsStr>,
}

impl<'a> Matches<'a> {
    fn new(
        spec: &'static Spec,
        flags: Vec<(&'a str, &'a OsStr)>,
        positionals: Vec<&'a OsStr>,
    ) -> Result<Self, String> {
        if let Some((name, _)) = flags
            .iter()
            .find(|(name, _)| spec.flag(name).is_none() && *name != NOW_MS.name)
        {
            return Err(format!("unknown flag --{name}"));
        }
        match (spec.positional, positionals.as_slice()) {
            (Positional::None, []) | (Positional::One(_), [_]) | (Positional::Many(_), [_, ..]) => {
                Ok(Self {
                    spec,
                    flags,
                    positionals,
                })
            }
            (Positional::None, [extra, ..]) | (Positional::One(_), [_, extra, ..]) => {
                Err(format!("unexpected argument {}", extra.display()))
            }
            (Positional::One(name) | Positional::Many(name), []) => {
                Err(format!("missing <{name}>"))
            }
        }
    }

    fn values(&self, name: &str) -> impl Iterator<Item = &'a OsStr> {
        self.flags
            .iter()
            .filter(move |(flag, _)| *flag == name)
            .map(|&(_, value)| value)
    }

    /// The value of a flag that may be given at most once.
    fn optional<T: FromArg>(&self, name: &str) -> Result<Option<T>, String> {
        let mut values = self.values(name);
        match (values.next(), values.next()) {
            (value, None) => value.map(|value| from_arg(name, value)).transpose(),
            (_, Some(_)) => Err(format!("--{name} given more than once")),
        }
    }

    fn required<T: FromArg>(&self, name: &str) -> Result<T, String> {
        debug_assert!(self.spec.flag(name).map(|flag| flag.kind) == Some(Kind::Required));
        self.optional(name)?
            .ok_or_else(|| format!("missing required flag --{name}"))
    }

    fn defaulted(&self, name: &str) -> Result<u64, String> {
        let Some(Kind::Default(default)) = self.spec.flag(name).map(|flag| flag.kind) else {
            unreachable!("--{name} has no default in {}", self.spec.name);
        };
        Ok(self.optional(name)?.unwrap_or(default))
    }

    fn repeated<T: FromArg>(&self, name: &str) -> Result<Vec<T>, String> {
        debug_assert!(self.spec.flag(name).map(|flag| flag.kind) == Some(Kind::Repeated));
        self.values(name)
            .map(|value| from_arg(name, value))
            .collect()
    }

    /// The one positional argument; [`Matches::new`] checked there is exactly one.
    fn positional(&self) -> PathBuf {
        self.positionals[0].into()
    }

    fn positionals(&self) -> Vec<PathBuf> {
        self.positionals
            .iter()
            .copied()
            .map(PathBuf::from)
            .collect()
    }
}

impl Spec {
    fn flag(&self, name: &str) -> Option<&'static Flag> {
        self.flags.iter().find(|flag| flag.name == name)
    }
}

/// A flag's value type.
trait FromArg: Sized {
    fn from_arg(arg: &OsStr) -> Result<Self, String>;
}

fn from_arg<T: FromArg>(name: &str, arg: &OsStr) -> Result<T, String> {
    T::from_arg(arg)
        .map_err(|reason| format!("invalid value '{}' for --{name}: {reason}", arg.display()))
}

fn text(arg: &OsStr) -> Result<&str, String> {
    arg.to_str().ok_or_else(|| "not valid UTF-8".to_owned())
}

fn number<T: FromStr<Err = std::num::ParseIntError>>(arg: &OsStr) -> Result<T, String> {
    text(arg)?.parse().map_err(|error| format!("{error}"))
}

impl FromArg for PathBuf {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        Ok(arg.into())
    }
}

impl FromArg for String {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        text(arg).map(str::to_owned)
    }
}

impl FromArg for u32 {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        number(arg)
    }
}

impl FromArg for u64 {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        number(arg)
    }
}

/// A comma-separated list, for `--schema`.
impl FromArg for Vec<String> {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        text(arg).map(|list| list.split(',').map(str::to_owned).collect())
    }
}

/// `name=value`, for `--attr`.
impl FromArg for (String, u64) {
    fn from_arg(arg: &OsStr) -> Result<Self, String> {
        let (name, value) = text(arg)?.split_once('=').ok_or("expected name=value")?;
        let value = value.parse().map_err(|_| format!("{value} is not a u64"))?;
        Ok((name.to_owned(), value))
    }
}

fn general_usage() -> String {
    let commands: String = COMMANDS
        .iter()
        .map(|spec| format!("\n  {:<9}{}", spec.name, spec.about))
        .collect();
    format!(
        "Authorization where a zero-knowledge proof is the decision.\n\n\
         usage: zkopa <command> [flags]\n\ncommands:{commands}\n\n\
         Every command takes --{} {} instead of reading the clock.\n\
         Run zkopa <command> --help for its flags.\n",
        NOW_MS.name, NOW_MS.value
    )
}

fn usage(spec: &Spec) -> String {
    let positional = match spec.positional {
        Positional::None => String::new(),
        Positional::One(name) => format!(" <{name}>"),
        Positional::Many(name) => format!(" <{name}>..."),
    };
    let flags: String = spec
        .flags
        .iter()
        .chain([&NOW_MS])
        .map(|flag| {
            let kind = match flag.kind {
                Kind::Required => "required".to_owned(),
                Kind::Optional => "optional".to_owned(),
                Kind::Default(default) => format!("default {default}"),
                Kind::Repeated => "repeatable".to_owned(),
            };
            let left = format!("--{} {}", flag.name, flag.value);
            format!("\n  {left:<32}{kind}")
        })
        .collect();
    format!(
        "{}\n\nusage: zkopa {}{positional} [flags]\n\nflags:{flags}\n",
        spec.about, spec.name
    )
}
