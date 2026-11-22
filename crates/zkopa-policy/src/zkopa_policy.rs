//! Lowers a provable subset of Rego to the circuit IR.
//!
//! Modules are Rego v1 (OPA 1.0 syntax: rule bodies need `if`), read by a small parser of our
//! own. Everything outside the subset is rejected with the construct's name and location.

mod lex;
mod lower;
mod parse;

use std::collections::HashMap;
use std::fmt::Display;

use zkopa_ir::{FieldType, Policy, Schema};

use lex::Span;
use lower::Lower;
use parse::{Expr, ExprKind, Query, Rule};

/// Compiles one Rego module into one policy per rule, in order of first definition.
///
/// The decision path of rule `allow` in `package a.b` is `a/b/allow`. Definitions of one rule
/// are joined with `or`, the statements of a body with `and`. Each policy's input layout lists
/// the fields it uses in order of first use; a field's type comes from how the module uses it.
pub fn compile(source: &str, schema: &Schema) -> Result<Vec<Policy>, Error> {
    let module = parse::module(source)?;
    let package = module.package.join("/");
    if let Some(import) = module.imports.first() {
        return Err(unsupported(
            import.span,
            format!("`import {}`", import.path),
        ));
    }
    let decisions = decisions(&module.rules)?;

    // A field compared only with another field gets its type from a use elsewhere, possibly in
    // a later rule, so lowering repeats until no comparison is left untyped. Each pass either
    // types another field or ends. The field types carry over from pass to pass, so this stays
    // a loop over shared state rather than a chain of pure passes.
    let mut types = HashMap::new();
    loop {
        let known = types.len();
        let mut unresolved = None;
        let policies = decisions
            .iter()
            .map(|decision| {
                let mut lower = Lower::new(schema, &mut types, &mut unresolved);
                let root = lower.decision(decision)?;
                let path = format!("{package}/{}", decision.name);
                lower.finish(path, root, decision.span)
            })
            .collect::<Result<Vec<_>, _>>()?;
        match unresolved {
            None => return Ok(policies),
            Some(error) if types.len() == known => return Err(error),
            Some(_) => {}
        }
    }
}

/// Why a module was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A syntax error, with its line and column.
    #[error("{0}")]
    Parse(String),
    #[error("line {line}, column {col}: {kind}")]
    At { line: u32, col: u32, kind: Kind },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Kind {
    /// A construct outside the provable subset, named.
    #[error("{0} is not supported")]
    Unsupported(String),
    #[error("`input.subject.{0}` is not in the credential schema")]
    UnknownAttribute(String),
    #[error("`input.{name}` is used as {first} and as {second}")]
    FieldType {
        name: String,
        first: FieldType,
        second: FieldType,
    },
    #[error("the type of `input.{0}` cannot be inferred: it is only compared with fields")]
    UnknownType(String),
    #[error("expected {expected}, found {found}")]
    Type {
        expected: &'static str,
        found: &'static str,
    },
    #[error("division is only supported in a comparison")]
    Division,
    #[error("subtraction and negative values are only supported in a comparison")]
    Subtraction,
    #[error("a divisor must be a positive integer constant")]
    Divisor,
    #[error("one factor of a product must be a constant")]
    Product,
    #[error("a constant does not fit in {} bits", u64::BITS)]
    Constant,
    #[error("`{0}` has a second default")]
    Default(String),
    #[error("the value may need {0} bits, more than {max}", max = zkopa_ir::MAX_BITS)]
    TooWide(u32),
    #[error(transparent)]
    Ir(zkopa_ir::Error),
}

pub(crate) fn syntax(span: Span, message: impl Display) -> Error {
    Error::Parse(format!(
        "line {}, column {}: {message}",
        span.line, span.col
    ))
}

pub(crate) fn at(span: Span, kind: Kind) -> Error {
    Error::At {
        line: span.line,
        col: span.col,
        kind,
    }
}

pub(crate) fn unsupported(span: Span, construct: impl Into<String>) -> Error {
    at(span, Kind::Unsupported(construct.into()))
}

/// All definitions of one rule name.
pub(crate) struct Decision<'m> {
    pub name: &'m str,
    pub span: Span,
    /// Each body is one `or` alternative.
    pub bodies: Vec<&'m Query<'m>>,
    /// A definition without a body, such as `allow := true`.
    pub always: bool,
    pub default: bool,
}

fn decisions<'m>(rules: &'m [Rule<'m>]) -> Result<Vec<Decision<'m>>, Error> {
    // Definitions merge into the entry of their name in place; a fold would only thread the
    // same vector through.
    let mut decisions = Vec::new();
    for rule in rules {
        match rule {
            Rule::Default {
                span,
                name,
                function,
                value,
            } => {
                if *function {
                    return Err(unsupported(*span, "a function"));
                }
                if !matches!(value.kind, ExprKind::Bool(false)) {
                    return Err(unsupported(value.span, "a default other than `false`"));
                }
                let decision = entry(&mut decisions, name, *span)?;
                if decision.default {
                    return Err(at(*span, Kind::Default(decision.name.into())));
                }
                decision.default = true;
            }
            Rule::Value {
                span,
                name,
                value,
                bodies,
                otherwise,
            } => {
                value.as_ref().map_or(Ok(()), is_true)?;
                let decision = entry(&mut decisions, name, *span)?;
                decision.always |= bodies.is_empty();
                if let Some(otherwise) = otherwise {
                    return Err(unsupported(*otherwise, "`else`"));
                }
                decision.bodies.extend(bodies);
            }
            Rule::Set { span } => {
                return Err(unsupported(*span, "a partial set rule (`contains`)"));
            }
            Rule::Function { span } => return Err(unsupported(*span, "a function")),
        }
    }
    Ok(decisions)
}

fn entry<'d, 'm>(
    decisions: &'d mut Vec<Decision<'m>>,
    name: &'m Expr<'m>,
    span: Span,
) -> Result<&'d mut Decision<'m>, Error> {
    let name = match path(name)?[..] {
        [only] => only,
        _ => return Err(unsupported(name.span, "a rule with a dotted name")),
    };
    let index = decisions
        .iter()
        .position(|d| d.name == name)
        .unwrap_or_else(|| {
            decisions.push(Decision {
                name,
                span,
                bodies: Vec::new(),
                always: false,
                default: false,
            });
            decisions.len() - 1
        });
    Ok(&mut decisions[index])
}

fn is_true(value: &Expr<'_>) -> Result<(), Error> {
    match value.kind {
        ExprKind::Bool(true) => Ok(()),
        _ => Err(unsupported(value.span, "a rule value other than `true`")),
    }
}

/// The components of a reference such as `input.request["amount"]`.
///
/// Recursion follows the AST, which nests a reference's prefix inside it.
pub(crate) fn path<'e>(expr: &'e Expr<'_>) -> Result<Vec<&'e str>, Error> {
    let (prefix, last) = match &expr.kind {
        ExprKind::Var(name) => return Ok(vec![*name]),
        ExprKind::Dot(prefix, field) => (prefix, *field),
        ExprKind::Index(prefix, index) => match &index.kind {
            ExprKind::String(value) => (prefix, value.as_ref()),
            _ => {
                return Err(unsupported(
                    index.span,
                    "iteration or indexing by a non-string",
                ));
            }
        },
        _ => return Err(unsupported(expr.span, construct(expr))),
    };
    let mut path = path(prefix)?;
    path.push(last);
    Ok(path)
}

/// Names an expression the subset does not support.
pub(crate) fn construct(expr: &Expr<'_>) -> String {
    match &expr.kind {
        ExprKind::Set(_) => "a set outside `in`".into(),
        ExprKind::Unsupported(construct) => construct.to_string(),
        _ => format!("`{}`", expr.text),
    }
}
