//! Type inference and lowering of rule bodies to IR nodes.
//!
//! Integer expressions are kept as exact linear forms `(pos - neg + k) / den` until a
//! comparison, which moves everything to non-negative sides: `(P - N + k) / d <= 0` with
//! `d > 0` is `P + max(k, 0) <= N + max(-k, 0)`. So division by a constant and subtraction
//! compile to cross-multiplication and to a term on the other side, and the circuit never
//! holds a fraction or a negative number.

use std::collections::HashMap;

use zkopa_ir::{Builder, FieldType, Node, NodeId, Policy, Schema};

use crate::lex::{Magnitude, Number, Span};
use crate::parse::{ArithOp, CmpOp, Expr, ExprKind, Literal, Query};
use crate::{Decision, Error, Kind, at, construct, path, unsupported};

/// `(pos - neg + k) / den`, where `pos` and `neg` are sums of non-negative terms (`None` is 0)
/// and `den > 0`.
#[derive(Clone, Copy)]
struct Num {
    pos: Option<NodeId>,
    neg: Option<NodeId>,
    k: i128,
    den: u64,
}

impl Num {
    fn term(node: NodeId) -> Self {
        Num {
            pos: Some(node),
            neg: None,
            k: 0,
            den: 1,
        }
    }

    fn constant(k: i128) -> Self {
        Num {
            pos: None,
            neg: None,
            k,
            den: 1,
        }
    }

    fn is_constant(self) -> bool {
        self.pos.is_none() && self.neg.is_none()
    }

    fn negate(self) -> Self {
        Num {
            pos: self.neg,
            neg: self.pos,
            k: -self.k,
            den: self.den,
        }
    }
}

enum Val {
    Num(Num),
    Bool(NodeId),
    Bytes(NodeId),
    /// A public input field, typed by its use.
    Field(String),
}

impl Val {
    fn describe(&self) -> &'static str {
        match self {
            Val::Num(_) => "a number",
            Val::Bool(_) => "a boolean",
            Val::Bytes(_) => "a string",
            Val::Field(_) => "an untyped field",
        }
    }
}

pub(crate) struct Lower<'a> {
    b: Builder,
    schema: &'a Schema,
    /// Field types inferred so far across the whole module.
    types: &'a mut HashMap<String, FieldType>,
    /// The first comparison of two untyped fields in this pass.
    unresolved: &'a mut Option<Error>,
}

impl<'a> Lower<'a> {
    pub fn new(
        schema: &'a Schema,
        types: &'a mut HashMap<String, FieldType>,
        unresolved: &'a mut Option<Error>,
    ) -> Self {
        Lower {
            b: Builder::new(schema),
            schema,
            types,
            unresolved,
        }
    }

    pub fn finish(self, path: String, root: NodeId, span: Span) -> Result<Policy, Error> {
        self.b.finish(path, root).map_err(|e| at(span, Kind::Ir(e)))
    }

    pub fn decision(&mut self, decision: &Decision<'_>) -> Result<NodeId, Error> {
        let always = decision
            .always
            .then(|| self.push(Node::Bool(true), decision.span))
            .transpose()?;
        let root = decision.bodies.iter().try_fold(always, |root, query| {
            let body = self.query(query)?;
            self.join(Node::Or, root, Some(body), query.span)
        })?;
        root.map_or_else(|| self.push(Node::Bool(false), decision.span), Ok)
    }

    fn query(&mut self, query: &Query<'_>) -> Result<NodeId, Error> {
        let all = query.stmts.iter().try_fold(None, |all, stmt| {
            if let Some(with) = stmt.with {
                return Err(unsupported(with, "`with`"));
            }
            let node = match &stmt.literal {
                Literal::Expr(expr) => self.condition(expr)?,
                Literal::Not { span, expr } => {
                    let node = self.condition(expr)?;
                    self.push(Node::Not(node), *span)?
                }
                Literal::Unsupported { span, construct } => {
                    return Err(unsupported(*span, *construct));
                }
            };
            self.join(Node::And, all, Some(node), stmt.span)
        })?;
        all.map_or_else(|| self.push(Node::Bool(true), query.span), Ok)
    }

    fn condition(&mut self, expr: &Expr<'_>) -> Result<NodeId, Error> {
        match &expr.kind {
            ExprKind::Compare(op, lhs, rhs) => self.compare(expr.span, *op, lhs, rhs),
            ExprKind::In(value, collection) => self.membership(expr.span, value, collection),
            _ => match self.value(expr)? {
                Val::Bool(node) => Ok(node),
                Val::Field(name) => self.field(name, FieldType::Bool, expr.span),
                other => Err(at(
                    expr.span,
                    Kind::Type {
                        expected: "a boolean",
                        found: other.describe(),
                    },
                )),
            },
        }
    }

    /// `value in {…}`, for a set literal of non-negative integers.
    fn membership(
        &mut self,
        span: Span,
        value: &Expr<'_>,
        collection: &Expr<'_>,
    ) -> Result<NodeId, Error> {
        let ExprKind::Set(items) = &collection.kind else {
            return Err(unsupported(
                collection.span,
                "`in` anything but a set literal",
            ));
        };
        let set = items
            .iter()
            .map(|item| {
                let ExprKind::Number(number) = item.kind else {
                    return Err(unsupported(
                        item.span,
                        "a set element that is not an integer",
                    ));
                };
                u64::try_from(integer(number, item.span)?)
                    .map_err(|_| at(item.span, Kind::Subtraction))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let num = self.num(value)?;
        let node = self.integer(num, value.span)?;
        let set = self.b.set(set).map_err(|e| at(span, Kind::Ir(e)))?;
        self.push(Node::In(node, set), span)
    }

    fn compare(
        &mut self,
        span: Span,
        op: CmpOp,
        lhs: &Expr<'_>,
        rhs: &Expr<'_>,
    ) -> Result<NodeId, Error> {
        if matches!(op, CmpOp::Eq | CmpOp::Ne) {
            let eq = self.equal(span, lhs, rhs)?;
            return match op {
                CmpOp::Ne => self.push(Node::Not(eq), span),
                _ => Ok(eq),
            };
        }
        let a = self.num(lhs)?;
        let b = self.num(rhs)?;
        let (l, r) = self.sides(a, b, span)?;
        let node = match op {
            CmpOp::Lt => Node::Lt(l, r),
            CmpOp::Le => Node::Le(l, r),
            CmpOp::Gt => Node::Lt(r, l),
            CmpOp::Ge => Node::Le(r, l),
            CmpOp::Eq | CmpOp::Ne => Node::Eq(l, r),
        };
        self.push(node, span)
    }

    fn equal(&mut self, span: Span, lhs: &Expr<'_>, rhs: &Expr<'_>) -> Result<NodeId, Error> {
        let a = self.value(lhs)?;
        let b = self.value(rhs)?;
        let Some(ty) = self.type_of(&a).or(self.type_of(&b)) else {
            // Two untyped fields: a placeholder until a later pass knows a type. `compile`
            // fails if no pass does.
            if let Val::Field(name) = a {
                self.unresolved
                    .get_or_insert(at(span, Kind::UnknownType(name)));
            }
            return self.push(Node::Bool(true), span);
        };
        let a = self.resolve(a, ty, lhs.span)?;
        let b = self.resolve(b, ty, rhs.span)?;
        match (a, b) {
            (Val::Num(a), Val::Num(b)) => {
                let (l, r) = self.sides(a, b, span)?;
                self.push(Node::Eq(l, r), span)
            }
            (Val::Bool(a), Val::Bool(b)) | (Val::Bytes(a), Val::Bytes(b)) => {
                self.push(Node::Eq(a, b), span)
            }
            (a, b) => Err(at(
                span,
                Kind::Type {
                    expected: a.describe(),
                    found: b.describe(),
                },
            )),
        }
    }

    fn type_of(&self, value: &Val) -> Option<FieldType> {
        match value {
            Val::Num(_) => Some(FieldType::U64),
            Val::Bool(_) => Some(FieldType::Bool),
            Val::Bytes(_) => Some(FieldType::Bytes),
            Val::Field(name) => self.types.get(name).copied(),
        }
    }

    /// Gives a field the type `ty`.
    fn resolve(&mut self, value: Val, ty: FieldType, span: Span) -> Result<Val, Error> {
        match value {
            Val::Field(name) => self.typed(name, ty, span),
            value => Ok(value),
        }
    }

    fn typed(&mut self, name: String, ty: FieldType, span: Span) -> Result<Val, Error> {
        let node = self.field(name, ty, span)?;
        Ok(match ty {
            FieldType::U64 => Val::Num(Num::term(node)),
            FieldType::Bool => Val::Bool(node),
            FieldType::Bytes => Val::Bytes(node),
        })
    }

    fn field(&mut self, name: String, ty: FieldType, span: Span) -> Result<NodeId, Error> {
        if let Some(&first) = self.types.get(&name)
            && first != ty
        {
            return Err(at(
                span,
                Kind::FieldType {
                    name,
                    first,
                    second: ty,
                },
            ));
        }
        let node = self.b.input(&name, ty).map_err(|e| at(span, Kind::Ir(e)))?;
        self.types.insert(name, ty);
        Ok(node)
    }

    fn value(&mut self, expr: &Expr<'_>) -> Result<Val, Error> {
        let span = expr.span;
        Ok(match &expr.kind {
            ExprKind::Number(number) => Val::Num(Num::constant(integer(*number, span)?)),
            ExprKind::String(value) => {
                let index = self
                    .b
                    .bytes(value.as_bytes())
                    .map_err(|e| at(span, Kind::Ir(e)))?;
                Val::Bytes(self.push(Node::Bytes(index), span)?)
            }
            ExprKind::Bool(value) => Val::Bool(self.push(Node::Bool(*value), span)?),
            ExprKind::Var(_) | ExprKind::Dot(..) | ExprKind::Index(..) => self.reference(expr)?,
            ExprKind::Arith(op, lhs, rhs) => {
                let a = self.num(lhs)?;
                let b = self.num(rhs)?;
                Val::Num(match op {
                    ArithOp::Add => self.add(a, b, span)?,
                    ArithOp::Sub => self.add(a, b.negate(), span)?,
                    ArithOp::Mul => self.mul(a, b, span)?,
                    ArithOp::Div => {
                        let d = match b {
                            Num {
                                pos: None,
                                neg: None,
                                k,
                                den: 1,
                            } if k > 0 => k,
                            _ => return Err(at(rhs.span, Kind::Divisor)),
                        };
                        let d = u64::try_from(d).map_err(|_| at(rhs.span, Kind::Constant))?;
                        let den = a.den.checked_mul(d).ok_or(at(span, Kind::Constant))?;
                        Num { den, ..a }
                    }
                    ArithOp::Mod => return Err(unsupported(span, "`%`")),
                })
            }
            ExprKind::Neg(inner) => Val::Num(self.num(inner)?.negate()),
            ExprKind::Compare(..) | ExprKind::In(..) => Val::Bool(self.condition(expr)?),
            ExprKind::Set(_) | ExprKind::Unsupported(_) => {
                return Err(unsupported(span, construct(expr)));
            }
        })
    }

    fn reference(&mut self, expr: &Expr<'_>) -> Result<Val, Error> {
        let span = expr.span;
        let path = path(expr)?;
        match path[..] {
            ["input", "subject", ref name @ ..] if !name.is_empty() => {
                let name = name.join(".");
                let Some(index) = self.schema.index(&name) else {
                    return Err(at(span, Kind::UnknownAttribute(name)));
                };
                Ok(Val::Num(Num::term(
                    self.push(Node::Attribute(index), span)?,
                )))
            }
            ["input", "request" | "resource", ref rest @ ..] if !rest.is_empty() => {
                Ok(Val::Field(path[1..].join(".")))
            }
            ["input", ..] => Err(unsupported(span, format!("`{}`", path.join(".")))),
            ["data", ..] => Err(unsupported(span, "a `data` document")),
            _ => Err(unsupported(
                span,
                format!("the variable or rule `{}`", path.join(".")),
            )),
        }
    }

    fn num(&mut self, expr: &Expr<'_>) -> Result<Num, Error> {
        match self.value(expr)? {
            Val::Num(num) => Ok(num),
            Val::Field(name) => Ok(Num::term(self.field(name, FieldType::U64, expr.span)?)),
            other => Err(at(
                expr.span,
                Kind::Type {
                    expected: "a number",
                    found: other.describe(),
                },
            )),
        }
    }

    /// The node of a value that must be a non-negative integer, as for `in`.
    fn integer(&mut self, num: Num, span: Span) -> Result<NodeId, Error> {
        if num.den != 1 {
            return Err(at(span, Kind::Division));
        }
        if num.neg.is_some() || num.k < 0 {
            return Err(at(span, Kind::Subtraction));
        }
        let k = self.constant(num.k.unsigned_abs(), span)?;
        self.side(num.pos, k, span)
    }

    /// The two non-negative sides that compare like `a` and `b`.
    fn sides(&mut self, a: Num, b: Num, span: Span) -> Result<(NodeId, NodeId), Error> {
        let d = self.add(a, b.negate(), span)?;
        let (kl, kr) = if d.k >= 0 {
            (d.k.unsigned_abs(), 0)
        } else {
            (0, d.k.unsigned_abs())
        };
        let kl = self.constant(kl, span)?;
        let kr = self.constant(kr, span)?;
        Ok((self.side(d.pos, kl, span)?, self.side(d.neg, kr, span)?))
    }

    fn side(&mut self, a: Option<NodeId>, b: Option<NodeId>, span: Span) -> Result<NodeId, Error> {
        self.join(Node::Add, a, b, span)?
            .map_or_else(|| self.push(Node::Int(0), span), Ok)
    }

    fn constant(&mut self, k: u128, span: Span) -> Result<Option<NodeId>, Error> {
        if k == 0 {
            return Ok(None);
        }
        let k = u64::try_from(k).map_err(|_| at(span, Kind::Constant))?;
        self.push(Node::Int(k), span).map(Some)
    }

    fn add(&mut self, a: Num, b: Num, span: Span) -> Result<Num, Error> {
        let den = lcm(a.den, b.den).ok_or(at(span, Kind::Constant))?;
        let a = self.scale(a, den / a.den, span)?;
        let b = self.scale(b, den / b.den, span)?;
        Ok(Num {
            pos: self.join(Node::Add, a.pos, b.pos, span)?,
            neg: self.join(Node::Add, a.neg, b.neg, span)?,
            k: a.k.checked_add(b.k).ok_or(at(span, Kind::Constant))?,
            den,
        })
    }

    fn mul(&mut self, a: Num, b: Num, span: Span) -> Result<Num, Error> {
        let (c, n) = match (a.is_constant(), b.is_constant()) {
            (_, true) => (b, a),
            (true, false) => (a, b),
            (false, false) => return Err(at(span, Kind::Product)),
        };
        let magnitude = u64::try_from(c.k.unsigned_abs()).map_err(|_| at(span, Kind::Constant))?;
        let n = self.scale(n, magnitude, span)?;
        let den = n.den.checked_mul(c.den).ok_or(at(span, Kind::Constant))?;
        let n = Num { den, ..n };
        Ok(if c.k < 0 { n.negate() } else { n })
    }

    /// Multiplies numerator terms by `c`, keeping the denominator.
    fn scale(&mut self, n: Num, c: u64, span: Span) -> Result<Num, Error> {
        Ok(Num {
            pos: self.scale_term(n.pos, c, span)?,
            neg: self.scale_term(n.neg, c, span)?,
            k: n.k.checked_mul(c.into()).ok_or(at(span, Kind::Constant))?,
            den: n.den,
        })
    }

    fn scale_term(
        &mut self,
        t: Option<NodeId>,
        c: u64,
        span: Span,
    ) -> Result<Option<NodeId>, Error> {
        match (t, c) {
            (None, _) | (_, 0) => Ok(None),
            (Some(t), 1) => Ok(Some(t)),
            (Some(t), c) => self.push(Node::MulConst(t, c), span).map(Some),
        }
    }

    /// Joins two optional nodes with `op`; a missing node is the identity of `op`.
    fn join(
        &mut self,
        op: fn(NodeId, NodeId) -> Node,
        a: Option<NodeId>,
        b: Option<NodeId>,
        span: Span,
    ) -> Result<Option<NodeId>, Error> {
        match (a, b) {
            (Some(a), Some(b)) => self.push(op(a, b), span).map(Some),
            (a, b) => Ok(a.or(b)),
        }
    }

    fn push(&mut self, node: Node, span: Span) -> Result<NodeId, Error> {
        self.b.push(node).map_err(|e| match e {
            zkopa_ir::Error::TooWide { bits, .. } => at(span, Kind::TooWide(bits)),
            e => at(span, Kind::Ir(e)),
        })
    }
}

/// An integer literal; Rego numbers may also be fractional, which the subset rejects.
fn integer(number: Number, span: Span) -> Result<i128, Error> {
    let magnitude = match number.magnitude {
        Magnitude::Int(magnitude) => i128::from(magnitude),
        Magnitude::Fraction => return Err(unsupported(span, "a floating-point number")),
        Magnitude::TooLarge => return Err(at(span, Kind::Constant)),
    };
    Ok(if number.negative {
        -magnitude
    } else {
        magnitude
    })
}

fn lcm(a: u64, b: u64) -> Option<u64> {
    // Euclid's gcd: two registers stepped in place read more plainly than a fold or recursion.
    let (mut x, mut y) = (a, b);
    while y != 0 {
        (x, y) = (y, x % y);
    }
    (a / x).checked_mul(b)
}
