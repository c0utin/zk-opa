//! A recursive-descent parser for Rego v1 modules, into a small AST.
//!
//! Precedence follows OPA, loosest first: `in`, comparisons, `|`, `&`, `+ -`, `* / %`.
//! Constructs outside the provable subset are recognized by a keyword or token and skipped as
//! balanced token groups (`some`, `every`, `with`, calls, arrays, objects, comprehensions,
//! function arguments), leaving a node that lowering rejects with the construct's name and
//! location. Every syntax error is an [`Error::Parse`] with a line and column.

use std::borrow::Cow;
use std::fmt;

use crate::lex::{self, Number, Span, Sym, Tok, Token};
use crate::{Error, syntax};

/// Words that cannot name a variable or a rule. `true`, `false` and `null` are literals.
const KEYWORDS: [&str; 15] = [
    "as", "contains", "default", "else", "every", "false", "if", "import", "in", "not", "null",
    "package", "some", "true", "with",
];

/// The keywords `import future.keywords` enables. `import rego.v1` enables them all.
const FUTURE_KEYWORDS: [&str; 4] = ["contains", "every", "if", "in"];

/// The roots an import path may start with.
const IMPORT_ROOTS: [&str; 4] = ["data", "future", "input", "rego"];

/// How deeply expressions may nest. Parsing and lowering recurse once per level, so deeper
/// input is rejected before it can exhaust the stack.
const MAX_DEPTH: u32 = 256;

/// The documents a rule may not redefine.
const ROOT_DOCUMENTS: [&str; 2] = ["input", "data"];

pub(crate) struct Module<'s> {
    pub package: Vec<Cow<'s, str>>,
    /// Imports other than `rego.v1` and `future.keywords`, which only enable syntax.
    pub imports: Vec<Import>,
    pub rules: Vec<Rule<'s>>,
}

pub(crate) struct Import {
    pub span: Span,
    /// The dotted path, without an alias.
    pub path: String,
}

pub(crate) enum Rule<'s> {
    /// `default name := value`.
    Default {
        span: Span,
        name: Expr<'s>,
        /// Whether the name takes parameters, as a function's default does.
        function: bool,
        value: Expr<'s>,
    },
    /// `name [:= value] [if body]`, with more `{ … }` bodies joined by `or`.
    Value {
        span: Span,
        name: Expr<'s>,
        value: Option<Expr<'s>>,
        bodies: Vec<Query<'s>>,
        /// Where an `else` chain starts.
        otherwise: Option<Span>,
    },
    /// `name contains key [if body]`.
    Set { span: Span },
    /// `name(args) …`.
    Function { span: Span },
}

/// A rule body: statements joined by `and`.
pub(crate) struct Query<'s> {
    pub span: Span,
    pub stmts: Vec<Stmt<'s>>,
}

pub(crate) struct Stmt<'s> {
    pub span: Span,
    /// Where a `with` modifier starts.
    pub with: Option<Span>,
    pub literal: Literal<'s>,
}

pub(crate) enum Literal<'s> {
    Expr(Expr<'s>),
    Not {
        span: Span,
        expr: Expr<'s>,
    },
    /// `some` or `every`, by name.
    Unsupported {
        span: Span,
        construct: &'static str,
    },
}

/// An expression, where its operator (or only token) is, and its source text.
pub(crate) struct Expr<'s> {
    pub span: Span,
    pub text: &'s str,
    pub kind: ExprKind<'s>,
    /// Levels in this expression's tree, at most [`MAX_DEPTH`].
    depth: u32,
}

pub(crate) enum ExprKind<'s> {
    Number(Number),
    String(Cow<'s, str>),
    Bool(bool),
    Var(&'s str),
    Dot(Box<Expr<'s>>, &'s str),
    Index(Box<Expr<'s>>, Box<Expr<'s>>),
    Neg(Box<Expr<'s>>),
    Arith(ArithOp, Box<Expr<'s>>, Box<Expr<'s>>),
    Compare(CmpOp, Box<Expr<'s>>, Box<Expr<'s>>),
    /// `value in collection`.
    In(Box<Expr<'s>>, Box<Expr<'s>>),
    Set(Vec<Expr<'s>>),
    Unsupported(Construct<'s>),
}

#[derive(Clone, Copy)]
pub(crate) enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy)]
pub(crate) enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// An expression outside the subset, kept only to be named in the error.
pub(crate) enum Construct<'s> {
    Null,
    Array,
    Object,
    Comprehension,
    /// A call, by the function's name.
    Call(&'s str),
    Union,
    Intersection,
    Assignment,
    KeyValueIn,
}

impl fmt::Display for Construct<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Construct::Null => f.write_str("`null`"),
            Construct::Array => f.write_str("an array"),
            Construct::Object => f.write_str("an object"),
            Construct::Comprehension => f.write_str("a comprehension"),
            Construct::Call(name) => write!(f, "a call to `{name}`"),
            Construct::Union | Construct::Intersection => f.write_str("set union or intersection"),
            Construct::Assignment => f.write_str("assignment or unification"),
            Construct::KeyValueIn => f.write_str("`key, value in`"),
        }
    }
}

impl ExprKind<'_> {
    /// The depth of the deepest operand.
    fn depth(&self) -> u32 {
        match self {
            ExprKind::Number(_)
            | ExprKind::String(_)
            | ExprKind::Bool(_)
            | ExprKind::Var(_)
            | ExprKind::Unsupported(_) => 0,
            ExprKind::Dot(a, _) | ExprKind::Neg(a) => a.depth,
            ExprKind::Index(a, b)
            | ExprKind::Arith(_, a, b)
            | ExprKind::Compare(_, a, b)
            | ExprKind::In(a, b) => a.depth.max(b.depth),
            ExprKind::Set(items) => items.iter().map(|item| item.depth).max().unwrap_or(0),
        }
    }
}

/// A binary operator of one precedence level.
#[derive(Clone, Copy)]
enum Binary {
    Compare(CmpOp),
    Arith(ArithOp),
    Union,
    Intersection,
}

impl Binary {
    fn kind<'s>(self, lhs: Expr<'s>, rhs: Expr<'s>) -> ExprKind<'s> {
        let (lhs, rhs) = (Box::new(lhs), Box::new(rhs));
        match self {
            Binary::Compare(op) => ExprKind::Compare(op, lhs, rhs),
            Binary::Arith(op) => ExprKind::Arith(op, lhs, rhs),
            Binary::Union => ExprKind::Unsupported(Construct::Union),
            Binary::Intersection => ExprKind::Unsupported(Construct::Intersection),
        }
    }

    fn comparison(sym: Sym) -> Option<Binary> {
        let op = match sym {
            Sym::Lt => CmpOp::Lt,
            Sym::Le => CmpOp::Le,
            Sym::Gt => CmpOp::Gt,
            Sym::Ge => CmpOp::Ge,
            Sym::Eq => CmpOp::Eq,
            Sym::Ne => CmpOp::Ne,
            _ => return None,
        };
        Some(Binary::Compare(op))
    }

    fn product(sym: Sym) -> Option<Binary> {
        let op = match sym {
            Sym::Star => ArithOp::Mul,
            Sym::Slash => ArithOp::Div,
            Sym::Percent => ArithOp::Mod,
            _ => return None,
        };
        Some(Binary::Arith(op))
    }
}

/// What a bracketed group holds directly, outside nested brackets.
struct Group {
    len: usize,
    pipe: bool,
    colon: bool,
}

/// How a token changes the bracket depth.
fn nesting(tok: &Tok<'_>) -> i32 {
    match tok {
        Tok::Sym(Sym::LBrace | Sym::LBrack | Sym::LParen) => 1,
        Tok::Sym(Sym::RBrace | Sym::RBrack | Sym::RParen) => -1,
        _ => 0,
    }
}

/// Parses a module.
pub(crate) fn module(source: &str) -> Result<Module<'_>, Error> {
    let tokens = lex::tokens(source)?;
    Parser {
        source,
        tokens,
        pos: 0,
        depth: 0,
    }
    .module()
}

struct Parser<'s> {
    source: &'s str,
    /// Ends with the one end-of-input token, which `pos` never passes.
    tokens: Vec<Token<'s>>,
    pos: usize,
    /// How many terms are being parsed, one inside another.
    depth: u32,
}

impl<'s> Parser<'s> {
    fn peek(&self) -> &Token<'s> {
        &self.tokens[self.pos]
    }

    /// The token before the current one: the last one consumed.
    fn prev(&self) -> &Token<'s> {
        &self.tokens[self.pos.saturating_sub(1)]
    }

    fn span(&self) -> Span {
        self.peek().span
    }

    fn bump(&mut self) {
        if self.peek().tok != Tok::Eof {
            self.pos += 1;
        }
    }

    fn sym(&self) -> Option<Sym> {
        match self.peek().tok {
            Tok::Sym(sym) => Some(sym),
            _ => None,
        }
    }

    fn word(&self) -> Option<&'s str> {
        match self.peek().tok {
            Tok::Ident(word) => Some(word),
            _ => None,
        }
    }

    fn is(&self, sym: Sym) -> bool {
        self.sym() == Some(sym)
    }

    fn is_word(&self, word: &str) -> bool {
        self.word() == Some(word)
    }

    fn eat(&mut self, sym: Sym) -> bool {
        let found = self.is(sym);
        if found {
            self.bump();
        }
        found
    }

    fn expect(&mut self, sym: Sym) -> Result<(), Error> {
        if self.eat(sym) {
            Ok(())
        } else {
            Err(self.unexpected(&format!("`{sym}`")))
        }
    }

    fn expect_word(&mut self, word: &str) -> Result<(), Error> {
        if self.is_word(word) {
            self.bump();
            Ok(())
        } else {
            Err(self.unexpected(&format!("`{word}`")))
        }
    }

    fn unexpected(&self, expected: &str) -> Error {
        let found = match &self.peek().tok {
            Tok::Ident(word) => format!("`{word}`"),
            Tok::Number(_) => "a number".into(),
            Tok::String(_) => "a string".into(),
            Tok::Sym(sym) => format!("`{sym}`"),
            Tok::Eof => "the end of the module".into(),
        };
        syntax(self.span(), format!("expected {expected}, found {found}"))
    }

    /// Whether the current token touches the previous one, as `.` and `[` in a reference must.
    fn adjacent(&self) -> bool {
        self.peek().start == self.prev().end
    }

    fn on_new_line(&self) -> bool {
        self.peek().span.line != self.prev().span.line
    }

    /// The source from the token at `start` through the last one consumed.
    fn text_from(&self, start: usize) -> &'s str {
        let source = self.source;
        &source[self.tokens[start].start..self.prev().end]
    }

    fn node(&self, start: usize, span: Span, kind: ExprKind<'s>) -> Result<Expr<'s>, Error> {
        let depth = kind.depth() + 1;
        if depth > MAX_DEPTH {
            return Err(syntax(span, "the expression is nested too deeply"));
        }
        Ok(Expr {
            span,
            text: self.text_from(start),
            kind,
            depth,
        })
    }

    /// A name that is not a keyword.
    fn name(&mut self) -> Result<&'s str, Error> {
        match self.word() {
            Some(word) if !KEYWORDS.contains(&word) => {
                self.bump();
                Ok(word)
            }
            _ => Err(self.unexpected("a name")),
        }
    }

    /// A field name right after `.`; keywords are fields too, as in `input.package`.
    fn field(&mut self) -> Result<&'s str, Error> {
        match self.word() {
            Some(word) if self.adjacent() => {
                self.bump();
                Ok(word)
            }
            _ => Err(self.unexpected("a field name right after `.`")),
        }
    }

    fn string(&mut self) -> Result<Cow<'s, str>, Error> {
        let Tok::String(value) = &self.peek().tok else {
            return Err(self.unexpected("a string"));
        };
        // A borrowed `Cow` copies only the reference.
        let value = value.clone();
        self.bump();
        Ok(value)
    }

    /// The bracketed group that starts here, without moving past it.
    fn group(&self) -> Result<Group, Error> {
        let tokens = &self.tokens[self.pos..];
        // The depth before each token: tokens directly inside the group are at depth 1.
        let depths = || {
            tokens.iter().scan(0, |depth, token| {
                let before = *depth;
                *depth += nesting(&token.tok);
                Some((before, token))
            })
        };
        let len = depths()
            .skip(1)
            .position(|(before, token)| before + nesting(&token.tok) == 0)
            .ok_or_else(|| syntax(self.span(), "unclosed bracket"))?
            + 2;
        let inside = |sym| {
            depths()
                .take(len)
                .any(|(before, token)| before == 1 && token.tok == Tok::Sym(sym))
        };
        Ok(Group {
            len,
            pipe: inside(Sym::Pipe),
            colon: inside(Sym::Colon),
        })
    }

    fn skip_group(&mut self) -> Result<Group, Error> {
        let group = self.group()?;
        self.pos += group.len;
        Ok(group)
    }

    /// Skips a clause that starts with a keyword, such as `some` or `with`, to the end of its
    /// statement. Something must follow the keyword on its line.
    fn skip_clause(&mut self) -> Result<(), Error> {
        self.bump();
        if self.peek().tok == Tok::Eof || self.on_new_line() {
            return Err(self.unexpected("the rest of the clause"));
        }
        self.skip_statement();
        Ok(())
    }

    /// Skips to the end of a statement: a new line, `;`, or the bracket that closes the body,
    /// outside any brackets of the statement's own.
    fn skip_statement(&mut self) {
        let mut depth = 0;
        loop {
            let tok = &self.peek().tok;
            let closes = nesting(tok) < 0 || *tok == Tok::Sym(Sym::Semi);
            if *tok == Tok::Eof || (depth == 0 && (closes || self.on_new_line())) {
                return;
            }
            depth += nesting(tok);
            self.bump();
        }
    }

    fn module(&mut self) -> Result<Module<'s>, Error> {
        self.expect_word("package")?;
        let package = self.path()?;
        let imports = self.imports()?;
        let mut rules = Vec::new();
        while self.peek().tok != Tok::Eof {
            rules.push(self.rule()?);
        }
        Ok(Module {
            package,
            imports,
            rules,
        })
    }

    /// A dotted name such as `a.b["c"]`, for `package` and `import`.
    fn path(&mut self) -> Result<Vec<Cow<'s, str>>, Error> {
        let mut path = vec![Cow::Borrowed(self.name()?)];
        while let Some(sym @ (Sym::Dot | Sym::LBrack)) = self.sym() {
            if !self.adjacent() {
                return Err(syntax(
                    self.span(),
                    format!("unexpected space before `{sym}`"),
                ));
            }
            self.bump();
            let part = match sym {
                Sym::Dot => Cow::Borrowed(self.field()?),
                _ => {
                    let part = self.string()?;
                    self.expect(Sym::RBrack)?;
                    part
                }
            };
            path.push(part);
        }
        Ok(path)
    }

    fn imports(&mut self) -> Result<Vec<Import>, Error> {
        let mut imports = Vec::new();
        let mut enabled: Vec<&str> = Vec::new();
        while self.is_word("import") {
            let span = self.span();
            self.bump();
            let root = self.span();
            let path = self.path()?;
            let parts: Vec<&str> = path.iter().map(AsRef::as_ref).collect();
            let keywords: &[&str] = match parts[..] {
                ["rego", "v1"] | ["future", "keywords"] => &FUTURE_KEYWORDS,
                ["future", "keywords", word] => FUTURE_KEYWORDS
                    .iter()
                    .find(|k| **k == word)
                    .map(std::slice::from_ref)
                    .ok_or_else(|| syntax(root, format!("unknown future keyword `{word}`")))?,
                ["future", ..] => return Err(syntax(root, "expected `future.keywords`")),
                [first, ..] if !IMPORT_ROOTS.contains(&first) => {
                    return Err(syntax(
                        root,
                        "an import must start with `data`, `future`, `input` or `rego`",
                    ));
                }
                _ => &[],
            };
            if self.is_word("as") {
                if !keywords.is_empty() {
                    return Err(syntax(self.span(), "a keyword import cannot be aliased"));
                }
                self.bump();
                let alias = self.span();
                if self.name()? == "_" {
                    return Err(syntax(alias, "`_` cannot be an alias"));
                }
            }
            if let Some(word) = keywords.iter().find(|word| enabled.contains(*word)) {
                return Err(syntax(span, format!("`{word}` is imported twice")));
            }
            enabled.extend(keywords);
            if keywords.is_empty() {
                imports.push(Import {
                    span,
                    path: parts.join("."),
                });
            }
        }
        Ok(imports)
    }

    fn rule(&mut self) -> Result<Rule<'s>, Error> {
        let span = self.span();
        if self.is_word("default") {
            self.bump();
            let name = self.rule_name()?;
            let function = self.is(Sym::LParen);
            if function {
                self.skip_group()?;
            }
            if !(self.eat(Sym::Assign) || self.eat(Sym::Unify)) {
                return Err(self.unexpected("`:=`"));
            }
            let value = self.term()?;
            return Ok(Rule::Default {
                span,
                name,
                function,
                value,
            });
        }
        let name = self.rule_name()?;
        let (function, set) = (self.is(Sym::LParen), self.is_word("contains"));
        if function {
            self.skip_group()?;
        }
        let value = if set {
            self.bump();
            Some(self.expr()?)
        } else {
            self.assigned()?
        };
        let (bodies, otherwise) = self.bodies()?;
        if value.is_none() && bodies.is_empty() {
            return Err(syntax(span, "a rule needs a value or a body"));
        }
        Ok(match (function, set) {
            (true, _) => Rule::Function { span },
            (_, true) => Rule::Set { span },
            _ => Rule::Value {
                span,
                name,
                value,
                bodies,
                otherwise,
            },
        })
    }

    fn rule_name(&mut self) -> Result<Expr<'s>, Error> {
        let (start, span) = (self.pos, self.span());
        let name = self.name()?;
        if ROOT_DOCUMENTS.contains(&name) {
            return Err(syntax(span, format!("a rule cannot redefine `{name}`")));
        }
        let base = self.node(start, span, ExprKind::Var(name))?;
        self.suffixes(start, base, false)
    }

    fn assigned(&mut self) -> Result<Option<Expr<'s>>, Error> {
        if self.eat(Sym::Assign) || self.eat(Sym::Unify) {
            self.expr().map(Some)
        } else {
            Ok(None)
        }
    }

    /// The bodies after `if`, then any `else` chain.
    fn bodies(&mut self) -> Result<(Vec<Query<'s>>, Option<Span>), Error> {
        if self.is(Sym::LBrace) {
            return Err(syntax(self.span(), "expected `if` before a rule body"));
        }
        if !self.is_word("if") {
            return Ok((Vec::new(), None));
        }
        self.bump();
        let mut bodies = vec![self.body()?];
        while self.is(Sym::LBrace) {
            let open = self.span();
            self.bump();
            let first = self.statement()?;
            bodies.push(self.query(open, first)?);
        }
        Ok((bodies, self.otherwise()?))
    }

    /// The body after `if`: a block, or one statement.
    fn body(&mut self) -> Result<Query<'s>, Error> {
        if self.is(Sym::LBrace) {
            let (save, open) = (self.pos, self.span());
            self.bump();
            // `{` is a set, an object or a comprehension instead when its first statement
            // ends at `,`, `:` or, for `{x | y}`, at `}` after a union.
            if let Ok(first) = self.statement() {
                let union = matches!(
                    first.literal,
                    Literal::Expr(Expr {
                        kind: ExprKind::Unsupported(Construct::Union),
                        ..
                    })
                );
                let literal = matches!(self.sym(), Some(Sym::Comma | Sym::Colon))
                    || (union && self.is(Sym::RBrace));
                if !literal {
                    return self.query(open, first);
                }
            }
            self.pos = save;
        }
        let stmt = self.statement()?;
        Ok(Query {
            span: stmt.span,
            stmts: vec![stmt],
        })
    }

    /// The rest of a block opened at `open`, after its first statement. Statements are
    /// separated by `;` or a new line.
    fn query(&mut self, open: Span, first: Stmt<'s>) -> Result<Query<'s>, Error> {
        let mut stmts = vec![first];
        while !self.eat(Sym::RBrace) {
            let separated = self.eat(Sym::Semi) || self.on_new_line();
            if !separated || self.peek().tok == Tok::Eof {
                return Err(self.unexpected("`}`"));
            }
            stmts.push(self.statement()?);
        }
        Ok(Query { span: open, stmts })
    }

    /// Skips an `else` chain, returning where it starts.
    fn otherwise(&mut self) -> Result<Option<Span>, Error> {
        let start = self.is_word("else").then(|| self.span());
        while self.is_word("else") {
            let span = self.span();
            self.bump();
            let value = self.assigned()?;
            if self.is_word("if") {
                self.bump();
                self.body()?;
            } else if value.is_none() {
                return Err(syntax(span, "`else` needs a value or a body"));
            }
        }
        Ok(start)
    }

    fn statement(&mut self) -> Result<Stmt<'s>, Error> {
        let span = self.span();
        let literal = match self.word() {
            Some(word @ ("some" | "every")) => {
                self.skip_clause()?;
                Literal::Unsupported {
                    span,
                    construct: match word {
                        "some" => "iteration (`some`)",
                        _ => "`every`",
                    },
                }
            }
            Some("not") => {
                self.bump();
                let expr = self.assignment()?;
                Literal::Not { span, expr }
            }
            _ => Literal::Expr(self.assignment()?),
        };
        let with = self.is_word("with").then(|| self.span());
        if with.is_some() {
            self.skip_clause()?;
        }
        Ok(Stmt {
            span,
            with,
            literal,
        })
    }

    /// A statement's expression; an assignment is parsed only to be rejected.
    fn assignment(&mut self) -> Result<Expr<'s>, Error> {
        let start = self.pos;
        let lhs = self.expr()?;
        let span = self.span();
        // Like OPA, only a reference can be assigned to; anything else ends at `:=`.
        let reference = matches!(
            lhs.kind,
            ExprKind::Var(_) | ExprKind::Dot(..) | ExprKind::Index(..)
        );
        if !(reference && (self.eat(Sym::Assign) || self.eat(Sym::Unify))) {
            return Ok(lhs);
        }
        self.expr()?;
        self.node(start, span, ExprKind::Unsupported(Construct::Assignment))
    }

    /// An expression that may be `key, value in collection`.
    fn expr(&mut self) -> Result<Expr<'s>, Error> {
        let start = self.pos;
        let value = self.compare()?;
        if !self.eat(Sym::Comma) {
            return self.memberships(start, value);
        }
        self.compare()?;
        let span = self.span();
        self.expect_word("in")?;
        self.compare()?;
        let value = self.node(start, span, ExprKind::Unsupported(Construct::KeyValueIn))?;
        self.memberships(start, value)
    }

    fn in_expr(&mut self) -> Result<Expr<'s>, Error> {
        let start = self.pos;
        let value = self.compare()?;
        self.memberships(start, value)
    }

    fn memberships(&mut self, start: usize, mut value: Expr<'s>) -> Result<Expr<'s>, Error> {
        while self.is_word("in") {
            let span = self.span();
            self.bump();
            let collection = self.compare()?;
            value = self.node(
                start,
                span,
                ExprKind::In(Box::new(value), Box::new(collection)),
            )?;
        }
        Ok(value)
    }

    /// A left-associative chain of `operand`s joined by the operators `op` recognizes.
    fn chain(
        &mut self,
        operand: fn(&mut Self) -> Result<Expr<'s>, Error>,
        op: fn(Sym) -> Option<Binary>,
    ) -> Result<Expr<'s>, Error> {
        let start = self.pos;
        let mut lhs = operand(self)?;
        while let Some(op) = self.sym().and_then(op) {
            let span = self.span();
            self.bump();
            let rhs = operand(self)?;
            lhs = self.node(start, span, op.kind(lhs, rhs))?;
        }
        Ok(lhs)
    }

    fn compare(&mut self) -> Result<Expr<'s>, Error> {
        self.chain(Self::union, Binary::comparison)
    }

    fn union(&mut self) -> Result<Expr<'s>, Error> {
        self.chain(Self::intersection, |sym| {
            (sym == Sym::Pipe).then_some(Binary::Union)
        })
    }

    fn intersection(&mut self) -> Result<Expr<'s>, Error> {
        self.chain(Self::sum, |sym| {
            (sym == Sym::Amp).then_some(Binary::Intersection)
        })
    }

    fn sum(&mut self) -> Result<Expr<'s>, Error> {
        let start = self.pos;
        let mut lhs = self.product()?;
        loop {
            let token = self.peek();
            let span = token.span;
            let (op, rhs) = match token.tok {
                Tok::Sym(sym @ (Sym::Plus | Sym::Minus)) => {
                    self.bump();
                    let op = match sym {
                        Sym::Plus => ArithOp::Add,
                        _ => ArithOp::Sub,
                    };
                    (op, self.product()?)
                }
                // `a -1` lexes `-1` as one number; it subtracts that number alone.
                Tok::Number(number @ Number { negative: true, .. }) => {
                    let source = self.source;
                    let rhs = Expr {
                        span: Span {
                            col: span.col.saturating_add(1),
                            ..span
                        },
                        text: &source[token.start + 1..token.end],
                        kind: ExprKind::Number(Number {
                            negative: false,
                            ..number
                        }),
                        depth: 1,
                    };
                    self.bump();
                    (ArithOp::Sub, rhs)
                }
                _ => return Ok(lhs),
            };
            lhs = self.node(start, span, Binary::Arith(op).kind(lhs, rhs))?;
        }
    }

    fn product(&mut self) -> Result<Expr<'s>, Error> {
        self.chain(Self::term, Binary::product)
    }

    /// A term; every nested expression is parsed through here, so this bounds the recursion.
    fn term(&mut self) -> Result<Expr<'s>, Error> {
        if self.depth == MAX_DEPTH {
            return Err(syntax(self.span(), "the expression is nested too deeply"));
        }
        self.depth += 1;
        let term = self.nested_term();
        self.depth -= 1;
        term
    }

    fn nested_term(&mut self) -> Result<Expr<'s>, Error> {
        let (start, span) = (self.pos, self.span());
        let kind = match self.sym() {
            Some(Sym::LParen) => {
                self.bump();
                let inner = self.expr()?;
                self.expect(Sym::RParen)?;
                return Ok(inner);
            }
            // Like OPA, a unary minus takes the whole membership expression after it.
            Some(Sym::Minus) => {
                self.bump();
                let inner = self.in_expr()?;
                return self.node(start, span, ExprKind::Neg(Box::new(inner)));
            }
            Some(Sym::LBrack) => ExprKind::Unsupported(if self.skip_group()?.pipe {
                Construct::Comprehension
            } else {
                Construct::Array
            }),
            Some(Sym::LBrace) => self.braces()?,
            _ if self.is_empty_set() => {
                self.pos += 3;
                ExprKind::Set(Vec::new())
            }
            _ => {
                let kind = self.scalar()?;
                self.bump();
                kind
            }
        };
        let callable = matches!(kind, ExprKind::Var(_));
        let base = self.node(start, span, kind)?;
        self.suffixes(start, base, callable)
    }

    /// `set()`, the empty set: `set` touching `(`, then `)`.
    fn is_empty_set(&self) -> bool {
        let name = self.peek();
        name.tok == Tok::Ident("set")
            && matches!(
                &self.tokens[self.pos + 1..],
                [open, close, ..] if open.tok == Tok::Sym(Sym::LParen)
                    && open.start == name.end
                    && close.tok == Tok::Sym(Sym::RParen)
            )
    }

    /// The literal or variable at the current token, which the caller then consumes.
    fn scalar(&self) -> Result<ExprKind<'s>, Error> {
        Ok(match &self.peek().tok {
            Tok::Number(number) => ExprKind::Number(*number),
            // A borrowed `Cow` copies only the reference.
            Tok::String(value) => ExprKind::String(value.clone()),
            Tok::Ident("true") => ExprKind::Bool(true),
            Tok::Ident("false") => ExprKind::Bool(false),
            Tok::Ident("null") => ExprKind::Unsupported(Construct::Null),
            Tok::Ident(word) if !KEYWORDS.contains(word) => ExprKind::Var(word),
            _ => return Err(self.unexpected("an expression")),
        })
    }

    /// `{` opens a set, an object or a comprehension; only a set is parsed.
    fn braces(&mut self) -> Result<ExprKind<'s>, Error> {
        let open = self.pos;
        let group = self.skip_group()?;
        let empty = group.len == 2;
        if group.pipe {
            return Ok(ExprKind::Unsupported(Construct::Comprehension));
        }
        if group.colon || empty {
            return Ok(ExprKind::Unsupported(Construct::Object));
        }
        self.pos = open + 1;
        let mut items = vec![self.in_expr()?];
        while self.eat(Sym::Comma) && !self.is(Sym::RBrace) {
            items.push(self.in_expr()?);
        }
        self.expect(Sym::RBrace)?;
        Ok(ExprKind::Set(items))
    }

    /// `.field`, `[index]` and, on a function name, a call. `.` and `[` must touch what they
    /// follow; on a new line they start the next statement.
    fn suffixes(
        &mut self,
        start: usize,
        mut expr: Expr<'s>,
        mut callable: bool,
    ) -> Result<Expr<'s>, Error> {
        loop {
            let span = self.span();
            let kind = match self.sym() {
                Some(sym @ (Sym::Dot | Sym::LBrack)) if !self.adjacent() => {
                    if self.on_new_line() {
                        return Ok(expr);
                    }
                    return Err(syntax(span, format!("unexpected space before `{sym}`")));
                }
                Some(Sym::Dot) => {
                    self.bump();
                    ExprKind::Dot(Box::new(expr), self.field()?)
                }
                Some(Sym::LBrack) => {
                    self.bump();
                    let index = self.in_expr()?;
                    self.expect(Sym::RBrack)?;
                    callable &= matches!(index.kind, ExprKind::String(_));
                    ExprKind::Index(Box::new(expr), Box::new(index))
                }
                Some(Sym::LParen) if callable => {
                    self.skip_group()?;
                    callable = false;
                    ExprKind::Unsupported(Construct::Call(expr.text))
                }
                _ => return Ok(expr),
            };
            expr = self.node(start, span, kind)?;
        }
    }
}
