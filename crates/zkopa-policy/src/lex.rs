//! Splits a Rego module into tokens, each with the line and column where it starts.
//!
//! Columns count bytes, and a tab as [`TAB_WIDTH`], the way OPA reports them.

use std::borrow::Cow;
use std::fmt;

use crate::{Error, syntax};

/// Columns a tab advances.
const TAB_WIDTH: u32 = 4;

/// Hex digits in a `\u` escape.
const CODE_UNIT_DIGITS: usize = 4;

/// Decimal digits in `u64::MAX`, the widest integer constant.
const U64_DIGITS: i64 = u64::MAX.ilog10() as i64 + 1;

/// Where a token starts, 1-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Span {
    pub line: u32,
    pub col: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sym {
    Assign,
    Unify,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    Pipe,
    LBrace,
    RBrace,
    LBrack,
    RBrack,
    LParen,
    RParen,
    Comma,
    Semi,
    Dot,
    Colon,
}

impl Sym {
    /// Every symbol. Lexing takes the longest that matches, so the order does not matter.
    const ALL: [Sym; 25] = [
        Sym::Assign,
        Sym::Unify,
        Sym::Eq,
        Sym::Ne,
        Sym::Lt,
        Sym::Le,
        Sym::Gt,
        Sym::Ge,
        Sym::Plus,
        Sym::Minus,
        Sym::Star,
        Sym::Slash,
        Sym::Percent,
        Sym::Amp,
        Sym::Pipe,
        Sym::LBrace,
        Sym::RBrace,
        Sym::LBrack,
        Sym::RBrack,
        Sym::LParen,
        Sym::RParen,
        Sym::Comma,
        Sym::Semi,
        Sym::Dot,
        Sym::Colon,
    ];

    fn text(self) -> &'static str {
        match self {
            Sym::Assign => ":=",
            Sym::Unify => "=",
            Sym::Eq => "==",
            Sym::Ne => "!=",
            Sym::Lt => "<",
            Sym::Le => "<=",
            Sym::Gt => ">",
            Sym::Ge => ">=",
            Sym::Plus => "+",
            Sym::Minus => "-",
            Sym::Star => "*",
            Sym::Slash => "/",
            Sym::Percent => "%",
            Sym::Amp => "&",
            Sym::Pipe => "|",
            Sym::LBrace => "{",
            Sym::RBrace => "}",
            Sym::LBrack => "[",
            Sym::RBrack => "]",
            Sym::LParen => "(",
            Sym::RParen => ")",
            Sym::Comma => ",",
            Sym::Semi => ";",
            Sym::Dot => ".",
            Sym::Colon => ":",
        }
    }
}

impl fmt::Display for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// A number literal. Only integers of magnitude up to `u64::MAX` compile; the rest keep just
/// enough to be rejected precisely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Number {
    pub negative: bool,
    pub magnitude: Magnitude,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Magnitude {
    Int(u64),
    Fraction,
    TooLarge,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Tok<'s> {
    Ident(&'s str),
    Number(Number),
    /// A quoted or raw string's value, escapes resolved.
    String(Cow<'s, str>),
    Sym(Sym),
    Eof,
}

pub(crate) struct Token<'s> {
    pub tok: Tok<'s>,
    pub span: Span,
    /// The byte range in the source.
    pub start: usize,
    pub end: usize,
}

/// The tokens of `source`, ending with one [`Tok::Eof`].
pub(crate) fn tokens(source: &str) -> Result<Vec<Token<'_>>, Error> {
    let mut lexer = Lexer {
        source,
        pos: 0,
        line: 1,
        col: 1,
    };
    let mut tokens = Vec::new();
    loop {
        let token = lexer.token()?;
        let end = token.tok == Tok::Eof;
        tokens.push(token);
        if end {
            return Ok(tokens);
        }
    }
}

struct Lexer<'s> {
    source: &'s str,
    pos: usize,
    line: u32,
    col: u32,
}

impl<'s> Lexer<'s> {
    fn rest(&self) -> &'s str {
        let source = self.source;
        &source[self.pos..]
    }

    fn here(&self) -> Span {
        Span {
            line: self.line,
            col: self.col,
        }
    }

    /// Moves past `len` bytes, counting lines and columns.
    fn advance(&mut self, len: usize) {
        let source = self.source;
        source.as_bytes()[self.pos..self.pos + len]
            .iter()
            .for_each(|&b| match b {
                b'\n' => {
                    self.line = self.line.saturating_add(1);
                    self.col = 1;
                }
                b'\t' => self.col = self.col.saturating_add(TAB_WIDTH),
                _ => self.col = self.col.saturating_add(1),
            });
        self.pos += len;
    }

    fn skip_trivia(&mut self) -> Result<(), Error> {
        loop {
            let rest = self.rest();
            let len = match rest.as_bytes() {
                [b' ' | b'\t' | b'\n', ..] | [b'\r', b'\n', ..] => 1,
                [b'\r', ..] => return Err(syntax(self.here(), "`\\r` must be followed by `\\n`")),
                // A comment runs to the end of the line.
                [b'#', ..] => rest.find('\n').unwrap_or(rest.len()),
                _ => return Ok(()),
            };
            self.advance(len);
        }
    }

    fn token(&mut self) -> Result<Token<'s>, Error> {
        self.skip_trivia()?;
        let (start, span) = (self.pos, self.here());
        // A string's position is that of its first character, after the quote.
        let inner = Span {
            col: span.col.saturating_add(1),
            ..span
        };
        let (tok, span) = match self.rest().as_bytes() {
            [] => (Tok::Eof, span),
            [b'-', d, ..] | [d, ..] if d.is_ascii_digit() => (self.number(span)?, span),
            [b'.', d, ..] if d.is_ascii_digit() => {
                return Err(syntax(span, "a number must start with a digit"));
            }
            [b'"', ..] => (self.string(span)?, inner),
            [b'`', ..] => (self.raw_string(span)?, inner),
            [c, ..] if c.is_ascii_alphabetic() || *c == b'_' => (self.ident(), span),
            _ => (Tok::Sym(self.symbol(span)?), span),
        };
        Ok(Token {
            tok,
            span,
            start,
            end: self.pos,
        })
    }

    fn ident(&mut self) -> Tok<'s> {
        let rest = self.rest();
        let len = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        self.advance(len);
        Tok::Ident(&rest[..len])
    }

    fn symbol(&mut self, span: Span) -> Result<Sym, Error> {
        let rest = self.rest();
        let sym = Sym::ALL
            .into_iter()
            .filter(|sym| rest.starts_with(sym.text()))
            .max_by_key(|sym| sym.text().len())
            .ok_or_else(|| syntax(span, "unexpected character"))?;
        self.advance(sym.text().len());
        Ok(sym)
    }

    /// A JSON number, optionally negative: `-12`, `0`, `1.5`, `2e3`.
    fn number(&mut self, span: Span) -> Result<Tok<'s>, Error> {
        let rest = self.rest();
        let bytes = rest.as_bytes();
        let digits_from =
            |i: usize| i + bytes[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        let negative = bytes.first() == Some(&b'-');
        let int_start = usize::from(negative);
        // A leading zero stands alone, so `01` is malformed.
        let int_end = match bytes.get(int_start) {
            Some(b'0') => int_start + 1,
            _ => digits_from(int_start),
        };
        let frac_end = match bytes.get(int_end..int_end + 2) {
            Some([b'.', d]) if d.is_ascii_digit() => digits_from(int_end + 1),
            _ => int_end,
        };
        let (exponent, end) = match bytes.get(frac_end) {
            Some(b'e' | b'E') => {
                let sign = bytes.get(frac_end + 1).copied();
                let digits = frac_end + 1 + usize::from(matches!(sign, Some(b'+' | b'-')));
                let end = digits_from(digits);
                if end == digits {
                    return Err(syntax(span, "an exponent needs digits"));
                }
                let value = rest[digits..end].bytes().fold(0i64, |e, d| {
                    e.saturating_mul(10).saturating_add(i64::from(d - b'0'))
                });
                let exponent = match sign {
                    Some(b'-') => -value,
                    _ => value,
                };
                (exponent, end)
            }
            _ => (0, frac_end),
        };
        if bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        {
            return Err(syntax(span, "malformed number"));
        }
        // OPA reads numbers as JSON, which has no infinity.
        if rest[..end].parse::<f64>().is_ok_and(f64::is_infinite) {
            return Err(syntax(span, "number out of range"));
        }
        self.advance(end);
        let fraction = rest.get(int_end + 1..frac_end).unwrap_or("");
        Ok(Tok::Number(Number {
            negative,
            magnitude: magnitude(&rest[int_start..int_end], fraction, exponent),
        }))
    }

    /// A JSON string; `open` is where its opening quote is.
    fn string(&mut self, open: Span) -> Result<Tok<'s>, Error> {
        self.advance(1);
        // Borrowed from the source until an escape needs a copy.
        let mut value = Cow::Borrowed("");
        loop {
            let rest = self.rest();
            let run = rest
                .find(|c: char| c == '"' || c == '\\' || c < ' ')
                .unwrap_or(rest.len());
            value += &rest[..run];
            self.advance(run);
            match self.rest().as_bytes().first() {
                Some(b'"') => {
                    self.advance(1);
                    return Ok(Tok::String(value));
                }
                Some(b'\\') => {
                    let c = self.escape()?;
                    value.to_mut().push(c);
                }
                Some(b'\n') | None => return Err(syntax(open, "unterminated string")),
                Some(_) => return Err(syntax(self.here(), "a control character in a string")),
            }
        }
    }

    fn escape(&mut self) -> Result<char, Error> {
        let at = self.here();
        let c = match self.rest().as_bytes().get(1) {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.advance(2);
                return self.unicode(at);
            }
            _ => return Err(syntax(at, "invalid escape sequence")),
        };
        self.advance(2);
        Ok(c)
    }

    /// The character of a `\u` escape whose backslash is at `at`.
    fn unicode(&mut self, at: Span) -> Result<char, Error> {
        let invalid = || syntax(at, "invalid `\\u` escape");
        let first = self.code_unit().ok_or_else(invalid)?;
        match char::from_u32(first.into()) {
            Some(c) => Ok(c),
            // A surrogate is valid only as the first half of a pair, written as a second `\u`.
            None if self.rest().starts_with("\\u") => {
                self.advance(2);
                let second = self.code_unit().ok_or_else(invalid)?;
                char::decode_utf16([first, second])
                    .next()
                    .and_then(Result::ok)
                    .ok_or_else(invalid)
            }
            None => Err(invalid()),
        }
    }

    fn code_unit(&mut self) -> Option<u16> {
        let hex = self
            .rest()
            .get(..CODE_UNIT_DIGITS)
            .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))?;
        let unit = u16::from_str_radix(hex, 16).ok()?;
        self.advance(CODE_UNIT_DIGITS);
        Some(unit)
    }

    /// A raw string, between backquotes, which may span lines and has no escapes.
    fn raw_string(&mut self, open: Span) -> Result<Tok<'s>, Error> {
        self.advance(1);
        let rest = self.rest();
        let len = rest
            .find('`')
            .ok_or_else(|| syntax(open, "unterminated raw string"))?;
        self.advance(len + 1);
        Ok(Tok::String(Cow::Borrowed(&rest[..len])))
    }
}

/// The magnitude of the decimal `int.frac × 10^exponent`, exactly.
fn magnitude(int: &str, frac: &str, exponent: i64) -> Magnitude {
    let digits = || int.bytes().chain(frac.bytes());
    let total = int.len() + frac.len();
    let leading = digits().take_while(|&d| d == b'0').count();
    if leading == total {
        return Magnitude::Int(0);
    }
    let trailing = digits().rev().take_while(|&d| d == b'0').count();
    let significant = total - leading - trailing;
    // The value is the significant digits times 10^scale.
    let scale = exponent
        .saturating_sub(frac.len() as i64)
        .saturating_add(trailing as i64);
    if scale < 0 {
        return Magnitude::Fraction;
    }
    if (significant as i64).saturating_add(scale) > U64_DIGITS {
        return Magnitude::TooLarge;
    }
    // At most `U64_DIGITS` digits, so `u128` holds the value exactly.
    let value = digits()
        .skip(leading)
        .take(significant)
        .fold(0u128, |v, d| v * 10 + u128::from(d - b'0'))
        * 10u128.pow(scale as u32);
    u64::try_from(value).map_or(Magnitude::TooLarge, Magnitude::Int)
}
