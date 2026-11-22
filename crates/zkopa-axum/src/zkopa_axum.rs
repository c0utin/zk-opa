//! Lets axum handlers ask the kernel for a decision.
//!
//! The host keeps one [`Verifier`] in an `Arc` in its router state, reachable through
//! [`FromRef`]. The host also keeps it fresh: a background task of its own fetches signed feed
//! updates and calls [`Verifier::apply_feed`], because a verifier without a recent update denies
//! every request as stale.
//!
//! A handler parses its request as usual, then passes the parsed value to [`Zk::require`]. The
//! proof covers the typed values that [`Input`] returns, never the raw request, so a proxy that
//! rewrites the path or headers cannot break the check.

use std::{
    ops::Deref,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zkopa_kernel::{Decision, Query, TOKEN_LEN};
pub use zkopa_kernel::{Reason, Receipt, Value, Verifier};

/// The request header that carries the proof token, base64url without padding.
pub const TOKEN_HEADER: &str = "zkopa-token";

/// A value a handler is about to act on, as the named, typed fields of a policy's `input`.
///
/// ```ignore
/// impl Input for CreateTransfer {
///     type Fields<'a> = [(&'static str, Value<'a>); 2];
///
///     fn fields(&self) -> Self::Fields<'_> {
///         [
///             ("request.to", Value::Bytes(self.to.as_bytes())),
///             ("request.amount", Value::U64(self.amount)),
///         ]
///     }
/// }
/// ```
pub trait Input {
    /// Usually an array, so building `input` allocates nothing; a `Vec` also works.
    type Fields<'a>: AsRef<[(&'static str, Value<'a>)]>
    where
        Self: 'a;

    /// The fields, each exactly as the handler will use it: a value rounded or normalized here
    /// but used in its original form elsewhere is not protected.
    fn fields(&self) -> Self::Fields<'_>;
}

/// Extracts the proof token from the [`TOKEN_HEADER`] header, with the shared verifier.
pub struct Zk {
    verifier: Arc<Verifier>,
    token: [u8; TOKEN_LEN],
}

impl<S: Send + Sync> FromRequestParts<S> for Zk
where
    Arc<Verifier>: FromRef<S>,
{
    type Rejection = TokenRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(TOKEN_HEADER)
            .ok_or(TokenRejection::Missing)?;
        let mut token = [0; TOKEN_LEN];
        match URL_SAFE_NO_PAD.decode_slice(header.as_bytes(), &mut token) {
            Ok(TOKEN_LEN) => Ok(Self {
                verifier: Arc::from_ref(state),
                token,
            }),
            _ => Err(TokenRejection::Malformed),
        }
    }
}

impl Zk {
    /// Asks the kernel whether the token allows acting on `value` under the decision path
    /// `policy`, at the current time. The token is spent either way: its nonce is recorded on
    /// allow, so a replay to this replica is denied.
    ///
    /// Verification takes milliseconds, so it runs on tokio's blocking pool.
    pub async fn require<T: Input + Send + 'static>(
        self,
        policy: &'static str,
        value: T,
    ) -> Result<Allowed<T>, Denied> {
        let Self { verifier, token } = self;
        let now_ms = now_ms();
        let decided = tokio::task::spawn_blocking(move || {
            let decision = verifier.decide(
                now_ms,
                Query {
                    policy,
                    input: value.fields().as_ref(),
                    token: &token,
                },
            );
            (decision, value)
        })
        .await;
        match decided {
            Ok((Decision::Allow(receipt), value)) => Ok(Allowed { value, receipt }),
            Ok((Decision::Deny(reason), _)) => Err(Denied(reason)),
            // `decide` catches its own panics, so only the handler's `fields` can get here.
            Err(_) => Err(Denied(Reason::Panic)),
        }
    }
}

fn now_ms() -> u64 {
    // A clock before 1970 makes every token's timestamp fall outside the window: a deny.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A value the kernel allowed. Only [`Zk::require`] makes one, so a function that changes state
/// and takes `Allowed<T>` cannot be called without the check.
#[derive(Debug)]
pub struct Allowed<T> {
    value: T,
    receipt: Receipt,
}

impl<T> Allowed<T> {
    /// The kernel's receipt. Use its nonce as the idempotency key of a write, in the same
    /// database transaction: replicas do not share the nonces they have seen.
    pub fn receipt(&self) -> Receipt {
        self.receipt
    }

    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T> Deref for Allowed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

/// The kernel denied the request. Responds 403 with the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Denied(pub Reason);

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        (StatusCode::FORBIDDEN, self.0.to_string()).into_response()
    }
}

/// The request carries no usable proof token. Responds 401.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenRejection {
    #[error("the zkopa-token header is missing")]
    Missing,
    #[error("the zkopa-token header is not a base64url token without padding")]
    Malformed,
}

impl IntoResponse for TokenRejection {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
    }
}
