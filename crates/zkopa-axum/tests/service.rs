//! A service behind `zkopa-axum`, with real proofs and no network.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ark_std::rand::{SeedableRng, rngs::StdRng};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SECRET_KEY_LENGTH, Signer, SigningKey};
use serde::Deserialize;
use tower::ServiceExt;
use zkopa_axum::{Allowed, Denied, Input, TOKEN_HEADER, Value, Verifier, Zk};
use zkopa_ir::Schema;
use zkopa_kernel::{FeedUpdate, attach_signature};
use zkopa_prove::{Credential, Fr, IssuerKey, Params, RevocationTree, setup};

const AUDIENCE: &str = "transfers";
const PATH: &str = "transfers/create/allow";
const EPOCH: u64 = 40;

const POLICY: &str = r#"
package transfers.create

default allow := false

allow if {
    input.request.amount <= input.subject.income * 3 / 10
    input.subject.kyc_level >= 2
}
"#;

#[derive(Deserialize)]
struct CreateTransfer {
    to: String,
    amount: u64,
}

impl Input for CreateTransfer {
    // The policy reads only the amount, so that is its whole layout.
    type Fields<'a> = [(&'static str, Value<'a>); 1];

    fn fields(&self) -> Self::Fields<'_> {
        [("request.amount", Value::U64(self.amount))]
    }
}

async fn create_transfer(
    zk: Zk,
    Json(body): Json<CreateTransfer>,
) -> Result<(StatusCode, String), Denied> {
    let transfer = zk.require(PATH, body).await?;
    Ok((StatusCode::CREATED, book(transfer)))
}

/// Takes only an allowed transfer, and keys it by the request's nonce.
fn book(transfer: Allowed<CreateTransfer>) -> String {
    let nonce = transfer.receipt().nonce();
    format!("{nonce} {} {}", transfer.to, transfer.amount)
}

fn now_ms() -> u64 {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    u64::try_from(elapsed.as_millis()).unwrap()
}

fn sign(root: &SigningKey, body: Vec<u8>) -> Vec<u8> {
    let signature = root.sign(&body).to_bytes();
    attach_signature(body, &signature)
}

async fn send(app: Router, uri: &str, token: Option<&str>, amount: u64) -> (StatusCode, String) {
    let mut request = Request::post(uri).header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header(TOKEN_HEADER, token);
    }
    let body = Body::from(format!(r#"{{"to":"bob","amount":{amount}}}"#));
    let response = app.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn a_service_allows_the_proven_request_and_nothing_else() {
    let mut rng = StdRng::seed_from_u64(7);
    let root = SigningKey::from_bytes(&[3; SECRET_KEY_LENGTH]);
    let issuer = IssuerKey::generate(&mut rng);
    let schema = Schema::new(vec!["income".into(), "kyc_level".into()]).unwrap();
    let policies = zkopa_policy::compile(POLICY, &schema).unwrap();
    let params = Params {
        version: 1,
        window_ms: 30_000,
        stale_ms: 60_000,
        session_epochs: 2,
    };
    let (bundle, prover) = setup(schema, issuer.public(), params, policies, &mut rng).unwrap();

    let start = now_ms();
    let root_key = root.verifying_key().to_bytes();
    let verifier =
        Verifier::new(start, &root_key, AUDIENCE, &sign(&root, bundle.encode())).unwrap();
    let revoked = RevocationTree::default();
    let feed = FeedUpdate {
        sequence: 1,
        issued_ms: start,
        min_bundle_version: 1,
        revoked: vec![],
        roots: vec![(EPOCH, revoked.root())],
    };
    verifier
        .apply_feed(start, &sign(&root, feed.encode()))
        .unwrap();

    let credential = Credential {
        id: 77,
        attributes: vec![10_000, 2],
        exp: EPOCH + 10,
    };
    let session = prover
        .login(issuer.sign(credential, &mut rng), &revoked, EPOCH, &mut rng)
        .unwrap();
    let mut token = |nonce: u64, amount: u64| {
        let request = zkopa_prove::Request {
            audience: AUDIENCE,
            policy: PATH,
            input: &[("request.amount", Value::U64(amount))],
            ts: now_ms(),
            nonce: Fr::from(nonce),
            root_epoch: EPOCH,
        };
        let token = prover.prove(&session, request, &mut rng).unwrap();
        URL_SAFE_NO_PAD.encode(token.encode())
    };

    let app = Router::new()
        .route("/transfers", post(create_transfer))
        .with_state(Arc::new(verifier));

    let honest = token(1, 3_000);
    assert_eq!(
        send(app.clone(), "/transfers", Some(&honest), 3_000).await,
        (StatusCode::CREATED, "1 bob 3000".into())
    );
    assert_eq!(
        send(app.clone(), "/transfers", Some(&honest), 3_000).await,
        (StatusCode::FORBIDDEN, "the nonce was already used".into())
    );

    let fresh = token(2, 3_000);
    assert_eq!(
        send(app.clone(), "/transfers", Some(&fresh), 2_999).await,
        (
            StatusCode::FORBIDDEN,
            "the request proof does not verify".into()
        )
    );

    assert_eq!(
        send(app.clone(), "/transfers", None, 3_000).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Padding, a dropped character and the standard alphabet are all refused before the kernel.
    for malformed in [
        format!("{fresh}="),
        fresh[1..].to_string(),
        format!("+{}", &fresh[1..]),
    ] {
        assert_eq!(
            send(app.clone(), "/transfers", Some(&malformed), 3_000)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    // A gateway that mounts the service under another path changes nothing the proof covers.
    let gateway = Router::new().nest("/api/v1", app);
    assert_eq!(
        send(gateway, "/api/v1/transfers", Some(&token(3, 3_000)), 3_000).await,
        (StatusCode::CREATED, "3 bob 3000".into())
    );
}
