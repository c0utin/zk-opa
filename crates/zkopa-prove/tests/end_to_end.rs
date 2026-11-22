//! Setup, login and request proofs checked by the real kernel.

use ark_std::rand::{SeedableRng, rngs::StdRng};
use ed25519_dalek::{Signer, SigningKey};
use zkopa_ir::Schema;
use zkopa_kernel::{
    Decision, FeedUpdate, Query, Reason, Value, Verifier, attach_signature, request_inputs,
};
use zkopa_prove::{
    Credential, Error, Fr, IssuerKey, Params, Prover, Request, RevocationTree, setup,
};

const START: u64 = 1_700_000_000_000;
const NOW: u64 = START + 1_000;
const EPOCH: u64 = 40;
const AUDIENCE: &str = "transfers";
const PATH: &str = "transfers/create/allow";

const POLICY: &str = r#"
package transfers.create

default allow := false

allow if {
    input.request.amount <= input.subject.income * 3 / 10
    input.subject.kyc_level >= 2
    input.request.to != "mallory"
}
"#;

fn sign(root: &SigningKey, body: Vec<u8>) -> Vec<u8> {
    let signature = root.sign(&body).to_bytes();
    attach_signature(body, &signature)
}

fn feed(sequence: u64, root: Fr, revoked: Vec<Fr>) -> FeedUpdate {
    FeedUpdate {
        sequence,
        issued_ms: NOW,
        min_bundle_version: 1,
        revoked,
        roots: vec![(EPOCH, root)],
    }
}

#[test]
fn the_kernel_allows_an_honest_request_and_denies_changes_and_revocation() {
    let mut rng = StdRng::seed_from_u64(42);
    let root = SigningKey::from_bytes(&[9; 32]);
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
    // The client gets its proving data as bytes.
    let prover = Prover::decode(&prover.encode()).unwrap();

    let verifier = Verifier::new(START, &root.verifying_key().to_bytes(), AUDIENCE, &{
        sign(&root, bundle.encode())
    })
    .unwrap();
    let mut revoked = RevocationTree::default();
    revoked.revoke(3);
    verifier
        .apply_feed(NOW, &sign(&root, feed(1, revoked.root(), vec![]).encode()))
        .unwrap();

    let credential = Credential {
        id: 77,
        attributes: vec![10_000, 2],
        exp: EPOCH + 10,
    };
    let session = prover
        .login(issuer.sign(credential, &mut rng), &revoked, EPOCH, &mut rng)
        .unwrap();

    let input = [
        ("request.to", Value::Bytes(b"bob")),
        ("request.amount", Value::U64(3_000)),
    ];
    let request = |nonce: u64, input| Request {
        audience: AUDIENCE,
        policy: PATH,
        input,
        ts: NOW,
        nonce: Fr::from(nonce),
        root_epoch: EPOCH,
    };
    let decide = |input: &[(&str, Value<'_>)], token: &[u8]| {
        verifier.decide(
            NOW,
            Query {
                policy: PATH,
                input,
                token,
            },
        )
    };

    let token = prover
        .prove(&session, request(1, &input), &mut rng)
        .unwrap();
    let encoded = token.encode();
    // The proof covers exactly the inputs the kernel derives from the handler's values.
    let changed = [
        ("request.to", Value::Bytes(b"bob")),
        ("request.amount", Value::U64(2_999)),
    ];
    assert_eq!(
        decide(&changed, &encoded),
        Decision::Deny(Reason::BadRequestProof)
    );
    assert!(matches!(decide(&input, &encoded), Decision::Allow(_)));

    // The client refuses what it cannot prove, with a reason.
    let too_much = [
        ("request.to", Value::Bytes(b"bob")),
        ("request.amount", Value::U64(3_001)),
    ];
    assert!(matches!(
        prover.prove(&session, request(2, &too_much), &mut rng),
        Err(Error::Denied)
    ));
    assert!(matches!(
        prover.prove(&session, request(2, &input[..1]), &mut rng),
        Err(Error::InputMismatch)
    ));
    assert!(matches!(
        prover.prove(
            &session,
            Request {
                policy: "transfers/delete/allow",
                ..request(2, &input)
            },
            &mut rng
        ),
        Err(Error::UnknownPolicy(_))
    ));

    // The issuer revokes the session's tag; the next request is denied.
    verifier
        .apply_feed(
            NOW,
            &sign(&root, feed(2, revoked.root(), vec![session.tag()]).encode()),
        )
        .unwrap();
    let token = prover
        .prove(&session, request(3, &input), &mut rng)
        .unwrap();
    assert_eq!(
        decide(&input, &token.encode()),
        Decision::Deny(Reason::Revoked)
    );
    // It is the same statement the kernel checks against.
    let public = request_inputs(
        &token.claims,
        AUDIENCE,
        PATH,
        &bundle.policies[0].layout,
        &input,
    );
    assert_eq!(public.unwrap()[0], session.commitment());
}

#[test]
fn login_refuses_credentials_the_circuit_would_reject() {
    let mut rng = StdRng::seed_from_u64(43);
    let issuer = IssuerKey::generate(&mut rng);
    let schema = Schema::new(vec!["income".into()]).unwrap();
    let policies =
        zkopa_policy::compile("package p\nallow if input.subject.income > 1\n", &schema).unwrap();
    let params = Params {
        version: 1,
        window_ms: 1,
        stale_ms: 1,
        session_epochs: 1,
    };
    let (_, prover) = setup(schema, issuer.public(), params, policies, &mut rng).unwrap();
    let mut revoked = RevocationTree::default();
    revoked.revoke(5);
    let login = |id, attributes: Vec<u64>, exp, rng: &mut StdRng| {
        let credential = issuer.sign(
            Credential {
                id,
                attributes,
                exp,
            },
            rng,
        );
        prover.login(credential, &revoked, EPOCH, rng)
    };
    assert!(matches!(
        login(5, vec![2], EPOCH + 1, &mut rng),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        login(6, vec![2], EPOCH, &mut rng),
        Err(Error::Expired)
    ));
    assert!(matches!(
        login(6, vec![2, 3], EPOCH + 1, &mut rng),
        Err(Error::Schema { .. })
    ));
    let other = IssuerKey::generate(&mut rng).sign(
        Credential {
            id: 6,
            attributes: vec![2],
            exp: EPOCH + 1,
        },
        &mut rng,
    );
    assert!(matches!(
        prover.login(other, &revoked, EPOCH, &mut rng),
        Err(Error::Signature)
    ));
}
