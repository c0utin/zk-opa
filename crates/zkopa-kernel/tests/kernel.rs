//! Every test goes through the public API with real Groth16 proofs. The test circuits only
//! allocate their public inputs, so a proof can be made for any chosen statement.

use std::sync::{Barrier, LazyLock};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use ed25519_dalek::{Signer, SigningKey};
use zkopa_kernel::{
    Bundle, BundleError, Claims, Decision, DecodeError, FeedError, FeedUpdate, Field, Issuer,
    LOGIN_INPUTS, PROOF_LEN, Policy, PreparedVerifyingKey, Profile, Proof, Query, Reason,
    TOKEN_LEN, Token, Type, Value, Verifier, VerifyingKey, attach_signature, login_inputs,
    request_inputs,
};

const START: u64 = 1_700_000_000_000;
const NOW: u64 = START + 10_000;
const WINDOW: u64 = 30_000;
const STALE: u64 = 60_000;
const SESSION_EPOCHS: u64 = 2;
const LOGIN_EPOCH: u64 = 9;
const ROOT_EPOCH: u64 = 10;
const AUDIENCE: &str = "transfers";
const PATH: &str = "transfers/create/allow";
/// Shares the layout and key of `PATH`, so only the encoded path tells them apart.
const OTHER_PATH: &str = "transfers/cancel/allow";

const INPUT: [(&str, Value<'static>); 4] = [
    ("request.to", Value::Bytes(b"bob")),
    ("request.amount", Value::U64(500)),
    ("request.fee", Value::U64(3)),
    ("request.urgent", Value::Bool(false)),
];

static ROOT: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::from_bytes(&[7; 32]));

/// Allocates its values as public inputs and does nothing else.
struct Inputs(Vec<Fr>);

impl ConstraintSynthesizer<Fr> for Inputs {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::gr1cs::Result<()> {
        for value in self.0 {
            let _ = cs.new_input_variable(|| Ok(value))?;
        }
        Ok(())
    }
}

struct Keys {
    login: ProvingKey<Bn254>,
    request: ProvingKey<Bn254>,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let mut rng = StdRng::seed_from_u64(1);
    let mut setup = |count| {
        Groth16::<Bn254>::generate_random_parameters_with_reduction(
            Inputs(vec![Fr::from(0u64); count]),
            &mut rng,
        )
        .unwrap()
    };
    Keys {
        login: setup(LOGIN_INPUTS),
        request: setup(6 + INPUT.len()),
    }
});

/// The kernel's copy of a test key's verifying key.
fn vk(key: &ProvingKey<Bn254>) -> VerifyingKey {
    VerifyingKey {
        alpha_g1: key.vk.alpha_g1,
        beta_g2: key.vk.beta_g2,
        gamma_g2: key.vk.gamma_g2,
        delta_g2: key.vk.delta_g2,
        gamma_abc_g1: key.vk.gamma_abc_g1.clone(),
    }
}

fn to_kernel(proof: ark_groth16::Proof<Bn254>) -> Proof {
    Proof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    }
}

fn to_ark(proof: Proof) -> ark_groth16::Proof<Bn254> {
    ark_groth16::Proof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
    }
}

fn layout() -> Vec<Field> {
    let field = |name: &str, ty| Field {
        name: name.to_owned(),
        ty,
    };
    vec![
        field("request.to", Type::Bytes),
        field("request.amount", Type::U64),
        field("request.fee", Type::U64),
        field("request.urgent", Type::Bool),
    ]
}

fn issuer() -> Issuer {
    Issuer {
        x: Fr::from(11u64),
        y: Fr::from(12u64),
    }
}

fn revocation_root(epoch: u64) -> Fr {
    Fr::from(1000 + epoch)
}

fn bundle() -> Bundle {
    let policy = |path: &str| Policy {
        path: path.to_owned(),
        layout: layout(),
        key: vk(&KEYS.request),
    };
    Bundle {
        profile: Profile::Groth16Bn254,
        version: 1,
        issuer: issuer(),
        window_ms: WINDOW,
        stale_ms: STALE,
        session_epochs: SESSION_EPOCHS,
        login_key: vk(&KEYS.login),
        policies: vec![policy(PATH), policy(OTHER_PATH)],
    }
}

fn sign(body: Vec<u8>) -> Vec<u8> {
    let signature = ROOT.sign(&body).to_bytes();
    attach_signature(body, &signature)
}

fn root_key() -> [u8; 32] {
    ROOT.verifying_key().to_bytes()
}

fn feed(sequence: u64, issued_ms: u64) -> FeedUpdate {
    FeedUpdate {
        sequence,
        issued_ms,
        min_bundle_version: 1,
        revoked: vec![Fr::from(5u64)],
        roots: vec![
            (ROOT_EPOCH, revocation_root(ROOT_EPOCH)),
            (LOGIN_EPOCH, revocation_root(LOGIN_EPOCH)),
        ],
    }
}

fn load(audience: &str) -> Verifier {
    Verifier::new(START, &root_key(), audience, &sign(bundle().encode())).unwrap()
}

/// A verifier with the test bundle and one fresh feed update.
fn verifier() -> Verifier {
    let verifier = load(AUDIENCE);
    verifier
        .apply_feed(NOW, &sign(feed(1, NOW).encode()))
        .unwrap();
    verifier
}

fn claims(nonce: u64) -> Claims {
    Claims {
        commitment: Fr::from(77u64),
        tag: Fr::from(88u64),
        login_epoch: LOGIN_EPOCH,
        ts: NOW,
        nonce: Fr::from(nonce),
        root_epoch: ROOT_EPOCH,
    }
}

/// What an honest client sends after proving `claims` for `path`, `audience` and `input`.
fn prove(claims: Claims, audience: &str, path: &str, input: &[(&str, Value<'_>)]) -> Token {
    let mut rng = StdRng::seed_from_u64(claims.ts ^ claims.root_epoch);
    let login = login_inputs(issuer(), revocation_root(claims.login_epoch), &claims);
    let request = request_inputs(&claims, audience, path, &layout(), input).unwrap();
    let mut prove = |key, inputs: Vec<Fr>| {
        to_kernel(
            Groth16::<Bn254>::create_random_proof_with_reduction(Inputs(inputs), key, &mut rng)
                .unwrap(),
        )
    };
    Token {
        claims,
        login_proof: prove(&KEYS.login, login.to_vec()),
        request_proof: prove(&KEYS.request, request),
    }
}

fn token(claims: Claims) -> Vec<u8> {
    prove(claims, AUDIENCE, PATH, &INPUT).encode()
}

fn decide_at(
    verifier: &Verifier,
    now_ms: u64,
    policy: &str,
    input: &[(&str, Value<'_>)],
    token: &[u8],
) -> Decision {
    verifier.decide(
        now_ms,
        Query {
            policy,
            input,
            token,
        },
    )
}

fn decide(verifier: &Verifier, token: &[u8]) -> Decision {
    decide_at(verifier, NOW, PATH, &INPUT, token)
}

fn denied(reason: Reason) -> Decision {
    Decision::Deny(reason)
}

#[test]
fn honest_query_allows_with_its_nonce_and_commitment() {
    let verifier = verifier();
    let Decision::Allow(receipt) = decide(&verifier, &token(claims(1))) else {
        panic!("denied");
    };
    assert_eq!(receipt.nonce(), Fr::from(1u64));
    assert_eq!(receipt.commitment(), Fr::from(77u64));

    // The handler may list its fields in any order.
    let mut reversed = INPUT;
    reversed.reverse();
    let token = token(claims(2));
    assert!(matches!(
        decide_at(&verifier, NOW, PATH, &reversed, &token),
        Decision::Allow(_)
    ));
}

#[test]
fn input_values_and_their_order_are_bound() {
    let verifier = verifier();
    let token = token(claims(1));
    let mut changed = INPUT;
    changed[1].1 = Value::U64(501);
    let mut swapped = INPUT;
    swapped[1].1 = Value::U64(3);
    swapped[2].1 = Value::U64(500);
    let mut other_bytes = INPUT;
    other_bytes[0].1 = Value::Bytes(b"bobb");
    let mut flipped_bool = INPUT;
    flipped_bool[3].1 = Value::Bool(true);
    for input in [changed, swapped, other_bytes, flipped_bool] {
        assert_eq!(
            decide_at(&verifier, NOW, PATH, &input, &token),
            denied(Reason::BadRequestProof)
        );
    }
    assert!(matches!(decide(&verifier, &token), Decision::Allow(_)));
}

#[test]
fn input_not_matching_the_layout_denies_before_any_proof() {
    let verifier = verifier();
    // A garbage request proof: only the layout check can deny before it is looked at.
    let mut bytes = token(claims(1));
    bytes[TOKEN_LEN - PROOF_LEN..].fill(0);
    let [to, amount, fee, urgent] = INPUT;
    let missing = [to, amount, fee];
    let extra = [to, amount, fee, urgent, ("request.memo", Value::U64(0))];
    let wrong_type = [to, ("request.amount", Value::Bool(true)), fee, urgent];
    let duplicate = [to, amount, amount, urgent];
    let duplicate_extra = [to, amount, amount, fee, urgent];
    let inputs: [&[(&str, Value<'_>)]; 5] =
        [&missing, &extra, &wrong_type, &duplicate, &duplicate_extra];
    for input in inputs {
        assert_eq!(
            decide_at(&verifier, NOW, PATH, input, &bytes),
            denied(Reason::InputMismatch)
        );
    }
}

#[test]
fn decision_path_and_audience_are_bound() {
    let verifier = verifier();
    let token = token(claims(1));
    assert_eq!(
        decide_at(&verifier, NOW, OTHER_PATH, &INPUT, &token),
        denied(Reason::BadRequestProof)
    );
    assert_eq!(
        decide_at(&verifier, NOW, "transfers/delete/allow", &INPUT, &token),
        denied(Reason::UnknownPolicy)
    );

    let elsewhere = load("payments");
    elsewhere
        .apply_feed(NOW, &sign(feed(1, NOW).encode()))
        .unwrap();
    assert_eq!(decide(&elsewhere, &token), denied(Reason::BadRequestProof));
}

#[test]
fn every_token_claim_is_bound_by_a_proof() {
    let verifier = verifier();
    let honest = prove(claims(1), AUDIENCE, PATH, &INPUT);
    type Change = fn(&mut Claims);
    let cases: [(Change, Reason); 6] = [
        (|c| c.commitment += Fr::from(1u64), Reason::BadLoginProof),
        (|c| c.tag += Fr::from(1u64), Reason::BadLoginProof),
        (|c| c.login_epoch = ROOT_EPOCH, Reason::BadLoginProof),
        (|c| c.ts += 1, Reason::BadRequestProof),
        (|c| c.nonce += Fr::from(1u64), Reason::BadRequestProof),
        (|c| c.root_epoch = LOGIN_EPOCH, Reason::BadRequestProof),
    ];
    for (change, reason) in cases {
        let mut token = honest.clone();
        change(&mut token.claims);
        assert_eq!(decide(&verifier, &token.encode()), denied(reason));
    }
    assert!(matches!(
        decide(&verifier, &honest.encode()),
        Decision::Allow(_)
    ));
}

#[test]
fn flipped_proof_bytes_deny() {
    let honest = token(claims(1));
    for offset in [0, 31, 64, 100, PROOF_LEN - 1] {
        let verifier = verifier();
        let mut login = honest.clone();
        login[TOKEN_LEN - 2 * PROOF_LEN + offset] ^= 1;
        assert_eq!(decide(&verifier, &login), denied(Reason::BadLoginProof));
        let mut request = honest.clone();
        request[TOKEN_LEN - PROOF_LEN + offset] ^= 1;
        assert_eq!(decide(&verifier, &request), denied(Reason::BadRequestProof));
    }
}

#[test]
fn malformed_tokens_deny() {
    let verifier = verifier();
    let honest = token(claims(1));
    let modulus = Fr::MODULUS.to_bytes_le();
    let mut non_canonical = honest.clone();
    non_canonical[5..37].copy_from_slice(&modulus);
    assert_eq!(decide(&verifier, &non_canonical), denied(Reason::BadToken));

    // One below the modulus decodes, and only the proof fails.
    let mut canonical = non_canonical;
    canonical[5] -= 1;
    assert_eq!(decide(&verifier, &canonical), denied(Reason::BadLoginProof));

    let mut trailing = honest.clone();
    trailing.push(0);
    let mut version = honest.clone();
    version[4] = 2;
    for bytes in [&honest[..TOKEN_LEN - 1], &trailing, &version, &[]] {
        assert_eq!(decide(&verifier, bytes), denied(Reason::BadToken));
    }
}

#[test]
fn replayed_nonce_denies_even_with_a_rerandomized_proof() {
    let verifier = verifier();
    let honest = prove(claims(1), AUDIENCE, PATH, &INPUT);
    assert!(matches!(
        decide(&verifier, &honest.encode()),
        Decision::Allow(_)
    ));
    assert_eq!(decide(&verifier, &honest.encode()), denied(Reason::Replay));

    let mut rng = StdRng::seed_from_u64(9);
    let mut rerandomized = honest.clone();
    rerandomized.request_proof = to_kernel(Groth16::<Bn254>::rerandomize_proof(
        &KEYS.request.vk,
        &to_ark(honest.request_proof),
        &mut rng,
    ));
    assert_ne!(rerandomized, honest);
    assert_eq!(
        decide(&verifier, &rerandomized.encode()),
        denied(Reason::Replay)
    );
}

#[test]
fn timestamp_must_be_in_the_window_and_after_the_start() {
    let verifier = verifier();
    let at = |nonce, ts| {
        token(Claims {
            ts,
            ..claims(nonce)
        })
    };
    assert_eq!(
        decide(&verifier, &at(1, NOW - WINDOW - 1)),
        denied(Reason::Timestamp)
    );
    assert_eq!(
        decide(&verifier, &at(2, NOW + WINDOW + 1)),
        denied(Reason::Timestamp)
    );
    assert!(matches!(
        decide(&verifier, &at(3, NOW + WINDOW)),
        Decision::Allow(_)
    ));
    // Within the window of `NOW`, but before the verifier started.
    assert_eq!(
        decide(&verifier, &at(4, START - 1)),
        denied(Reason::Timestamp)
    );
    assert!(matches!(
        decide(&verifier, &at(5, START)),
        Decision::Allow(_)
    ));
}

#[test]
fn revoked_tag_denies() {
    let verifier = verifier();
    let token = token(Claims {
        tag: Fr::from(5u64),
        ..claims(1)
    });
    assert_eq!(decide(&verifier, &token), denied(Reason::Revoked));
}

#[test]
fn missing_or_stale_feed_denies() {
    let token = token(claims(1));
    assert_eq!(decide(&load(AUDIENCE), &token), denied(Reason::StaleFeed));

    let verifier = verifier();
    let late = |nonce, now| {
        let token = self::token(Claims {
            ts: now,
            ..claims(nonce)
        });
        decide_at(&verifier, now, PATH, &INPUT, &token)
    };
    assert_eq!(late(2, NOW + STALE + 1), denied(Reason::StaleFeed));
    assert!(matches!(late(3, NOW + STALE), Decision::Allow(_)));
}

#[test]
fn epochs_must_be_accepted_and_within_the_session() {
    let verifier = verifier();
    let with = |nonce, login_epoch, root_epoch| {
        token(Claims {
            login_epoch,
            root_epoch,
            ..claims(nonce)
        })
    };
    // No root for epoch 11, then none for epoch 8.
    assert_eq!(
        decide(&verifier, &with(1, ROOT_EPOCH, ROOT_EPOCH + 1)),
        denied(Reason::RootEpoch)
    );
    assert_eq!(
        decide(&verifier, &with(2, LOGIN_EPOCH - 1, LOGIN_EPOCH)),
        denied(Reason::RootEpoch)
    );
    assert_eq!(
        decide(&verifier, &with(3, LOGIN_EPOCH - 1, ROOT_EPOCH)),
        denied(Reason::SessionExpired)
    );
    assert_eq!(
        decide(&verifier, &with(4, ROOT_EPOCH, LOGIN_EPOCH)),
        denied(Reason::SessionExpired)
    );
    assert!(matches!(
        decide(&verifier, &with(5, ROOT_EPOCH, ROOT_EPOCH)),
        Decision::Allow(_)
    ));
}

#[test]
fn verified_logins_are_cached_by_statement_and_failed_ones_never() {
    let verifier = verifier();
    let honest = |nonce| prove(claims(nonce), AUDIENCE, PATH, &INPUT);
    // A valid login proof for another statement.
    let wrong_login = prove(
        Claims {
            tag: Fr::from(89u64),
            ..claims(0)
        },
        AUDIENCE,
        PATH,
        &INPUT,
    )
    .login_proof;
    let with_wrong_login = |nonce| {
        Token {
            login_proof: wrong_login,
            ..honest(nonce)
        }
        .encode()
    };

    assert_eq!(
        decide(&verifier, &with_wrong_login(1)),
        denied(Reason::BadLoginProof)
    );
    assert_eq!(
        decide(&verifier, &with_wrong_login(2)),
        denied(Reason::BadLoginProof)
    );

    assert!(matches!(
        decide(&verifier, &honest(3).encode()),
        Decision::Allow(_)
    ));
    assert!(matches!(
        decide(&verifier, &with_wrong_login(4)),
        Decision::Allow(_)
    ));

    // A new revocation root for the login epoch is a new statement.
    let mut update = feed(2, NOW);
    update.roots[1].1 = Fr::from(1u64);
    verifier.apply_feed(NOW, &sign(update.encode())).unwrap();
    assert_eq!(
        decide(&verifier, &with_wrong_login(5)),
        denied(Reason::BadLoginProof)
    );
}

#[test]
fn concurrent_identical_requests_allow_once() {
    const THREADS: usize = 8;
    let verifier = verifier();
    let token = token(claims(1));
    let barrier = Barrier::new(THREADS);
    let allowed = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    decide(&verifier, &token)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|decision| {
                assert!(matches!(
                    decision,
                    Decision::Allow(_) | Decision::Deny(Reason::Replay)
                ));
                matches!(decision, Decision::Allow(_))
            })
            .count()
    });
    assert_eq!(allowed, 1);
}

#[test]
fn bundle_needs_the_root_signature() {
    let signed = sign(bundle().encode());
    let mut flipped = signed.clone();
    flipped[10] ^= 1;
    assert_eq!(
        Verifier::new(START, &root_key(), AUDIENCE, &flipped).err(),
        Some(BundleError::Signature)
    );
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert_eq!(
        Verifier::new(START, &other, AUDIENCE, &signed).err(),
        Some(BundleError::Signature)
    );
    assert_eq!(
        Verifier::new(START, &root_key()[1..], AUDIENCE, &signed).err(),
        Some(BundleError::RootKey)
    );
}

#[test]
fn bundle_keys_must_take_exactly_the_inputs_the_kernel_supplies() {
    let mut short_policy = bundle();
    short_policy.policies[1].key = vk(&KEYS.login);
    assert_eq!(
        Verifier::new(START, &root_key(), AUDIENCE, &sign(short_policy.encode())).err(),
        Some(BundleError::PolicyInputCount {
            policy: OTHER_PATH.to_owned(),
            expected: 10,
            actual: LOGIN_INPUTS,
        })
    );

    let mut long_login = bundle();
    long_login.login_key = vk(&KEYS.request);
    assert_eq!(
        Verifier::new(START, &root_key(), AUDIENCE, &sign(long_login.encode())).err(),
        Some(BundleError::LoginInputCount {
            expected: LOGIN_INPUTS,
            actual: 10,
        })
    );
}

#[test]
fn bundle_decoding_rejects_duplicates_versions_and_trailing_bytes() {
    let honest = bundle();
    assert_eq!(Bundle::decode(&honest.encode()).unwrap(), honest);
    let load = |body| Verifier::new(START, &root_key(), AUDIENCE, &sign(body)).err();

    let mut duplicate_path = bundle();
    duplicate_path.policies[1].path = PATH.to_owned();
    assert_eq!(
        load(duplicate_path.encode()),
        Some(BundleError::Decode(DecodeError::Duplicate))
    );

    let mut duplicate_field = bundle();
    duplicate_field.policies[0].layout[2].name = "request.amount".to_owned();
    assert_eq!(
        load(duplicate_field.encode()),
        Some(BundleError::Decode(DecodeError::Duplicate))
    );

    let mut version = honest.encode();
    version[4] = 2;
    assert_eq!(
        load(version),
        Some(BundleError::Decode(DecodeError::Version(2)))
    );

    let mut trailing = honest.encode();
    trailing.push(0);
    assert_eq!(
        load(trailing),
        Some(BundleError::Decode(DecodeError::Trailing))
    );

    // A signed feed update is not a bundle.
    assert_eq!(
        load(feed(1, NOW).encode()),
        Some(BundleError::Decode(DecodeError::Magic))
    );
}

#[test]
fn feed_updates_apply_in_sequence_order_only() {
    let verifier = verifier();
    verifier
        .apply_feed(NOW, &sign(feed(3, NOW).encode()))
        .unwrap();
    for sequence in [2, 3] {
        assert_eq!(
            verifier.apply_feed(NOW, &sign(feed(sequence, NOW).encode())),
            Err(FeedError::Sequence {
                applied: 3,
                update: sequence,
            })
        );
    }

    let mut unsigned = sign(feed(4, NOW).encode());
    unsigned[8] ^= 1;
    assert_eq!(
        verifier.apply_feed(NOW, &unsigned),
        Err(FeedError::Signature)
    );
    assert_eq!(
        verifier.apply_feed(NOW, &sign(feed(4, NOW - STALE - 1).encode())),
        Err(FeedError::Stale)
    );
    assert_eq!(
        verifier.apply_feed(NOW, &sign(feed(4, NOW + WINDOW + 1).encode())),
        Err(FeedError::Future)
    );

    let mut duplicate = feed(4, NOW);
    duplicate.revoked.push(Fr::from(5u64));
    assert_eq!(
        verifier.apply_feed(NOW, &sign(duplicate.encode())),
        Err(FeedError::Decode(DecodeError::Duplicate))
    );

    // A rejected update leaves the applied state in place.
    assert!(matches!(
        decide(&verifier, &token(claims(1))),
        Decision::Allow(_)
    ));
}

#[test]
fn feed_can_require_a_newer_bundle() {
    let verifier = verifier();
    let mut update = feed(2, NOW);
    update.min_bundle_version = 2;
    verifier.apply_feed(NOW, &sign(update.encode())).unwrap();
    assert_eq!(
        decide(&verifier, &token(claims(1))),
        denied(Reason::OldBundle)
    );
}

#[test]
fn groth16_verification_agrees_with_ark_groth16() {
    let key = &KEYS.login;
    let theirs = ark_groth16::prepare_verifying_key(&key.vk);
    let ours = PreparedVerifyingKey::new(vk(key));
    let inputs: Vec<Fr> = (1..=LOGIN_INPUTS as u64).map(Fr::from).collect();
    let mut rng = StdRng::seed_from_u64(5);
    let honest =
        Groth16::<Bn254>::create_random_proof_with_reduction(Inputs(inputs.clone()), key, &mut rng)
            .unwrap();

    // The kernel's types encode exactly as `ark-groth16`'s.
    fn compressed(value: &impl CanonicalSerialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        value.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
    assert_eq!(compressed(&to_kernel(honest.clone())), compressed(&honest));
    assert_eq!(compressed(&vk(key)), compressed(&key.vk));

    // Tampered points stay valid group elements, so only the pairing check can reject them.
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let tampered_proofs = [
        ark_groth16::Proof {
            a: (honest.a + g1).into_affine(),
            ..honest.clone()
        },
        ark_groth16::Proof {
            b: (honest.b + g2).into_affine(),
            ..honest.clone()
        },
        ark_groth16::Proof {
            c: (honest.c + g1).into_affine(),
            ..honest.clone()
        },
        ark_groth16::Proof {
            a: honest.c,
            b: honest.b,
            c: honest.a,
        },
    ];
    let tampered_inputs = (0..inputs.len()).map(|i| {
        let mut tampered = inputs.clone();
        tampered[i] += Fr::from(1u64);
        tampered
    });
    let cases: Vec<(ark_groth16::Proof<Bn254>, Vec<Fr>)> = [(honest.clone(), inputs.clone())]
        .into_iter()
        .chain(tampered_proofs.map(|proof| (proof, inputs.clone())))
        .chain(tampered_inputs.map(|inputs| (honest.clone(), inputs)))
        .collect();

    let verdicts: Vec<bool> = cases
        .into_iter()
        .map(|(proof, inputs)| {
            let expected = Groth16::<Bn254>::verify_proof(&theirs, &proof, &inputs).unwrap();
            assert_eq!(ours.verify(&to_kernel(proof), &inputs), expected);
            expected
        })
        .collect();
    // Only the honest proof with its own inputs verifies.
    assert!(verdicts[0]);
    assert!(verdicts[1..].iter().all(|&verdict| !verdict));
}
