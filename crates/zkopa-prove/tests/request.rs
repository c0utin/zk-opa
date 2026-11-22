//! Request circuits lowered from compiled Rego must be satisfied exactly when the reference
//! evaluator allows. Checked by constraint satisfaction, without proving.

use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
use zkopa_ir::{FieldType, Policy, Schema};
use zkopa_kernel::{Claims, Field, Type, Value};
use zkopa_prove::{Fr, RequestCircuit, commitment, is_satisfied};

const MAX: u64 = u64::MAX;

fn schema() -> Schema {
    Schema::new(vec!["income".into(), "kyc_level".into(), "country".into()]).unwrap()
}

fn compile(source: &str) -> Vec<Policy> {
    zkopa_policy::compile(source, &schema()).unwrap()
}

fn claims(attributes: &[u64], blinding: Fr) -> Claims {
    Claims {
        commitment: commitment(attributes, blinding),
        tag: Fr::from(5u64),
        login_epoch: 9,
        ts: 1_700_000_000_000,
        nonce: Fr::from(77u64),
        root_epoch: 10,
    }
}

fn layout(policy: &Policy) -> Vec<Field> {
    policy
        .inputs()
        .iter()
        .map(|f| Field {
            name: f.name.clone(),
            ty: match f.ty {
                FieldType::U64 => Type::U64,
                FieldType::Bool => Type::Bool,
                FieldType::Bytes => Type::Bytes,
            },
        })
        .collect()
}

/// Whether the circuit is satisfied for these values, opening `C` honestly.
fn circuit(policy: &Policy, input: &[Value<'_>], attributes: &[u64]) -> bool {
    let blinding = Fr::from(1234u64);
    let layout = layout(policy);
    let named: Vec<_> = layout
        .iter()
        .zip(input)
        .map(|(f, &v)| (f.name.as_str(), v))
        .collect();
    let public = zkopa_kernel::request_inputs(
        &claims(attributes, blinding),
        "transfers",
        policy.path(),
        &layout,
        &named,
    )
    .unwrap();
    is_satisfied(RequestCircuit::new(policy, &public, attributes, blinding).unwrap()).unwrap()
}

fn eval(policy: &Policy, input: &[Value<'_>], attributes: &[u64]) -> bool {
    let input: Vec<_> = input
        .iter()
        .map(|&v| match v {
            Value::U64(v) => zkopa_ir::Value::U64(v),
            Value::Bool(v) => zkopa_ir::Value::Bool(v),
            Value::Bytes(v) => zkopa_ir::Value::Bytes(v),
        })
        .collect();
    policy.eval(&input, attributes).unwrap()
}

/// Checks the circuit against the evaluator on every case and that both outcomes occur.
fn agree<'a>(policy: &Policy, cases: impl IntoIterator<Item = (Vec<Value<'a>>, [u64; 3])>) {
    let mut seen = [0; 2];
    for (input, attributes) in cases {
        let expected = eval(policy, &input, &attributes);
        assert_eq!(
            circuit(policy, &input, &attributes),
            expected,
            "{}: input {input:?}, attributes {attributes:?}",
            policy.path()
        );
        seen[usize::from(expected)] += 1;
    }
    assert!(seen[0] > 0 && seen[1] > 0, "{}: {seen:?}", policy.path());
}

/// Values that sit on the boundaries of 64-bit arithmetic and of the small constants below.
fn interesting(rng: &mut StdRng) -> u64 {
    const EDGES: [u64; 14] = [
        0,
        1,
        2,
        3,
        9,
        10,
        11,
        99,
        100,
        300,
        301,
        MAX / 10 * 3 + 1,
        MAX - 1,
        MAX,
    ];
    match rng.gen_range(0..4) {
        0 => rng.r#gen(),
        1 => rng.gen_range(0..2000),
        _ => EDGES[rng.gen_range(0..EDGES.len())],
    }
}

#[test]
fn affordability_matches_the_evaluator_at_64_bit_boundaries() {
    let policies = compile(
        r#"
package transfers.create

default allow := false

allow if {
    input.request.amount <= input.subject.income * 3 / 10
    input.subject.kyc_level >= 2
}
"#,
    );
    let policy = &policies[0];
    let top = MAX / 10 * 3 + 1; // floor(3 * MAX / 10)
    let fixed = [
        (300, 1000, 2),
        (301, 1000, 2),
        (300, 1000, 1),
        (300, 1003, 2),
        (301, 1003, 2),
        (0, 0, 2),
        (1, 3, 2),
        (top, MAX, 2),
        (top + 1, MAX, 2),
        (MAX, MAX, MAX),
        (0, 0, 0),
        (0, 0, MAX),
    ];
    let mut rng = StdRng::seed_from_u64(1);
    let random = (0..80).map(|_| {
        (
            interesting(&mut rng),
            interesting(&mut rng),
            interesting(&mut rng),
        )
    });
    let cases = fixed
        .into_iter()
        .chain(random)
        .map(|(amount, income, kyc)| (vec![Value::U64(amount)], [income, kyc, 0]));
    agree(policy, cases);
}

#[test]
fn or_not_membership_bytes_and_bools_match_the_evaluator() {
    let policies = compile(
        r#"
package bank

allow if input.subject.kyc_level == 9

allow if {
    input.request.to == "treasury"
    input.request.amount < 100
}

allow if {
    input.resource.public
    not input.request.urgent
}

allow if {
    not input.subject.country in {7, 31, 850}
    input.request.amount - input.request.fee >= 10
    input.request.urgent == input.resource.public
}

screen if input.subject.country in {0, 7, 18446744073709551615}

deny if input.request.amount / 2 + input.request.fee / 3 < 1
"#,
    );
    assert_eq!(policies.len(), 3);
    let names = ["bob", "treasury", "Treasury", ""];
    let mut rng = StdRng::seed_from_u64(2);
    for policy in &policies {
        let cases: Vec<_> = (0..100)
            .map(|_| {
                let input = policy
                    .inputs()
                    .iter()
                    .map(|f| match f.ty {
                        FieldType::U64 => Value::U64(interesting(&mut rng)),
                        FieldType::Bool => Value::Bool(rng.r#gen()),
                        FieldType::Bytes => {
                            Value::Bytes(names[rng.gen_range(0..names.len())].as_bytes())
                        }
                    })
                    .collect();
                let country = [0, 1, 7, 8, 31, 849, 850, 851, MAX - 1, MAX];
                let attributes = [
                    interesting(&mut rng),
                    [0, 8, 9, 10, MAX][rng.gen_range(0..5)],
                    country[rng.gen_range(0..country.len())],
                ];
                (input, attributes)
            })
            .collect();
        agree(policy, cases);
    }
}

#[test]
fn a_rule_that_is_always_false_is_never_satisfied() {
    let policies = compile("package p\ndefault allow := false\n");
    assert!(!eval(&policies[0], &[], &[1, 2, 3]));
    assert!(!circuit(&policies[0], &[], &[1, 2, 3]));
}

#[test]
fn attributes_must_open_the_commitment() {
    let policies = compile("package p\nallow if input.subject.income >= 10\n");
    let policy = &policies[0];
    let blinding = Fr::from(1234u64);
    let honest = [10, 0, 0];
    let public = zkopa_kernel::request_inputs(
        &claims(&honest, blinding),
        "transfers",
        policy.path(),
        &[],
        &[],
    )
    .unwrap();
    let satisfied = |attributes: &[u64], blinding| {
        is_satisfied(RequestCircuit::new(policy, &public, attributes, blinding).unwrap()).unwrap()
    };
    assert!(satisfied(&honest, blinding));
    assert!(!satisfied(&[11, 0, 0], blinding));
    assert!(!satisfied(&[10, 0, 1], blinding));
    assert!(!satisfied(&honest, blinding + Fr::from(1u64)));
}
