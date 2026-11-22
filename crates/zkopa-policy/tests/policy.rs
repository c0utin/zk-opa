use zkopa_ir::{FieldType, Policy, Schema, Value};
use zkopa_policy::{Error, Kind, compile};

const MAX: u64 = u64::MAX;

fn schema() -> Schema {
    Schema::new(vec!["income".into(), "kyc_level".into(), "country".into()]).unwrap()
}

fn one(source: &str) -> Policy {
    let mut policies = compile(source, &schema()).unwrap();
    assert_eq!(policies.len(), 1);
    policies.pop().unwrap()
}

fn layout(policy: &Policy) -> Vec<(&str, FieldType)> {
    policy
        .inputs()
        .iter()
        .map(|f| (f.name.as_str(), f.ty))
        .collect()
}

const AFFORDABLE: &str = r#"
package transfers.create

import rego.v1

default allow := false

allow if {
    input.request.amount <= input.subject.income * 3 / 10
    input.subject.kyc_level >= 2
}
"#;

#[test]
fn affordability_at_its_boundaries() {
    let policy = one(AFFORDABLE);
    assert_eq!(policy.path(), "transfers/create/allow");
    assert_eq!(layout(&policy), [("request.amount", FieldType::U64)]);
    assert_eq!(policy.attributes(), 3);

    let decoded = Policy::decode(&policy.encode()).unwrap();
    for policy in [&policy, &decoded] {
        let allow = |amount, income, kyc| policy.eval(&[Value::U64(amount)], &[income, kyc, 0]);
        // 3/10 of 1000 is 300.
        assert!(allow(300, 1000, 2).unwrap());
        assert!(!allow(301, 1000, 2).unwrap());
        assert!(!allow(300, 1000, 1).unwrap());
        assert!(allow(300, 1000, MAX).unwrap());
        // 3/10 of 1003 is 300.9: Rego compares the fraction, so 300 passes and 301 does not.
        assert!(allow(300, 1003, 2).unwrap());
        assert!(!allow(301, 1003, 2).unwrap());
        // 3/10 of 3 is 0.9.
        assert!(allow(0, 3, 2).unwrap());
        assert!(!allow(1, 3, 2).unwrap());
        assert!(allow(0, 0, 2).unwrap());
        // 3/10 of 2^64 - 1 is 5534023222112865484.5, past what a u64 product can hold.
        assert!(allow(5_534_023_222_112_865_484, MAX, 2).unwrap());
        assert!(!allow(5_534_023_222_112_865_485, MAX, 2).unwrap());
        assert!(!allow(MAX, MAX, MAX).unwrap());
    }
}

#[test]
fn definitions_of_one_rule_are_joined_with_or() {
    let source = r#"
package bank

default allow := false

allow if input.subject.kyc_level == 9

allow if {
    input.request.to == "treasury"
    input.request.amount < 100
}

allow if input.resource.public

deny if input.request.amount > 1000

audit := true
"#;
    let policies = compile(source, &schema()).unwrap();
    let paths: Vec<_> = policies.iter().map(Policy::path).collect();
    assert_eq!(paths, ["bank/allow", "bank/deny", "bank/audit"]);

    let allow = &policies[0];
    assert_eq!(
        layout(allow),
        [
            ("request.to", FieldType::Bytes),
            ("request.amount", FieldType::U64),
            ("resource.public", FieldType::Bool),
        ]
    );
    let eval = |to: &str, amount, public, kyc| {
        let inputs = [
            Value::Bytes(to.as_bytes()),
            Value::U64(amount),
            Value::Bool(public),
        ];
        allow.eval(&inputs, &[0, kyc, 0]).unwrap()
    };
    assert!(!eval("bob", 0, false, 8));
    assert!(eval("bob", 0, false, 9));
    assert!(eval("treasury", 99, false, 0));
    assert!(!eval("treasury", 100, false, 0));
    assert!(!eval("Treasury", 99, false, 0));
    assert!(eval("bob", MAX, true, 0));

    let deny = &policies[1];
    assert_eq!(layout(deny), [("request.amount", FieldType::U64)]);
    assert!(!deny.eval(&[Value::U64(1000)], &[0, 0, 0]).unwrap());
    assert!(deny.eval(&[Value::U64(1001)], &[0, 0, 0]).unwrap());

    assert!(policies[2].inputs().is_empty());
    assert!(policies[2].eval(&[], &[0, 0, 0]).unwrap());
}

#[test]
fn a_rule_with_only_a_default_is_false() {
    let policy = one("package p\ndefault allow := false\n");
    assert!(!policy.eval(&[], &[0, 0, 0]).unwrap());
}

#[test]
fn membership_negation_subtraction_and_strings() {
    let source = r#"
package p

allow if {
    not input.subject.country in {7, 31, 850}
    input.request.amount - input.request.fee >= 10
    input.request.currency != "XYZ"
    input.request.to == input.resource.owner
}

owned if input.resource.owner == "alice"
"#;
    let policies = compile(source, &schema()).unwrap();
    let allow = &policies[0];
    // `request.to` is compared only with `resource.owner`, which the later rule types.
    assert_eq!(
        layout(allow),
        [
            ("request.amount", FieldType::U64),
            ("request.fee", FieldType::U64),
            ("request.currency", FieldType::Bytes),
            ("request.to", FieldType::Bytes),
            ("resource.owner", FieldType::Bytes),
        ]
    );
    let eval = |country, amount, fee, currency: &str, to: &str| {
        let inputs = [
            Value::U64(amount),
            Value::U64(fee),
            Value::Bytes(currency.as_bytes()),
            Value::Bytes(to.as_bytes()),
            Value::Bytes(b"alice"),
        ];
        allow.eval(&inputs, &[0, 0, country]).unwrap()
    };
    assert!(eval(1, 15, 5, "EUR", "alice"));
    assert!(!eval(1, 14, 5, "EUR", "alice"));
    assert!(eval(1, 10, 0, "EUR", "alice"));
    // In Rego 0 - (2^64 - 1) is negative, so the rule fails; nothing wraps.
    assert!(!eval(1, 0, MAX, "EUR", "alice"));
    assert!(eval(1, MAX, MAX - 10, "EUR", "alice"));
    assert!(!eval(1, MAX, MAX - 9, "EUR", "alice"));
    assert!(!eval(7, 15, 5, "EUR", "alice"));
    assert!(!eval(850, 15, 5, "EUR", "alice"));
    assert!(eval(849, 15, 5, "EUR", "alice"));
    assert!(!eval(1, 15, 5, "XYZ", "alice"));
    assert!(!eval(1, 15, 5, "EUR", "bob"));
}

#[test]
fn fractions_compare_exactly() {
    let source = r#"
package p

thirds if input.request.a / 3 == 2

mixed if input.request.a / 2 + input.request.b / 3 < 1

scaled if 10 < input.request.a * 5 / 2 - 2
"#;
    let policies = compile(source, &schema()).unwrap();
    let one = |p: &Policy, a| p.eval(&[Value::U64(a)], &[0, 0, 0]).unwrap();
    assert!(!one(&policies[0], 5));
    assert!(one(&policies[0], 6));
    assert!(!one(&policies[0], 7));
    // a/2 + b/3 < 1 is 3a + 2b < 6.
    let two = |a, b| {
        policies[1]
            .eval(&[Value::U64(a), Value::U64(b)], &[0, 0, 0])
            .unwrap()
    };
    assert!(two(1, 1));
    assert!(!two(0, 3));
    assert!(!two(2, 0));
    assert!(two(0, 2));
    assert!(!two(MAX, MAX));
    // 10 < 5a/2 - 2 is a > 4.8.
    assert!(!one(&policies[2], 4));
    assert!(one(&policies[2], 5));
}

#[test]
fn field_types_must_agree_across_rules() {
    let source = "package p\nallow if input.request.a == \"x\"\ndeny if input.request.a > 1\n";
    assert_eq!(
        compile(source, &schema()),
        Err(Error::At {
            line: 3,
            col: 22,
            kind: Kind::FieldType {
                name: "request.a".into(),
                first: FieldType::Bytes,
                second: FieldType::U64
            },
        })
    );
}

/// Compiles `body` as the only statement of `allow` on line 3 and returns why it failed.
fn reject(body: &str) -> Kind {
    let source = format!("package p\nallow if {{\n    {body}\n}}\n");
    match compile(&source, &schema()) {
        Err(Error::At { line: 3, kind, .. }) => kind,
        other => panic!("`{body}`: {other:?}"),
    }
}

fn unsupported(construct: &str) -> Kind {
    Kind::Unsupported(construct.into())
}

#[test]
fn constructs_outside_the_subset_are_rejected() {
    let cases = [
        (
            "some x in input.request.list",
            unsupported("iteration (`some`)"),
        ),
        (
            "input.request.list[_] == 1",
            unsupported("iteration or indexing by a non-string"),
        ),
        (
            "every x in input.request.list { x > 1 }",
            unsupported("`every`"),
        ),
        (
            "[x | x := input.request.list[_]]",
            unsupported("a comprehension"),
        ),
        (
            "input.request.a == 1 with input as {}",
            unsupported("`with`"),
        ),
        (
            "http.send({\"url\": \"x\"}).status == 200",
            unsupported("a call to `http.send`"),
        ),
        ("time.now_ns() < 5", unsupported("a call to `time.now_ns`")),
        (
            "startswith(input.request.to, \"a\")",
            unsupported("a call to `startswith`"),
        ),
        (
            "input.request.a < 1.5",
            unsupported("a floating-point number"),
        ),
        ("x := 1", unsupported("assignment or unification")),
        (
            "input.request.a = 1",
            unsupported("assignment or unification"),
        ),
        ("data.limits.max > 1", unsupported("a `data` document")),
        ("other > 1", unsupported("the variable or rule `other`")),
        (
            "input.context.ip == \"x\"",
            unsupported("`input.context.ip`"),
        ),
        ("input.request == 1", unsupported("`input.request`")),
        ("input.request.a % 2 == 0", unsupported("`%`")),
        ("input.request.a == null", unsupported("`null`")),
        (
            "input.request.a in [1, 2]",
            unsupported("`in` anything but a set literal"),
        ),
        (
            "input.subject.age > 18",
            Kind::UnknownAttribute("age".into()),
        ),
        (
            "input.request.name < \"m\"",
            Kind::Type {
                expected: "a number",
                found: "a string",
            },
        ),
        (
            "input.subject.income",
            Kind::Type {
                expected: "a boolean",
                found: "a number",
            },
        ),
        ("input.request.a / 2 in {1}", Kind::Division),
        (
            "input.request.a / 2",
            Kind::Type {
                expected: "a boolean",
                found: "a number",
            },
        ),
        ("input.request.a - 1 in {1}", Kind::Subtraction),
        ("input.request.a / input.request.b < 1", Kind::Divisor),
        ("input.request.a / 0 < 1", Kind::Divisor),
        ("input.request.a * input.request.b < 1", Kind::Product),
        ("input.request.a < 18446744073709551616", Kind::Constant),
        (
            "input.request.a == input.request.b",
            Kind::UnknownType("request.a".into()),
        ),
        (
            "input.request.a * 18446744073709551615 * 18446744073709551615 > 0",
            Kind::TooWide(192),
        ),
    ];
    for (body, kind) in cases {
        assert_eq!(reject(body), kind, "{body}");
    }
}

#[test]
fn rules_outside_the_subset_are_rejected() {
    let cases = [
        (
            "allow if true else := false if false",
            unsupported("`else`"),
        ),
        (
            "default allow := true",
            unsupported("a default other than `false`"),
        ),
        (
            "allow := 5 if true",
            unsupported("a rule value other than `true`"),
        ),
        (
            "allow contains 1 if true",
            unsupported("a partial set rule (`contains`)"),
        ),
        ("f(x) := true if x > 1", unsupported("a function")),
        ("import data.limits", unsupported("`import data.limits`")),
        (
            "default allow := false\ndefault allow := false",
            Kind::Default("allow".into()),
        ),
    ];
    for (rule, kind) in cases {
        let source = format!("package p\n{rule}\n");
        match compile(&source, &schema()) {
            Err(Error::At { kind: got, .. }) => assert_eq!(got, kind, "{rule}"),
            other => panic!("`{rule}`: {other:?}"),
        }
    }
    // Rego v1 needs `if`.
    assert!(matches!(
        compile("package p\nallow { true }\n", &schema()),
        Err(Error::Parse(_))
    ));
}

#[test]
fn multiplication_binds_tighter_than_addition() {
    let policy =
        one("package p\nallow if input.request.a + input.request.b * 3 <= input.request.c\n");
    let allow = |a, b, c| {
        policy
            .eval(&[Value::U64(a), Value::U64(b), Value::U64(c)], &[0, 0, 0])
            .unwrap()
    };
    // 1 + 2 * 3 is 7; read left to right it would be 9.
    assert!(allow(1, 2, 7));
    assert!(!allow(1, 2, 6));
    // Parentheses override it.
    let grouped =
        one("package p\nallow if (input.request.a + input.request.b) * 3 <= input.request.c\n");
    let inputs = [Value::U64(1), Value::U64(2), Value::U64(7)];
    assert!(!grouped.eval(&inputs, &[0, 0, 0]).unwrap());
}

#[test]
fn multi_line_bodies_comments_and_escapes() {
    let source = r#"
package p # the package

# A comment line, with "quotes" and { braces.
allow if {
    input.request.a +
        input.request.b < 10 # an expression may continue on the next line
    input.request.tag == "a#b\"c\\d\n\u00e9\ud83d\ude00"; input.subject.income > 5
}
"#;
    let policy = one(source);
    assert_eq!(
        layout(&policy),
        [
            ("request.a", FieldType::U64),
            ("request.b", FieldType::U64),
            ("request.tag", FieldType::Bytes),
        ]
    );
    let tag = "a#b\"c\\d\né😀";
    let allow = |a, b, tag: &str, income| {
        let inputs = [Value::U64(a), Value::U64(b), Value::Bytes(tag.as_bytes())];
        policy.eval(&inputs, &[income, 0, 0]).unwrap()
    };
    assert!(allow(4, 5, tag, 6));
    assert!(!allow(5, 5, tag, 6));
    assert!(!allow(4, 5, "a", 6));
    assert!(!allow(4, 5, tag, 5));
}

#[test]
fn syntax_errors_name_their_line_and_column() {
    let cases = [
        (
            "package p\nallow if {\n    input.request.a >\n}\n",
            "line 4, column 1: expected an expression, found `}`",
        ),
        (
            "package p\nallow if input.request.a > \"open\n",
            "line 2, column 28: unterminated string",
        ),
        (
            "package p\n\tallow if input.request.a > 1 @\n",
            "line 2, column 34: unexpected character",
        ),
    ];
    for (source, message) in cases {
        assert_eq!(
            compile(source, &schema()),
            Err(Error::Parse(message.into()))
        );
    } // Nesting is bounded, so hostile input is an error and not a stack overflow.
    let deep = format!(
        "package p\nallow if {}1{} > 0\n",
        "(".repeat(100_000),
        ")".repeat(100_000)
    );
    assert!(matches!(compile(&deep, &schema()), Err(Error::Parse(_))));
    let long = format!("package p\nallow if 0{} > 0\n", " + 1".repeat(100_000));
    assert!(matches!(compile(&long, &schema()), Err(Error::Parse(_))));
}
