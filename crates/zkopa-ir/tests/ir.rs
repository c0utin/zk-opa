use zkopa_ir::{Builder, Error, FieldType, MAX_BITS, Node, NodeId, Policy, Schema, Type, Value};

const MAX: u64 = u64::MAX;

fn schema(n: usize) -> Schema {
    Schema::new((0..n).map(|i| format!("a{i}")).collect()).unwrap()
}

/// `amount * 10 <= income * 3`, with `amount` public and `income` attribute 0 of 1.
fn affordability() -> Policy {
    let mut b = Builder::new(&schema(1));
    let amount = b.input("request.amount", FieldType::U64).unwrap();
    let income = b.push(Node::Attribute(0)).unwrap();
    let lhs = b.push(Node::MulConst(amount, 10)).unwrap();
    let rhs = b.push(Node::MulConst(income, 3)).unwrap();
    let root = b.push(Node::Le(lhs, rhs)).unwrap();
    b.finish("t/allow".into(), root).unwrap()
}

#[test]
fn eval_is_exact_beyond_64_bits() {
    let policy = affordability();
    // floor(3 * (2^64 - 1) / 10) = 5534023222112865484; a wrapping u64 evaluator gets both wrong.
    let at = |amount| policy.eval(&[Value::U64(amount)], &[MAX]).unwrap();
    assert!(at(5_534_023_222_112_865_484));
    assert!(!at(5_534_023_222_112_865_485));
    assert!(!at(MAX));
    assert!(policy.eval(&[Value::U64(0)], &[0]).unwrap());
    assert!(!policy.eval(&[Value::U64(1)], &[3]).unwrap());
    assert!(policy.eval(&[Value::U64(3)], &[10]).unwrap());
}

#[test]
fn sum_above_u64_max_compares_correctly() {
    let mut b = Builder::new(&schema(0));
    let x = b.input("request.x", FieldType::U64).unwrap();
    let y = b.input("request.y", FieldType::U64).unwrap();
    let sum = b.push(Node::Add(x, y)).unwrap();
    let max = b.push(Node::Int(MAX)).unwrap();
    let root = b.push(Node::Lt(max, sum)).unwrap();
    let policy = b.finish("t/allow".into(), root).unwrap();
    assert_eq!(policy.types()[sum.index()], Type::Int { bits: 65 });
    assert!(policy.eval(&[Value::U64(MAX), Value::U64(1)], &[]).unwrap());
    assert!(!policy.eval(&[Value::U64(MAX), Value::U64(0)], &[]).unwrap());
}

#[test]
fn inputs_follow_first_use_and_keep_one_type() {
    let mut b = Builder::new(&schema(0));
    let to = b.input("request.to", FieldType::Bytes).unwrap();
    let flag = b.input("resource.locked", FieldType::Bool).unwrap();
    assert_eq!(b.input("request.to", FieldType::Bytes).unwrap(), to);
    assert_eq!(
        b.input("request.to", FieldType::U64),
        Err(Error::FieldType("request.to".into()))
    );
    let policy = b.finish("t/allow".into(), flag).unwrap();
    let names: Vec<_> = policy
        .inputs()
        .iter()
        .map(|f| (f.name.as_str(), f.ty))
        .collect();
    assert_eq!(
        names,
        [
            ("request.to", FieldType::Bytes),
            ("resource.locked", FieldType::Bool)
        ]
    );
    assert!(
        policy
            .eval(&[Value::Bytes(b""), Value::Bool(true)], &[])
            .unwrap()
    );
    assert!(
        !policy
            .eval(&[Value::Bytes(b""), Value::Bool(false)], &[])
            .unwrap()
    );
}

#[test]
fn identical_nodes_are_shared() {
    let mut b = Builder::new(&schema(1));
    let x = b.push(Node::Attribute(0)).unwrap();
    assert_eq!(b.push(Node::Attribute(0)).unwrap(), x);
    let s = b.set(vec![3, 1, 2, 3]).unwrap();
    assert_eq!(b.set(vec![1, 2, 3]).unwrap(), s);
    let root = b.push(Node::In(x, s)).unwrap();
    let policy = b.finish("t/allow".into(), root).unwrap();
    assert_eq!(policy.nodes().len(), 2);
    assert_eq!(policy.set(s), &[1, 2, 3]);
}

#[test]
fn membership() {
    let mut b = Builder::new(&schema(1));
    let x = b.push(Node::Attribute(0)).unwrap();
    let s = b.set(vec![0, 7, MAX]).unwrap();
    let root = b.push(Node::In(x, s)).unwrap();
    let policy = b.finish("t/allow".into(), root).unwrap();
    for (v, member) in [
        (0, true),
        (1, false),
        (6, false),
        (7, true),
        (MAX - 1, false),
        (MAX, true),
    ] {
        assert_eq!(policy.eval(&[], &[v]).unwrap(), member, "{v}");
    }
}

#[test]
fn bytes_equality() {
    let mut b = Builder::new(&schema(0));
    let to = b.input("request.to", FieldType::Bytes).unwrap();
    let bob = b.bytes(b"bob").unwrap();
    let bob = b.push(Node::Bytes(bob)).unwrap();
    let root = b.push(Node::Eq(to, bob)).unwrap();
    let policy = b.finish("t/allow".into(), root).unwrap();
    assert!(policy.eval(&[Value::Bytes(b"bob")], &[]).unwrap());
    assert!(!policy.eval(&[Value::Bytes(b"bOb")], &[]).unwrap());
    assert!(!policy.eval(&[Value::Bytes(b"bob\0")], &[]).unwrap());
}

#[test]
fn widths_are_bounded() {
    let mut b = Builder::new(&schema(1));
    let x = b.push(Node::Attribute(0)).unwrap();
    let wide = b.push(Node::MulConst(x, MAX)).unwrap();
    assert_eq!(wide, NodeId(1));
    let root = b.push(Node::Eq(wide, x)).unwrap();
    let one = b.push(Node::Int(1)).unwrap();
    assert_eq!(
        b.push(Node::Add(wide, one)),
        Err(Error::TooWide {
            node: 4,
            bits: MAX_BITS + 1
        })
    );
    let policy = b.finish("t/allow".into(), root).unwrap();
    assert_eq!(policy.types()[wide.index()], Type::Int { bits: MAX_BITS });
    assert!(policy.eval(&[], &[0]).unwrap());
    assert!(!policy.eval(&[], &[MAX]).unwrap());
}

#[test]
fn malformed_nodes_are_rejected() {
    let mut b = Builder::new(&schema(1));
    let flag = b.input("request.flag", FieldType::Bool).unwrap();
    let attr = b.push(Node::Attribute(0)).unwrap();
    assert_eq!(
        b.push(Node::Not(NodeId(2))),
        Err(Error::Operand { node: 2 })
    );
    assert_eq!(b.push(Node::Input(1)), Err(Error::OutOfRange { node: 2 }));
    assert_eq!(
        b.push(Node::Attribute(1)),
        Err(Error::OutOfRange { node: 2 })
    );
    assert_eq!(b.push(Node::Bytes(0)), Err(Error::OutOfRange { node: 2 }));
    assert_eq!(
        b.push(Node::In(attr, 0)),
        Err(Error::OutOfRange { node: 2 })
    );
    assert_eq!(b.push(Node::Lt(flag, attr)), Err(Error::Type { node: 2 }));
    assert_eq!(b.push(Node::Not(attr)), Err(Error::Type { node: 2 }));
    assert_eq!(b.push(Node::Eq(flag, attr)), Err(Error::Type { node: 2 }));
    assert_eq!(b.push(Node::And(flag, attr)), Err(Error::Type { node: 2 }));
    assert_eq!(
        b.push(Node::MulConst(flag, 2)),
        Err(Error::Type { node: 2 })
    );
    let finish = |root| {
        let mut b = Builder::new(&schema(1));
        b.push(Node::Attribute(0)).unwrap();
        b.finish("t/allow".into(), root).unwrap_err()
    };
    assert_eq!(finish(NodeId(0)), Error::Root);
    assert_eq!(finish(NodeId(1)), Error::Root);
    let mut b = Builder::new(&schema(0));
    let t = b.push(Node::Bool(true)).unwrap();
    assert_eq!(b.finish(String::new(), t), Err(Error::EmptyPath));
}

#[test]
fn eval_checks_the_layout() {
    let policy = affordability();
    assert_eq!(
        policy.eval(&[], &[1]),
        Err(Error::InputCount {
            expected: 1,
            got: 0
        })
    );
    assert_eq!(
        policy.eval(&[Value::Bool(true)], &[1]),
        Err(Error::InputType("request.amount".into()))
    );
    assert_eq!(
        policy.eval(&[Value::U64(1)], &[1, 2]),
        Err(Error::AttributeCount {
            expected: 1,
            got: 2
        })
    );
}

fn everything() -> Policy {
    let mut b = Builder::new(&schema(2));
    let push = |b: &mut Builder, n| b.push(n).unwrap();
    let amount = b.input("request.amount", FieldType::U64).unwrap();
    let to = b.input("request.to", FieldType::Bytes).unwrap();
    let flag = b.input("resource.locked", FieldType::Bool).unwrap();
    let level = push(&mut b, Node::Attribute(1));
    let big = push(&mut b, Node::Int(300));
    let lhs = push(&mut b, Node::MulConst(amount, 1 << 40));
    let rhs = push(&mut b, Node::Add(level, big));
    let le = push(&mut b, Node::Le(lhs, rhs));
    let lt = push(&mut b, Node::Lt(level, big));
    let bob = b.bytes("bøb".as_bytes()).unwrap();
    let bob = push(&mut b, Node::Bytes(bob));
    let eq = push(&mut b, Node::Eq(to, bob));
    let s = b.set(vec![2, 3, 1 << 50]).unwrap();
    let member = push(&mut b, Node::In(level, s));
    let not = push(&mut b, Node::Not(flag));
    let t = push(&mut b, Node::Bool(true));
    let and = push(&mut b, Node::And(le, eq));
    let or = push(&mut b, Node::Or(lt, member));
    let and = push(&mut b, Node::And(and, or));
    let and = push(&mut b, Node::And(and, not));
    let root = push(&mut b, Node::And(and, t));
    b.finish("a/b/allow".into(), root).unwrap()
}

#[test]
fn encoding_round_trips() {
    let policy = everything();
    let bytes = policy.encode();
    let decoded = Policy::decode(&bytes).unwrap();
    assert_eq!(decoded, policy);
    assert_eq!(decoded.encode(), bytes);
    let inputs = [
        Value::U64(0),
        Value::Bytes("bøb".as_bytes()),
        Value::Bool(false),
    ];
    assert!(decoded.eval(&inputs, &[0, 2]).unwrap());
    assert!(!decoded.eval(&inputs, &[0, 300]).unwrap());
}

#[test]
fn encoding_rejects_damage() {
    let policy = everything();
    let bytes = policy.encode();
    for len in 0..bytes.len() {
        assert!(
            Policy::decode(&bytes[..len]).is_err(),
            "prefix of {len} bytes decoded"
        );
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Policy::decode(&longer), Err(Error::Trailing));
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1 << bit;
            assert_ne!(
                Policy::decode(&flipped).as_ref(),
                Ok(&policy),
                "byte {i} bit {bit}"
            );
        }
    }
    let mut version = bytes;
    version[0] = 2;
    assert_eq!(Policy::decode(&version), Err(Error::Version(2)));
}

#[test]
fn encodings_are_canonical() {
    let bytes = affordability().encode();
    // The version byte, the 7-byte path, then the attribute count, 1.
    assert_eq!(&bytes[..10], b"\x01\x07t/allow\x01");
    let mut padded = bytes[..9].to_vec();
    padded.extend_from_slice(&[0x81, 0x00]);
    padded.extend_from_slice(&bytes[10..]);
    assert_eq!(Policy::decode(&padded), Err(Error::Integer));

    // A node repeated in the arena would make a second encoding of the same policy.
    let mut b = Builder::new(&schema(0));
    let t = b.push(Node::Bool(true)).unwrap();
    let bytes = b.finish("p".into(), t).unwrap().encode();
    // version, path, attributes, inputs, sets, constants, 1 node: tag 1 value 1, root 0.
    assert_eq!(bytes, b"\x01\x01p\x00\x00\x00\x00\x01\x01\x01\x00");
    let repeated = b"\x01\x01p\x00\x00\x00\x00\x02\x01\x01\x01\x01\x00";
    assert_eq!(Policy::decode(repeated), Err(Error::Noncanonical));
    let unsorted = b"\x01\x01p\x00\x00\x01\x02\x02\x01\x00\x01\x01\x01\x00";
    assert_eq!(Policy::decode(unsorted), Err(Error::Noncanonical));
}

#[test]
fn schema_names_are_unique_and_ordered() {
    let schema = Schema::new(vec!["income".into(), "kyc_level".into()]).unwrap();
    assert_eq!(schema.index("kyc_level"), Some(1));
    assert_eq!(schema.index("income"), Some(0));
    assert_eq!(schema.index("age"), None);
    assert_eq!(
        Schema::new(vec!["a".into(), "b".into(), "a".into()]),
        Err(Error::DuplicateName("a".into()))
    );
}
