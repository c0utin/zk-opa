//! The reference evaluator: what a sound circuit for the policy must compute.

use crate::{Error, FieldType, Node, NodeId, Policy};

/// A public input value, in layout order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    U64(u64),
    Bool(bool),
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy)]
enum Slot<'a> {
    // The type check bounds every integer node by `MAX_BITS` = 128, so `u128` is exact.
    Int(u128),
    Bool(bool),
    Bytes(&'a [u8]),
}

impl Policy {
    /// Evaluates the policy in the clear with exact integer arithmetic.
    ///
    /// `inputs` follow [`Policy::inputs`] and `attributes` follow the schema.
    pub fn eval(&self, inputs: &[Value<'_>], attributes: &[u64]) -> Result<bool, Error> {
        if inputs.len() != self.inputs.len() {
            return Err(Error::InputCount {
                expected: self.inputs.len(),
                got: inputs.len(),
            });
        }
        if attributes.len() != self.attributes as usize {
            return Err(Error::AttributeCount {
                expected: self.attributes as usize,
                got: attributes.len(),
            });
        }
        let misfit = self.inputs.iter().zip(inputs).find(|&(field, value)| {
            !matches!(
                (field.ty, value),
                (FieldType::U64, Value::U64(_))
                    | (FieldType::Bool, Value::Bool(_))
                    | (FieldType::Bytes, Value::Bytes(_))
            )
        });
        if let Some((field, _)) = misfit {
            // The error owns the name; this is the cold path.
            return Err(Error::InputType(field.name.clone()));
        }

        // Each slot reads the slots of its operands, which precede it, so the arena fills in
        // order rather than through an iterator that cannot see what it already produced.
        let mut slots: Vec<Slot<'_>> = Vec::with_capacity(self.nodes.len());
        for &node in &self.nodes {
            let int = |id: NodeId| match slots[id.index()] {
                Slot::Int(v) => v,
                _ => unreachable!("the type check makes this operand an integer"),
            };
            let boolean = |id: NodeId| match slots[id.index()] {
                Slot::Bool(v) => v,
                _ => unreachable!("the type check makes this operand a boolean"),
            };
            let slot = match node {
                Node::Int(c) => Slot::Int(c.into()),
                Node::Bool(b) => Slot::Bool(b),
                Node::Bytes(b) => Slot::Bytes(self.bytes(b)),
                Node::Input(k) => match inputs[k as usize] {
                    Value::U64(v) => Slot::Int(v.into()),
                    Value::Bool(v) => Slot::Bool(v),
                    Value::Bytes(v) => Slot::Bytes(v),
                },
                Node::Attribute(k) => Slot::Int(attributes[k as usize].into()),
                Node::Add(a, b) => Slot::Int(int(a) + int(b)),
                Node::MulConst(a, c) => Slot::Int(int(a) * u128::from(c)),
                Node::Lt(a, b) => Slot::Bool(int(a) < int(b)),
                Node::Le(a, b) => Slot::Bool(int(a) <= int(b)),
                Node::Eq(a, b) => Slot::Bool(match (slots[a.index()], slots[b.index()]) {
                    (Slot::Int(x), Slot::Int(y)) => x == y,
                    (Slot::Bool(x), Slot::Bool(y)) => x == y,
                    (Slot::Bytes(x), Slot::Bytes(y)) => x == y,
                    _ => unreachable!("the type check gives both operands one type"),
                }),
                Node::And(a, b) => Slot::Bool(boolean(a) && boolean(b)),
                Node::Or(a, b) => Slot::Bool(boolean(a) || boolean(b)),
                Node::Not(a) => Slot::Bool(!boolean(a)),
                Node::In(a, s) => Slot::Bool(
                    u64::try_from(int(a)).is_ok_and(|v| self.set(s).binary_search(&v).is_ok()),
                ),
            };
            slots.push(slot);
        }
        match slots[self.root.index()] {
            Slot::Bool(v) => Ok(v),
            _ => unreachable!("the type check makes the root a boolean"),
        }
    }
}
