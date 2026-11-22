//! A compact byte encoding: a version byte, then LEB128 integers, length-prefixed strings and
//! one tag byte per node. Decoding replays a [`Builder`], so it runs the same type check.

use crate::{Builder, Error, Field, FieldType, Node, NodeId, Policy};

const VERSION: u8 = 1;

/// LEB128 stores 7 value bits per byte, low group first.
const GROUP_BITS: u32 = 7;
/// Set on every byte but the last.
const MORE: u8 = 0x80;
const GROUP: u8 = !MORE;

/// The tag byte of each node in the encoding. Part of the wire format: never renumber.
#[repr(u8)]
#[derive(Clone, Copy)]
enum NodeKind {
    Int = 0,
    Bool = 1,
    Bytes = 2,
    Input = 3,
    Attribute = 4,
    Add = 5,
    MulConst = 6,
    Lt = 7,
    Le = 8,
    Eq = 9,
    And = 10,
    Or = 11,
    Not = 12,
    In = 13,
}

impl NodeKind {
    /// Every kind, at the index of its tag.
    const ALL: [NodeKind; 14] = [
        NodeKind::Int,
        NodeKind::Bool,
        NodeKind::Bytes,
        NodeKind::Input,
        NodeKind::Attribute,
        NodeKind::Add,
        NodeKind::MulConst,
        NodeKind::Lt,
        NodeKind::Le,
        NodeKind::Eq,
        NodeKind::And,
        NodeKind::Or,
        NodeKind::Not,
        NodeKind::In,
    ];
}

const _: () = {
    let mut i = 0;
    while i < NodeKind::ALL.len() {
        assert!(NodeKind::ALL[i] as usize == i);
        i += 1;
    }
};

impl TryFrom<u8> for NodeKind {
    type Error = Error;

    fn try_from(tag: u8) -> Result<Self, Error> {
        Self::ALL
            .get(usize::from(tag))
            .copied()
            .ok_or(Error::Tag(tag))
    }
}

/// Every field type, at the index of its wire tag (its discriminant).
const FIELD_TYPES: [FieldType; 3] = [FieldType::U64, FieldType::Bool, FieldType::Bytes];

const _: () = {
    let mut i = 0;
    while i < FIELD_TYPES.len() {
        assert!(FIELD_TYPES[i] as usize == i);
        i += 1;
    }
};

impl TryFrom<u8> for FieldType {
    type Error = Error;

    /// Decodes the wire tag of a field type, its discriminant.
    fn try_from(tag: u8) -> Result<Self, Error> {
        FIELD_TYPES
            .get(usize::from(tag))
            .copied()
            .ok_or(Error::Tag(tag))
    }
}

impl Policy {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        put_bytes(&mut out, self.path.as_bytes());
        put(&mut out, self.attributes.into());
        put_all(&mut out, &self.inputs, |out, field| {
            put_bytes(out, field.name.as_bytes());
            out.push(field.ty as u8);
        });
        put_all(&mut out, &self.sets, |out, set| {
            put_all(out, set, |out, &v| put(out, v));
        });
        put_all(&mut out, &self.bytes, |out, b| put_bytes(out, b));
        put_all(&mut out, &self.nodes, |out, &node| put_node(out, node));
        put(&mut out, self.root.0.into());
        out
    }

    /// Decodes a policy and type-checks it. Every policy has exactly one encoding: integers
    /// are minimal, sets are strictly increasing, and no node, set or constant repeats.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes };
        let version = r.byte()?;
        if version != VERSION {
            return Err(Error::Version(version));
        }
        let path = r.string()?;
        // Each table replays into the builder, which interns: an entry that lands on an
        // earlier index repeats one.
        let mut b = Builder::with_attributes(r.u32()?);
        for _ in 0..r.count()? {
            let name = r.string()?;
            let ty = FieldType::try_from(r.byte()?)?;
            b.field(Field { name, ty })?;
        }
        for i in 0..r.count()? {
            let n = r.count()?;
            let set = (0..n).map(|_| r.uint()).collect::<Result<Vec<_>, _>>()?;
            if !set.is_sorted_by(|x, y| x < y) || b.set(set)? as usize != i {
                return Err(Error::Noncanonical);
            }
        }
        for i in 0..r.count()? {
            let len = r.count()?;
            if b.bytes(r.take(len)?)? as usize != i {
                return Err(Error::Noncanonical);
            }
        }
        for i in 0..r.count()? {
            if b.push(r.node_body()?)?.index() != i {
                return Err(Error::Noncanonical);
            }
        }
        let root = r.node()?;
        if !r.bytes.is_empty() {
            return Err(Error::Trailing);
        }
        b.finish(path, root)
    }
}

/// Writes a count, then each item.
fn put_all<T>(out: &mut Vec<u8>, items: &[T], put_item: impl Fn(&mut Vec<u8>, &T)) {
    put_len(out, items.len());
    items.iter().for_each(|item| put_item(out, item));
}

/// Writes a node's tag, then its one or two operands.
fn put_node(out: &mut Vec<u8>, node: Node) {
    let (kind, a, b) = match node {
        Node::Int(c) => (NodeKind::Int, c, None),
        Node::Bool(v) => (NodeKind::Bool, v.into(), None),
        Node::Bytes(i) => (NodeKind::Bytes, i.into(), None),
        Node::Input(i) => (NodeKind::Input, i.into(), None),
        Node::Attribute(i) => (NodeKind::Attribute, i.into(), None),
        Node::Add(x, y) => (NodeKind::Add, x.0.into(), Some(y.0.into())),
        Node::MulConst(x, c) => (NodeKind::MulConst, x.0.into(), Some(c)),
        Node::Lt(x, y) => (NodeKind::Lt, x.0.into(), Some(y.0.into())),
        Node::Le(x, y) => (NodeKind::Le, x.0.into(), Some(y.0.into())),
        Node::Eq(x, y) => (NodeKind::Eq, x.0.into(), Some(y.0.into())),
        Node::And(x, y) => (NodeKind::And, x.0.into(), Some(y.0.into())),
        Node::Or(x, y) => (NodeKind::Or, x.0.into(), Some(y.0.into())),
        Node::Not(x) => (NodeKind::Not, x.0.into(), None),
        Node::In(x, s) => (NodeKind::In, x.0.into(), Some(s.into())),
    };
    out.push(kind as u8);
    put(out, a);
    if let Some(b) = b {
        put(out, b);
    }
}

fn put(out: &mut Vec<u8>, mut v: u64) {
    while v > u64::from(GROUP) {
        out.push(v as u8 | MORE);
        v >>= GROUP_BITS;
    }
    out.push(v as u8);
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    put(out, len as u64);
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let (&b, rest) = self.bytes.split_first().ok_or(Error::Truncated)?;
        self.bytes = rest;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.bytes.split_at_checked(len).ok_or(Error::Truncated)?;
        self.bytes = rest;
        Ok(head)
    }

    /// LEB128, minimal form only, so every policy has exactly one encoding.
    fn uint(&mut self) -> Result<u64, Error> {
        let mut value = 0;
        for shift in (0..u64::BITS).step_by(GROUP_BITS as usize) {
            let b = self.byte()?;
            let low = u64::from(b & GROUP);
            // The last group holds only the top bit; anything above it does not fit.
            if (low << shift) >> shift != low {
                return Err(Error::Integer);
            }
            value |= low << shift;
            if b & MORE == 0 {
                // A zero last group after the first pads the integer.
                return if b == 0 && shift > 0 {
                    Err(Error::Integer)
                } else {
                    Ok(value)
                };
            }
        }
        Err(Error::Integer)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        u32::try_from(self.uint()?).map_err(|_| Error::Integer)
    }

    fn node(&mut self) -> Result<NodeId, Error> {
        Ok(NodeId(self.u32()?))
    }

    /// A node's tag and operands, as [`put_node`] writes them.
    fn node_body(&mut self) -> Result<Node, Error> {
        Ok(match NodeKind::try_from(self.byte()?)? {
            NodeKind::Int => Node::Int(self.uint()?),
            NodeKind::Bool => Node::Bool(match self.byte()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Integer),
            }),
            NodeKind::Bytes => Node::Bytes(self.u32()?),
            NodeKind::Input => Node::Input(self.u32()?),
            NodeKind::Attribute => Node::Attribute(self.u32()?),
            NodeKind::Add => Node::Add(self.node()?, self.node()?),
            NodeKind::MulConst => Node::MulConst(self.node()?, self.uint()?),
            NodeKind::Lt => Node::Lt(self.node()?, self.node()?),
            NodeKind::Le => Node::Le(self.node()?, self.node()?),
            NodeKind::Eq => Node::Eq(self.node()?, self.node()?),
            NodeKind::And => Node::And(self.node()?, self.node()?),
            NodeKind::Or => Node::Or(self.node()?, self.node()?),
            NodeKind::Not => Node::Not(self.node()?),
            NodeKind::In => Node::In(self.node()?, self.u32()?),
        })
    }

    /// A length or element count. Every element takes at least one byte, so a count larger
    /// than what is left is malformed, which also bounds what decoding allocates.
    fn count(&mut self) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n > self.bytes.len() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, Error> {
        let len = self.count()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Utf8)
    }
}
