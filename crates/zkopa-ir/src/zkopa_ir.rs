//! The circuit IR, as plain data.
//!
//! A [`Policy`] is one decision rule compiled to a flat arena of [`Node`]s in topological order:
//! every operand has a smaller [`NodeId`] than the node that uses it, so a prover lowers a policy
//! in one forward pass with one variable per node. The type check gives every integer node an
//! upper bound in bits, at most [`MAX_BITS`], which is what makes range-checked comparisons
//! sound in a field of about 254 bits.

mod codec;
mod eval;

pub use eval::Value;

use std::collections::HashMap;
use std::fmt;

/// The widest integer a node may hold, in bits.
///
/// 128 keeps the reference evaluator exact in `u128` and stays far below the BN254 scalar
/// field (p > 2^253), so `b - a` for two in-range values never wraps in a comparison gadget.
pub const MAX_BITS: u32 = 128;

/// The position of a node in [`Policy::nodes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

impl NodeId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// One operation. Operands are earlier nodes; the other `u32`s index the policy's tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Node {
    /// An integer constant.
    Int(u64),
    /// A boolean constant.
    Bool(bool),
    /// A bytes constant, by index into the policy's bytes table ([`Policy::bytes`]).
    /// Bytes support only [`Node::Eq`].
    Bytes(u32),
    /// A public input, by index into [`Policy::inputs`]. Its type is the field's type.
    Input(u32),
    /// A private subject attribute, by index into the credential [`Schema`]. Below 2^64.
    Attribute(u32),
    /// Integer sum.
    Add(NodeId, NodeId),
    /// Integer product with a constant.
    MulConst(NodeId, u64),
    /// Integer `a < b`.
    Lt(NodeId, NodeId),
    /// Integer `a <= b`.
    Le(NodeId, NodeId),
    /// Equality of two values of the same type: integers, booleans or bytes.
    Eq(NodeId, NodeId),
    And(NodeId, NodeId),
    Or(NodeId, NodeId),
    Not(NodeId),
    /// Integer membership in a constant set, by index into the policy's sets ([`Policy::set`]).
    In(NodeId, u32),
}

/// The type of a node's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Bool,
    Bytes,
    /// A non-negative integer below `2^bits`.
    Int {
        bits: u32,
    },
}

impl Type {
    /// A `u64` input or attribute.
    const U64: Type = Type::Int { bits: u64::BITS };
}

/// The type of a public input field, as the kernel encodes it.
///
/// The discriminant is the field's tag in [`Policy::encode`]: never renumber.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldType {
    U64 = 0,
    Bool = 1,
    Bytes = 2,
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FieldType::U64 => "u64",
            FieldType::Bool => "bool",
            FieldType::Bytes => "bytes",
        })
    }
}

/// A named public input field, such as `request.amount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
}

/// The ordered `u64` attribute names a credential commits to, shared by every policy of one
/// deployment. A policy refers to an attribute by its position here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    names: Vec<String>,
}

impl Schema {
    pub fn new(mut names: Vec<String>) -> Result<Self, Error> {
        if u32::try_from(names.len()).is_err() {
            return Err(Error::TooLarge);
        }
        match (0..names.len()).find(|&i| names[..i].contains(&names[i])) {
            Some(i) => Err(Error::DuplicateName(names.swap_remove(i))),
            None => Ok(Self { names }),
        }
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn index(&self, name: &str) -> Option<u32> {
        // `new` guarantees every index fits in a `u32`.
        self.names.iter().position(|n| n == name).map(|i| i as u32)
    }
}

/// A compiled decision rule. Only [`Builder`] makes one, and [`Policy::decode`] replays a
/// `Builder`, so every `Policy` passed the type check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    path: String,
    inputs: Vec<Field>,
    attributes: u32,
    nodes: Vec<Node>,
    types: Vec<Type>,
    sets: Vec<Box<[u64]>>,
    bytes: Vec<Box<[u8]>>,
    root: NodeId,
}

impl Policy {
    /// The decision path, such as `transfers/create/allow`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The public input layout, in encoding order.
    pub fn inputs(&self) -> &[Field] {
        &self.inputs
    }

    /// The number of attributes in the schema the policy was compiled against.
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// The arena, operands before users.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The type of every node, parallel to [`Policy::nodes`].
    pub fn types(&self) -> &[Type] {
        &self.types
    }

    /// The boolean node whose value is the decision.
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// A constant set, strictly increasing.
    pub fn set(&self, index: u32) -> &[u64] {
        &self.sets[index as usize]
    }

    /// A bytes constant, as written in the policy. The prover hashes it the way the kernel
    /// hashes a `bytes` input.
    pub fn bytes(&self, index: u32) -> &[u8] {
        &self.bytes[index as usize]
    }
}

/// Builds one policy, type-checking each node as it is pushed. Identical nodes are shared, so
/// a value used twice is constrained once.
#[derive(Debug)]
pub struct Builder {
    inputs: Vec<Field>,
    attributes: u32,
    nodes: Vec<Node>,
    types: Vec<Type>,
    sets: Vec<Box<[u64]>>,
    bytes: Vec<Box<[u8]>>,
    interned: HashMap<Node, NodeId>,
}

impl Builder {
    /// Starts a policy over the attributes of `schema`.
    pub fn new(schema: &Schema) -> Self {
        // `Schema::new` guarantees the count fits in a `u32`.
        Self::with_attributes(schema.names.len() as u32)
    }

    fn with_attributes(attributes: u32) -> Self {
        Self {
            inputs: Vec::new(),
            attributes,
            nodes: Vec::new(),
            types: Vec::new(),
            sets: Vec::new(),
            bytes: Vec::new(),
            interned: HashMap::new(),
        }
    }

    /// Returns the node of the public input `name`, adding the field to the end of the layout
    /// on first use. A second use with another type is an error.
    pub fn input(&mut self, name: &str, ty: FieldType) -> Result<NodeId, Error> {
        let index = match self.inputs.iter().position(|f| f.name == name) {
            Some(i) if self.inputs[i].ty == ty => i as u32,
            Some(_) => return Err(Error::FieldType(name.into())),
            None => self.field(Field {
                name: name.into(),
                ty,
            })?,
        };
        self.push(Node::Input(index))
    }

    fn field(&mut self, field: Field) -> Result<u32, Error> {
        if self.inputs.iter().any(|f| f.name == field.name) {
            return Err(Error::DuplicateName(field.name));
        }
        let index = u32::try_from(self.inputs.len()).map_err(|_| Error::TooLarge)?;
        self.inputs.push(field);
        Ok(index)
    }

    /// Adds a constant set and returns its index. Order and duplicates do not matter.
    pub fn set(&mut self, mut values: Vec<u64>) -> Result<u32, Error> {
        values.sort_unstable();
        values.dedup();
        intern(&mut self.sets, &values)
    }

    /// Adds a bytes constant and returns its index.
    pub fn bytes(&mut self, value: &[u8]) -> Result<u32, Error> {
        intern(&mut self.bytes, value)
    }

    /// Type-checks `node` and returns its id, or the id of the identical node already pushed.
    pub fn push(&mut self, node: Node) -> Result<NodeId, Error> {
        if let Some(&id) = self.interned.get(&node) {
            return Ok(id);
        }
        let id = NodeId(u32::try_from(self.nodes.len()).map_err(|_| Error::TooLarge)?);
        let ty = self.type_of(node, id.0)?;
        self.nodes.push(node);
        self.types.push(ty);
        self.interned.insert(node, id);
        Ok(id)
    }

    /// Ends the policy that decides `root` under the decision path `path`.
    pub fn finish(self, path: String, root: NodeId) -> Result<Policy, Error> {
        if path.is_empty() {
            return Err(Error::EmptyPath);
        }
        if self.types.get(root.index()) != Some(&Type::Bool) {
            return Err(Error::Root);
        }
        Ok(Policy {
            path,
            inputs: self.inputs,
            attributes: self.attributes,
            nodes: self.nodes,
            types: self.types,
            sets: self.sets,
            bytes: self.bytes,
            root,
        })
    }

    /// The type of `node` if pushed as node `at`, rejecting anything a prover could not lower
    /// soundly.
    fn type_of(&self, node: Node, at: u32) -> Result<Type, Error> {
        let ty = |id: NodeId| {
            self.types
                .get(id.index())
                .copied()
                .ok_or(Error::Operand { node: at })
        };
        let int = |id: NodeId| match ty(id)? {
            Type::Int { bits } => Ok(bits),
            _ => Err(Error::Type { node: at }),
        };
        let boolean = |id: NodeId| match ty(id)? {
            Type::Bool => Ok(Type::Bool),
            _ => Err(Error::Type { node: at }),
        };
        let out_of_range = Error::OutOfRange { node: at };
        let t = match node {
            Node::Int(c) => Type::Int { bits: bit_len(c) },
            Node::Bool(_) => Type::Bool,
            Node::Bytes(b) if (b as usize) < self.bytes.len() => Type::Bytes,
            Node::Input(k) => match self.inputs.get(k as usize).ok_or(out_of_range)?.ty {
                FieldType::U64 => Type::U64,
                FieldType::Bool => Type::Bool,
                FieldType::Bytes => Type::Bytes,
            },
            Node::Attribute(k) if k < self.attributes => Type::U64,
            // One carry bit above the wider operand.
            Node::Add(a, b) => Type::Int {
                bits: int(a)?.max(int(b)?) + 1,
            },
            Node::MulConst(a, c) => Type::Int {
                bits: int(a)? + bit_len(c),
            },
            Node::Lt(a, b) | Node::Le(a, b) => {
                int(a)?;
                int(b)?;
                Type::Bool
            }
            Node::Eq(a, b) => match (ty(a)?, ty(b)?) {
                (Type::Int { .. }, Type::Int { .. })
                | (Type::Bool, Type::Bool)
                | (Type::Bytes, Type::Bytes) => Type::Bool,
                _ => return Err(Error::Type { node: at }),
            },
            Node::And(a, b) | Node::Or(a, b) => {
                boolean(a)?;
                boolean(b)?
            }
            Node::Not(a) => boolean(a)?,
            Node::In(a, s) if (s as usize) < self.sets.len() => {
                int(a)?;
                Type::Bool
            }
            Node::Bytes(_) | Node::Attribute(_) | Node::In(..) => return Err(out_of_range),
        };
        match t {
            Type::Int { bits } if bits > MAX_BITS => Err(Error::TooWide { node: at, bits }),
            _ => Ok(t),
        }
    }
}

/// The index of `value` in `table`, appending it if absent.
fn intern<T: Copy + PartialEq>(table: &mut Vec<Box<[T]>>, value: &[T]) -> Result<u32, Error> {
    let index = table.iter().position(|v| **v == *value).unwrap_or_else(|| {
        table.push(value.into());
        table.len() - 1
    });
    u32::try_from(index).map_err(|_| Error::TooLarge)
}

fn bit_len(value: u64) -> u32 {
    u64::BITS - value.leading_zeros()
}

/// Why a policy was rejected, could not be decoded, or could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("duplicate name `{0}`")]
    DuplicateName(String),
    #[error("input `{0}` is used with two types")]
    FieldType(String),
    #[error("empty decision path")]
    EmptyPath,
    #[error("too many nodes or names")]
    TooLarge,
    #[error("node {node}: an operand does not precede it")]
    Operand { node: u32 },
    #[error("node {node}: an index is out of range")]
    OutOfRange { node: u32 },
    #[error("node {node}: operand types do not fit the operation")]
    Type { node: u32 },
    #[error("node {node}: the value may need {bits} bits, more than {MAX_BITS}")]
    TooWide { node: u32, bits: u32 },
    #[error("the root is not a boolean node")]
    Root,

    #[error("unsupported encoding version {0}")]
    Version(u8),
    #[error("the encoding ends early")]
    Truncated,
    #[error("the encoding has trailing bytes")]
    Trailing,
    #[error("malformed integer in the encoding")]
    Integer,
    #[error("unknown tag {0} in the encoding")]
    Tag(u8),
    #[error("a name in the encoding is not UTF-8")]
    Utf8,
    #[error("the encoding is not canonical")]
    Noncanonical,

    #[error("expected {expected} inputs, got {got}")]
    InputCount { expected: usize, got: usize },
    #[error("input `{0}` has the wrong type")]
    InputType(String),
    #[error("expected {expected} attributes, got {got}")]
    AttributeCount { expected: usize, got: usize },
}
