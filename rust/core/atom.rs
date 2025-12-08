//! Abstraction for dealing with statsd atoms.
use anyhow::Result;

/// Trait for something that can write atoms. Implemented by statsd libraries, abstracted for tests.
pub trait AtomWriter<A> {
    /// Write the atom to its destination.
    fn write(&mut self, atom: A) -> Result<()>;
}

/// An unstructured atom is one that doesn't have a compile-time defined structure, and is
/// described by an atom id and a sequence of values.
pub struct UnstructuredAtom {
    /// The atom id.
    pub atom_id: u32,
    /// Data instide the atom, *in the order it should be written*.
    pub fields: Vec<Field>,
}

/// A field in an atom.
pub struct Field {
    /// The actual data.
    pub value: Value,
    /// Any annotations on the field.
    pub annotations: Vec<FieldAnnotation>,
}

impl Field {
    /// Helper to create a field with no annotations.
    pub fn new(value: Value) -> Self {
        Self { value, annotations: vec![] }
    }

    /// Helper to create a field with a single annotation.
    pub fn new_with_annotation(value: Value, annotation: FieldAnnotation) -> Self {
        Self { value, annotations: vec![annotation] }
    }
}

/// A value in a field.
#[allow(missing_docs)]
pub enum Value {
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    Int32Vec(Vec<i32>),
    Int64Vec(Vec<i64>),
}

/// An annotation on a field.
pub enum FieldAnnotation {
    /// Whether the field is a uid.
    IsUid(bool),
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[allow(unused)]
    pub(crate) struct TestAtomWriter<A> {
        pub(crate) written: Vec<A>,
    }

    impl<A> AtomWriter<A> for TestAtomWriter<A> {
        fn write(&mut self, atom: A) -> Result<()> {
            self.written.push(atom);
            Ok(())
        }
    }
}
