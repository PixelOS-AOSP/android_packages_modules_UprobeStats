//! Abstraction for dealing with statsd atoms.
use anyhow::Result;

/// Trait for something that can write atoms. Implemented by statsd libraries, abstracted for tests.
pub trait AtomWriter<A> {
    /// Write the atom to its destination.
    fn write(&mut self, atom: A) -> Result<()>;
}

/// An unstructured atom is one that doesn't have a compile-time defined structure, and is
/// described by an atom id and a sequence of values.
#[derive(Debug, PartialEq, Clone)]
pub struct UnstructuredAtom {
    /// The atom id.
    pub atom_id: u32,
    /// Data instide the atom, *in the order it should be written*.
    pub fields: Vec<Field>,
}

/// A field in an atom.
#[derive(Debug, PartialEq, Clone)]
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
#[derive(Debug, PartialEq, Clone)]
pub enum Value {
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    Int32Vec(Vec<i32>),
    Int64Vec(Vec<i64>),
}

/// An annotation on a field.
#[derive(Debug, PartialEq, Clone)]
pub enum FieldAnnotation {
    /// Whether the field is a uid.
    IsUid(bool),
}

/// Mirrors the same atoms in uprobestats_extesion_atoms.proto
/// Note: these are the atoms that are supported by statsd codegen.
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone)]
pub enum CodegenAtom {
    SetComponentEnabledSettingReported {
        package_name: String,
        class_name: String,
        new_state: i32,
        calling_package_name: String,
        is_launcher_activity: bool,
    },
    DisabledLauncherActivityUidsReported {
        calling_uid: i32,
        disabled_activity_uid: i32,
    },
    BindServiceLockedWithBalFlagsReported {
        intent_package: String,
        flags: i64,
        calling_package: String,
        intent_action: String,
        intent_component_name_package: String,
        intent_component_name_class: String,
    },
    BindServiceLockedWithBalFlagsUidsReported {
        binder_uid: i32,
        bindee_uid: i32,
    },
    AndroidGraphicsBitmapAllocated {
        uid: i32,
        width: i32,
        height: i32,
    },
    AndroidGraphicsBitmapScaled {
        uid: i32,
        width: i32,
        height: i32,
        scaled_width: i32,
        scaled_height: i32,
        pixel_storage_type: i32,
        activity_name: String,
    },
    AndroidGraphicsBitmapAllocationSnapshot {
        uid: i32,
        width: i32,
        height: i32,
        pixel_storage_type: i32,
        snapshot_id: i64,
        snapshot_type: i32,
        activity_name: String,
    },
}

#[cfg(test)]
pub mod test {
    use super::*;
    pub(crate) struct TestAtomWriter<A> {
        pub(crate) written: Vec<A>,
    }

    impl<A> Default for TestAtomWriter<A> {
        fn default() -> Self {
            Self { written: vec![] }
        }
    }

    impl<A> AtomWriter<A> for TestAtomWriter<A> {
        fn write(&mut self, atom: A) -> Result<()> {
            self.written.push(atom);
            Ok(())
        }
    }
}
