//! Deals with bitmap allocation events from BPF.
use crate::{
    atom::{AtomWriter, CodegenAtom},
    bpf_handler::Handler,
    config_resolver::ResolvedTask,
    string::bytes_as_str,
};
use anyhow::Result;
use log::trace;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::vec::Vec;
use uprobestats_bpf_structs::{
    BitmapEvent, K_BITMAP_EVENT_TYPE_ACTIVITY_START, K_BITMAP_EVENT_TYPE_ALLOCATION,
    K_BITMAP_EVENT_TYPE_BITMAP_SCALED, K_BITMAP_EVENT_TYPE_DEALLOCATION,
};

/// V0 of the bitmap allocation handler. Only reports bitmap allocations.
#[derive(Default)]
pub struct BitmapAllocationHandlerV0<C> {
    writer: C,
}

// SAFETY: `BitmapEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<C: AtomWriter<CodegenAtom>> Handler for BitmapAllocationHandlerV0<C> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    type T = BitmapEvent;
    fn on_item(&mut self, task: &ResolvedTask, data: &BitmapEvent) -> Result<()> {
        trace!("BitmapEvent from v0 handler: {data:?}");
        let atom = CodegenAtom::AndroidGraphicsBitmapAllocated {
            uid: task.resolved_process.uid,
            width: data.width.try_into()?,
            height: data.height.try_into()?,
        };
        self.writer.write(atom)?;
        Ok(())
    }
}

/// Metadata for a bitmap.
#[derive(Debug, Clone)]
pub struct BitmapMetadata {
    /// UID of the process that allocated the bitmap.
    pub uid: i32,
    /// Width of the bitmap in pixels.
    pub width: i32,
    /// Height of the bitmap in pixels.
    pub height: i32,
    /// Pixel storage type of the bitmap.
    pub pixel_storage_type: i32,
    /// Name of the activity that was active when the bitmap was allocated.
    pub activity_name: String,
}

/// V1 of the bitmap allocation handler. Reports bitmap allocations, scaling,
/// and snapshots.
#[derive(Default)]
pub struct BitmapAllocationHandlerV1<C> {
    codegen_writer: C,
    bitmaps: HashMap<u64, BitmapMetadata>,
    max_total_bitmap_size: i64,
    current_total_bitmap_size: i64,
    bitmap_snapshot_at_max_size: Vec<BitmapMetadata>,
    activity_name: String,
}

// SAFETY: `BitmapEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl<C: AtomWriter<CodegenAtom>> Handler for BitmapAllocationHandlerV1<C> {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    type T = BitmapEvent;
    fn on_item(&mut self, task: &ResolvedTask, data: &BitmapEvent) -> Result<()> {
        trace!("BitmapEvent from v1 handler: {data:?}");
        match data.type_ {
            K_BITMAP_EVENT_TYPE_ALLOCATION => {
                let metadata = BitmapMetadata {
                    uid: task.resolved_process.uid,
                    width: data.width.try_into()?,
                    height: data.height.try_into()?,
                    pixel_storage_type: data.pixel_storage_type.try_into()?,
                    activity_name: self.activity_name.clone(),
                };
                self.codegen_writer.write(CodegenAtom::AndroidGraphicsBitmapAllocated {
                    uid: metadata.uid,
                    width: metadata.width,
                    height: metadata.height,
                })?;
                self.bitmaps.insert(data.native_ptr as u64, metadata);
                let bitmap_size: i64 = data.bitmap_size.try_into()?;
                self.current_total_bitmap_size += bitmap_size;
                if self.current_total_bitmap_size > self.max_total_bitmap_size {
                    self.max_total_bitmap_size = self.current_total_bitmap_size;
                    self.bitmap_snapshot_at_max_size = self.bitmaps.values().cloned().collect();
                }
                Ok(())
            }
            K_BITMAP_EVENT_TYPE_DEALLOCATION => {
                self.bitmaps.remove(&(data.native_ptr as u64));
                let bitmap_size: i64 = data.bitmap_size.try_into()?;
                self.current_total_bitmap_size -= bitmap_size;
                Ok(())
            }
            K_BITMAP_EVENT_TYPE_ACTIVITY_START => {
                self.activity_name = bytes_as_str(&data.activity_name)?.to_string();
                Ok(())
            }
            K_BITMAP_EVENT_TYPE_BITMAP_SCALED => {
                let atom = CodegenAtom::AndroidGraphicsBitmapScaled {
                    uid: task.resolved_process.uid,
                    width: data.width.try_into()?,
                    height: data.height.try_into()?,
                    scaled_width: data.scaled_width.try_into()?,
                    scaled_height: data.scaled_height.try_into()?,
                    pixel_storage_type: data.pixel_storage_type.try_into()?,
                    activity_name: self.activity_name.clone(),
                };
                self.codegen_writer.write(atom)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn on_finished(&mut self) -> Result<()> {
        trace!("BitmapAllocationHandler finished");
        let mut rng = thread_rng();
        {
            let snapshot_id: i64 = rng.gen();
            for metadata in &self.bitmap_snapshot_at_max_size {
                let atom = CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
                    uid: metadata.uid,
                    width: metadata.width,
                    height: metadata.height,
                    pixel_storage_type: metadata.pixel_storage_type,
                    snapshot_id,
                    snapshot_type: 1, // SnapshotTypeMaxAllocationSize
                    activity_name: metadata.activity_name.clone(),
                };
                self.codegen_writer.write(atom)?;
            }
        }
        {
            let snapshot_id: i64 = rng.gen();
            for metadata in self.bitmaps.values() {
                let atom = CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
                    uid: metadata.uid,
                    width: metadata.width,
                    height: metadata.height,
                    pixel_storage_type: metadata.pixel_storage_type,
                    snapshot_id,
                    snapshot_type: 2, // SnapshotTypeRandomSample
                    activity_name: metadata.activity_name.clone(),
                };
                self.codegen_writer.write(atom)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        atom::test::TestAtomWriter,
        config_resolver::{ResolvedProcess, ResolvedTask},
    };
    use std::collections::HashSet;
    use std::time::Duration;

    fn create_task(uid: i32) -> ResolvedTask {
        ResolvedTask {
            id: 1,
            duration: Duration::from_secs(0),
            resolved_process: ResolvedProcess { pid: 0, uid, name: "".to_string() },
            resolved_probes: vec![],
            bpf_map_paths: HashSet::new(),
            statsd_logging_config: None,
        }
    }

    #[test]
    fn bitmap_allocation_handler_v0_writes_atom() -> Result<()> {
        let writer = TestAtomWriter::<CodegenAtom>::default();
        let mut handler = BitmapAllocationHandlerV0 { writer };
        let task = create_task(1001);
        let event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_ALLOCATION,
            native_ptr: std::ptr::null_mut(),
            bitmap_size: 0,
            width: 100,
            height: 200,
            scaled_width: 0,
            scaled_height: 0,
            pixel_storage_type: 0,
            activity_name: [0; 128],
        };

        handler.on_item(&task, &event)?;

        assert_eq!(handler.writer.written.len(), 1);
        let atom = &handler.writer.written[0];
        assert_eq!(
            *atom,
            CodegenAtom::AndroidGraphicsBitmapAllocated { uid: 1001, width: 100, height: 200 }
        );
        Ok(())
    }

    #[test]
    fn bitmap_allocation_handler_v1_allocation_writes_atom() -> Result<()> {
        let codegen_writer = TestAtomWriter::<CodegenAtom>::default();
        let mut handler = BitmapAllocationHandlerV1 { codegen_writer, ..Default::default() };
        let task = create_task(1002);
        let event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_ALLOCATION,
            native_ptr: std::ptr::null_mut(),
            bitmap_size: 0,
            width: 150,
            height: 250,
            scaled_width: 0,
            scaled_height: 0,
            pixel_storage_type: 0,
            activity_name: [0; 128],
        };

        handler.on_item(&task, &event)?;

        assert_eq!(handler.codegen_writer.written.len(), 1);
        let atom = &handler.codegen_writer.written[0];
        assert_eq!(
            *atom,
            CodegenAtom::AndroidGraphicsBitmapAllocated { uid: 1002, width: 150, height: 250 }
        );
        Ok(())
    }

    #[test]
    fn bitmap_allocation_handler_v1_scaled_writes_atom() -> Result<()> {
        let codegen_writer = TestAtomWriter::<CodegenAtom>::default();
        let mut handler = BitmapAllocationHandlerV1 { codegen_writer, ..Default::default() };
        let task = create_task(1003);
        let event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_BITMAP_SCALED,
            native_ptr: std::ptr::null_mut(),
            bitmap_size: 0,
            width: 100,
            height: 100,
            scaled_width: 200,
            scaled_height: 200,
            pixel_storage_type: 1, // Heap
            activity_name: [0; 128],
        };

        handler.on_item(&task, &event)?;

        assert_eq!(handler.codegen_writer.written.len(), 1);
        let atom = &handler.codegen_writer.written[0];
        assert_eq!(
            *atom,
            CodegenAtom::AndroidGraphicsBitmapScaled {
                uid: 1003,
                width: 100,
                height: 100,
                scaled_width: 200,
                scaled_height: 200,
                pixel_storage_type: 1,
                activity_name: "".to_string(),
            }
        );
        Ok(())
    }

    #[test]
    fn bitmap_allocation_handler_v1_on_finished_writes_snapshot_atoms() -> Result<()> {
        let codegen_writer = TestAtomWriter::<CodegenAtom>::default();
        let mut handler = BitmapAllocationHandlerV1 { codegen_writer, ..Default::default() };
        let task = create_task(1004);

        // Allocate a bitmap
        let alloc_event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_ALLOCATION,
            native_ptr: 1234 as *mut _,
            width: 50,
            height: 50,
            bitmap_size: 10000,
            scaled_width: 0,
            scaled_height: 0,
            pixel_storage_type: 0,
            activity_name: [0; 128],
        };
        handler.on_item(&task, &alloc_event)?;
        handler.codegen_writer.written.clear(); // Clear allocation atom

        // Finish and check snapshots
        handler.on_finished()?;

        assert_eq!(handler.codegen_writer.written.len(), 2);

        // Max size snapshot
        let atom_max = &handler.codegen_writer.written[0];
        if let CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
            uid,
            width,
            height,
            snapshot_type,
            ..
        } = atom_max
        {
            assert_eq!(*uid, 1004);
            assert_eq!(*width, 50);
            assert_eq!(*height, 50);
            assert_eq!(*snapshot_type, 1); // SnapshotTypeMaxAllocationSize
        } else {
            panic!("Wrong atom written: {:?}", atom_max);
        }

        // Random sample snapshot
        let atom_rand = &handler.codegen_writer.written[1];
        if let CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
            uid,
            width,
            height,
            snapshot_type,
            ..
        } = atom_rand
        {
            assert_eq!(*uid, 1004);
            assert_eq!(*width, 50);
            assert_eq!(*height, 50);
            assert_eq!(*snapshot_type, 2); // SnapshotTypeRandomSample
        } else {
            panic!("Wrong atom written: {:?}", atom_rand);
        }

        Ok(())
    }

    #[test]
    fn bitmap_allocation_handler_v1_deallocation_removes_from_snapshot() -> Result<()> {
        let codegen_writer = TestAtomWriter::<CodegenAtom>::default();
        let mut handler = BitmapAllocationHandlerV1 { codegen_writer, ..Default::default() };
        let task = create_task(1005);

        // Allocate a bitmap
        let alloc_event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_ALLOCATION,
            native_ptr: 1234 as *mut _,
            width: 50,
            height: 50,
            bitmap_size: 10000,
            scaled_width: 0,
            scaled_height: 0,
            pixel_storage_type: 0,
            activity_name: [0; 128],
        };
        handler.on_item(&task, &alloc_event)?;

        // Deallocate the bitmap
        let dealloc_event = BitmapEvent {
            type_: K_BITMAP_EVENT_TYPE_DEALLOCATION,
            native_ptr: 1234 as *mut _,
            bitmap_size: 10000,
            width: 0,
            height: 0,
            scaled_width: 0,
            scaled_height: 0,
            pixel_storage_type: 0,
            activity_name: [0; 128],
        };
        handler.on_item(&task, &dealloc_event)?;

        handler.codegen_writer.written.clear(); // Clear allocation atom

        // Finish and check snapshots
        handler.on_finished()?;

        // The max allocation snapshot should still contain the bitmap that was allocated.
        // The random sample snapshot should be empty because the bitmap was deallocated.
        assert_eq!(handler.codegen_writer.written.len(), 1);

        // Max size snapshot
        let atom_max = &handler.codegen_writer.written[0];
        if let CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
            uid,
            width,
            height,
            snapshot_type,
            ..
        } = atom_max
        {
            assert_eq!(*uid, 1005);
            assert_eq!(*width, 50);
            assert_eq!(*height, 50);
            assert_eq!(*snapshot_type, 1); // SnapshotTypeMaxAllocationSize
        } else {
            panic!("Wrong atom written: {:?}", atom_max);
        }

        Ok(())
    }
}
