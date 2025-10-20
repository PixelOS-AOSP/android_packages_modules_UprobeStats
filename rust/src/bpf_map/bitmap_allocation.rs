use super::{bytes_as_str, Handler};
use crate::config_resolver::ResolvedTask;
use anyhow::Result;
use log::debug;
use rand::thread_rng;
use rand::Rng;
use statslog_uprobestats::{
    android_graphics_bitmap_allocated, android_graphics_bitmap_allocation_snapshot,
    android_graphics_bitmap_scaled,
};
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;
use uprobestats_bpf_bindgen::{
    BitmapEvent, K_BITMAP_EVENT_TYPE_ACTIVITY_START, K_BITMAP_EVENT_TYPE_ALLOCATION,
    K_BITMAP_EVENT_TYPE_BITMAP_SCALED, K_BITMAP_EVENT_TYPE_DEALLOCATION,
};

#[derive(Default)]
pub struct BitmapAllocationHandlerV0 {}

// SAFETY: `BitmapEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BitmapAllocationHandlerV0 {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    type T = BitmapEvent;
    fn on_item(&mut self, task: &ResolvedTask, data: &BitmapEvent) -> Result<()> {
        debug!("BitmapEvent from v0 handler: {data:?}");
        android_graphics_bitmap_allocated::stats_write(
            task.uid,
            data.width.try_into()?,
            data.height.try_into()?,
        )?;
        Ok(())
    }
    fn on_finished(&mut self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BitmapMetadata {
    pub uid: i32,
    pub width: i32,
    pub height: i32,
    pub pixel_storage_type: i32,
    pub activity_name: String,
}

#[derive(Default)]
pub struct BitmapAllocationHandlerV1 {
    bitmaps: HashMap<u64, BitmapMetadata>,
    max_total_bitmap_size: i64,
    current_total_bitmap_size: i64,
    bitmap_snapshot_at_max_size: Vec<BitmapMetadata>,
    activity_name: String,
}

// SAFETY: `BitmapEvent` is a struct defined in the given `MAP_PATH`, and is guaranteed to match the
// layout of the corresponding C struct.
unsafe impl Handler for BitmapAllocationHandlerV1 {
    const MAP_PATH: &'static str = "/sys/fs/bpf/uprobestats/map_BitmapAllocation_output";
    type T = BitmapEvent;
    fn on_item(&mut self, task: &ResolvedTask, data: &BitmapEvent) -> Result<()> {
        debug!("BitmapEvent from v1 handler: {data:?}");
        match data.type_ {
            K_BITMAP_EVENT_TYPE_ALLOCATION => {
                // Allocation
                let metadata = BitmapMetadata {
                    uid: task.uid,
                    width: data.width.try_into()?,
                    height: data.height.try_into()?,
                    pixel_storage_type: data.pixel_storage_type.try_into()?,
                    activity_name: self.activity_name.clone(),
                };
                android_graphics_bitmap_allocated::stats_write(
                    metadata.uid,
                    metadata.width,
                    metadata.height,
                )?;
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
                // Deallocation
                self.bitmaps.remove(&(data.native_ptr as u64));
                let bitmap_size: i64 = data.bitmap_size.try_into()?;
                self.current_total_bitmap_size -= bitmap_size;
                Ok(())
            }
            K_BITMAP_EVENT_TYPE_ACTIVITY_START => {
                // Activity start
                self.activity_name = bytes_as_str(&data.activity_name)?.to_string();
                Ok(())
            }
            K_BITMAP_EVENT_TYPE_BITMAP_SCALED => {
                // Bitmap scaled
                let metadata = BitmapMetadata {
                    uid: task.uid,
                    width: data.width.try_into()?,
                    height: data.height.try_into()?,
                    pixel_storage_type: data.pixel_storage_type.try_into()?,
                    activity_name: self.activity_name.clone(),
                };
                debug!("BitmapAllocationHandler.on_item: bitmap scaled {metadata:?}");
                android_graphics_bitmap_scaled::stats_write(
                    task.uid,
                    data.width.try_into()?,
                    data.height.try_into()?,
                    data.scaled_width.try_into()?,
                    data.scaled_height.try_into()?,
                    convert_to_bitmap_scaled_pixel_storage_type_enum(
                        data.pixel_storage_type.try_into()?,
                    ),
                    &self.activity_name.clone(),
                )?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn on_finished(&mut self) -> Result<()> {
        debug!("BitmapAllocationHandler finished");
        let mut rng = thread_rng();
        {
            let snapshot_id = rng.gen();
            for metadata in &self.bitmap_snapshot_at_max_size {
                debug!(
                    "BitmapAllocationHandler.on_finished: bitmap_snapshot_at_max_size {metadata:?}"
                );
                android_graphics_bitmap_allocation_snapshot::stats_write(
                    metadata.uid,
                    metadata.width,
                    metadata.height,
                    convert_to_pixel_storage_type_enum(metadata.pixel_storage_type),
                    snapshot_id,
                    android_graphics_bitmap_allocation_snapshot::SnapshotType::SnapshotTypeMaxAllocationSize,
                    &metadata.activity_name,
                )?;
                // Avoid flooding statsd.
                sleep(Duration::from_millis(10));
            }
        }
        {
            let snapshot_id = rng.gen();
            for metadata in self.bitmaps.values() {
                debug!("BitmapAllocationHandler.on_finished: random sample {metadata:?}");
                android_graphics_bitmap_allocation_snapshot::stats_write(
                    metadata.uid,
                    metadata.width,
                    metadata.height,
                    convert_to_pixel_storage_type_enum(metadata.pixel_storage_type),
                    snapshot_id,
                    android_graphics_bitmap_allocation_snapshot::SnapshotType::SnapshotTypeRandomSample,
                    &metadata.activity_name,
                )?;
                // Avoid flooding statsd.
                sleep(Duration::from_millis(10));
            }
            Ok(())
        }
    }
}

fn convert_to_pixel_storage_type_enum(
    pixel_storage_type: i32,
) -> android_graphics_bitmap_allocation_snapshot::PixelStorageType {
    match pixel_storage_type {
        0 => android_graphics_bitmap_allocation_snapshot::PixelStorageType::PixelStorageTypeWrappedPixelRef,
        1 => android_graphics_bitmap_allocation_snapshot::PixelStorageType::PixelStorageTypeHeap,
        2 => android_graphics_bitmap_allocation_snapshot::PixelStorageType::PixelStorageTypeAshmem,
        3 => android_graphics_bitmap_allocation_snapshot::PixelStorageType::PixelStorageTypeHardware,
        _ => android_graphics_bitmap_allocation_snapshot::PixelStorageType::PixelStorageTypeUnspecified,
    }
}

fn convert_to_bitmap_scaled_pixel_storage_type_enum(
    pixel_storage_type: i32,
) -> android_graphics_bitmap_scaled::PixelStorageType {
    match pixel_storage_type {
        0 => android_graphics_bitmap_scaled::PixelStorageType::PixelStorageTypeWrappedPixelRef,
        1 => android_graphics_bitmap_scaled::PixelStorageType::PixelStorageTypeHeap,
        2 => android_graphics_bitmap_scaled::PixelStorageType::PixelStorageTypeAshmem,
        3 => android_graphics_bitmap_scaled::PixelStorageType::PixelStorageTypeHardware,
        _ => android_graphics_bitmap_scaled::PixelStorageType::PixelStorageTypeUnspecified,
    }
}
