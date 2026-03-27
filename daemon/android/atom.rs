//! StatsD atom helpers.
use anyhow::{anyhow, bail, Result};
use log::error;
use statslog_uprobestats::{
    android_graphics_bitmap_allocated, android_graphics_bitmap_allocation_snapshot,
    android_graphics_bitmap_scaled, bind_service_locked_with_bal_flags_reported,
    bind_service_locked_with_bal_flags_uids_reported, disabled_launcher_activity_uids_reported,
    set_component_enabled_setting_reported, uprobe_stats_bpf_attached, uprobe_stats_bpf_map_polled,
    uprobe_stats_internal_error,
};
use uprobestats_core::atom::{AtomWriter, CodegenAtom};

/// We don't want to log strings to statsd, so we convert the path to an enum.
pub fn bpf_program_path_to_enum(path: &str) -> Result<uprobe_stats_bpf_attached::BpfProgram> {
    use uprobe_stats_bpf_attached::BpfProgram::*;
    let Some(filename) = path.rsplit('/').next() else {
        bail!("Failed to extract filename from path: {path}")
    };
    Ok(match filename {
        "prog_Accessibility_uprobe_accessibility_service_connection" => {
            ProgAccessibilityUprobeAccessibilityServiceConnection
        }
        "prog_Accessibility_uprobe_grant_runtime_permission" => {
            ProgAccessibilityUprobeGrantRuntimePermission
        }
        "prog_Binder_uprobe_exec_transact_internal" => ProgBinderUprobeExecTransactInternal,
        "prog_BitmapAllocation_uprobe_activity_perform_start" => {
            ProgBitmapAllocationUprobeActivityPerformStart
        }
        "prog_BitmapAllocation_uprobe_apply_free_function" => {
            ProgBitmapAllocationUprobeApplyFreeFunction
        }
        "prog_BitmapAllocation_uprobe_bitmap_creation_for_snapshot" => {
            ProgBitmapAllocationUprobeBitmapCreationForSnapshot
        }
        "prog_BitmapAllocation_uprobe_create_scaled_bitmap" => {
            ProgBitmapAllocationUprobeCreateScaledBitmap
        }
        "prog_DisruptiveApp_uprobe_bind_service_locked" => ProgDisruptiveAppUprobeBindServiceLocked,
        "prog_DisruptiveApp_uprobe_set_component_enabled_setting" => {
            ProgDisruptiveAppUprobeSetComponentEnabledSetting
        }
        "prog_GenericInstrumentation_uprobe_call_detail" => {
            ProgGenericInstrumentationUprobeCallDetail
        }
        "prog_GenericInstrumentation_uprobe_call_timestamp" => {
            ProgGenericInstrumentationUprobeCallTimestamp
        }
        _ => {
            error!("Unspecified program_path filename: {}", filename);
            UprobeStatsBpfProgramUnspecified
        }
    })
}

/// We don't want to log strings to statsd, so we convert the path to an enum.
pub fn bpf_map_path_to_enum(map_path: &str) -> Result<uprobe_stats_bpf_map_polled::MapPath> {
    use uprobe_stats_bpf_map_polled::MapPath::*;
    let Some(filename) = map_path.rsplit('/').next() else {
        bail!("Failed to extract filename from map_path: {map_path}")
    };
    Ok(match filename {
        "map_Accessibility_output_buf" => BpfMapPathAccessibilityOutputBuf,
        "map_Binder_output_buf" => BpfMapPathBinderOutputBuf,
        "map_BitmapAllocation_output" => BpfMapPathBitmapAllocationOutput,
        "map_DisruptiveApp_BindServiceLocked_output_buf" => {
            BpfMapPathDisruptiveAppBindServiceLockedOutputBuf
        }
        "map_DisruptiveApp_ComponentEnabledSetting_output_buf" => {
            BpfMapPathDisruptiveAppComponentEnabledSettingOutputBuf
        }
        "map_GenericInstrumentation_call_detail_buf" => {
            BpfMapPathGenericInstrumentationCallDetailBuf
        }
        "map_GenericInstrumentation_call_timestamp_buf" => {
            BpfMapPathGenericInstrumentationCallTimestampBuf
        }
        _ => {
            error!("Unspecified map_path filename: {}", filename);
            UprobeStatsBpfMapPathUnspecified
        }
    })
}

/// Unfortunate that this needs to exist.
/// stats-log-api-gen duplicates the enum definition
/// into every module that uses it, making them distinct types in Rust even though they
/// originate from the same proto enum.
pub fn to_internal_error_bpf_attached_program(
    p: uprobe_stats_bpf_attached::BpfProgram,
) -> uprobe_stats_internal_error::BpfProgram {
    use uprobe_stats_bpf_attached::BpfProgram as Attached;
    use uprobe_stats_internal_error::BpfProgram as InternalError;
    match p {
        Attached::UprobeStatsBpfProgramUnspecified => {
            InternalError::UprobeStatsBpfProgramUnspecified
        }
        Attached::ProgAccessibilityUprobeAccessibilityServiceConnection => {
            InternalError::ProgAccessibilityUprobeAccessibilityServiceConnection
        }
        Attached::ProgAccessibilityUprobeGrantRuntimePermission => {
            InternalError::ProgAccessibilityUprobeGrantRuntimePermission
        }
        Attached::ProgBinderUprobeExecTransactInternal => {
            InternalError::ProgBinderUprobeExecTransactInternal
        }
        Attached::ProgBitmapAllocationOutput => InternalError::ProgBitmapAllocationOutput,
        Attached::ProgBitmapAllocationUprobeActivityPerformStart => {
            InternalError::ProgBitmapAllocationUprobeActivityPerformStart
        }
        Attached::ProgBitmapAllocationUprobeApplyFreeFunction => {
            InternalError::ProgBitmapAllocationUprobeApplyFreeFunction
        }
        Attached::ProgBitmapAllocationUprobeBitmapCreationForSnapshot => {
            InternalError::ProgBitmapAllocationUprobeBitmapCreationForSnapshot
        }
        Attached::ProgBitmapAllocationUprobeCreateScaledBitmap => {
            InternalError::ProgBitmapAllocationUprobeCreateScaledBitmap
        }
        Attached::ProgDisruptiveAppUprobeBindServiceLocked => {
            InternalError::ProgDisruptiveAppUprobeBindServiceLocked
        }
        Attached::ProgDisruptiveAppUprobeSetComponentEnabledSetting => {
            InternalError::ProgDisruptiveAppUprobeSetComponentEnabledSetting
        }
        Attached::ProgGenericInstrumentationUprobeCallDetail => {
            InternalError::ProgGenericInstrumentationUprobeCallDetail
        }
        Attached::ProgGenericInstrumentationUprobeCallTimestamp => {
            InternalError::ProgGenericInstrumentationUprobeCallTimestamp
        }
        Attached::ProgKeepaliveUprobeAcquireWakeLockInternal => {
            InternalError::ProgKeepaliveUprobeAcquireWakeLockInternal
        }
        Attached::ProgKeepaliveUprobeReleaseWakeLockInternal => {
            InternalError::ProgKeepaliveUprobeReleaseWakeLockInternal
        }
    }
}

/// Unfortunate that this needs to exist.
/// stats-log-api-gen duplicates the enum definition
/// into every module that uses it, making them distinct types in Rust even though they
/// originate from the same proto enum.
pub fn to_internal_error_bpf_map_polled_path(
    p: uprobe_stats_bpf_map_polled::MapPath,
) -> uprobe_stats_internal_error::MapPath {
    use uprobe_stats_bpf_map_polled::MapPath as Polled;
    use uprobe_stats_internal_error::MapPath as InternalError;
    match p {
        Polled::UprobeStatsBpfMapPathUnspecified => InternalError::UprobeStatsBpfMapPathUnspecified,
        Polled::BpfMapPathAccessibilityOutputBuf => InternalError::BpfMapPathAccessibilityOutputBuf,
        Polled::BpfMapPathBinderOutputBuf => InternalError::BpfMapPathBinderOutputBuf,
        Polled::BpfMapPathBitmapAllocationOutput => InternalError::BpfMapPathBitmapAllocationOutput,
        Polled::BpfMapPathDisruptiveAppBindServiceLockedOutputBuf => {
            InternalError::BpfMapPathDisruptiveAppBindServiceLockedOutputBuf
        }
        Polled::BpfMapPathDisruptiveAppComponentEnabledSettingOutputBuf => {
            InternalError::BpfMapPathDisruptiveAppComponentEnabledSettingOutputBuf
        }
        Polled::BpfMapPathGenericInstrumentationCallDetailBuf => {
            InternalError::BpfMapPathGenericInstrumentationCallDetailBuf
        }
        Polled::BpfMapPathGenericInstrumentationCallTimestampBuf => {
            InternalError::BpfMapPathGenericInstrumentationCallTimestampBuf
        }
        Polled::BpfMapPathKeepaliveOutputBuf => InternalError::BpfMapPathKeepaliveOutputBuf,
    }
}

/// Write an internal error atom to statsd.
pub fn write_internal_error(
    error_type: uprobe_stats_internal_error::ErrorType,
    task_id: i64,
    bpf_program_path: Option<&str>,
    bpf_map_path: Option<&str>,
    failure_point: i64,
) {
    use uprobe_stats_internal_error::{BpfProgram, MapPath};
    let bpf_program_enum = match bpf_program_path {
        Some(path) => {
            // unwrap because if the path is /not/a/valid/path/at/all, that is totally unexpected and should panic.
            to_internal_error_bpf_attached_program(bpf_program_path_to_enum(path).unwrap())
        }
        None => BpfProgram::UprobeStatsBpfProgramUnspecified,
    };
    let map_path_enum = match bpf_map_path {
        Some(path) => {
            // unwrap because if the path is /not/a/valid/path/at/all, that is totally unexpected and should panic.
            to_internal_error_bpf_map_polled_path(bpf_map_path_to_enum(path).unwrap())
        }
        None => MapPath::UprobeStatsBpfMapPathUnspecified,
    };

    if let Err(e) = uprobe_stats_internal_error::stats_write(
        error_type,
        task_id,
        bpf_program_enum,
        map_path_enum,
        failure_point,
    ) {
        error!("Failed to write uprobe_stats_internal_error atom: {:?}", e);
    }
}

#[derive(Default)]
pub(crate) struct CodegenAtomWriter {}
impl AtomWriter<CodegenAtom> for CodegenAtomWriter {
    fn write(&mut self, atom: CodegenAtom) -> Result<()> {
        match atom {
            CodegenAtom::SetComponentEnabledSettingReported {
                package_name,
                class_name,
                new_state,
                calling_package_name,
                is_launcher_activity,
            } => set_component_enabled_setting_reported::stats_write(
                &package_name,
                &class_name,
                new_state,
                &calling_package_name,
                is_launcher_activity,
            ),
            CodegenAtom::DisabledLauncherActivityUidsReported {
                calling_uid,
                disabled_activity_uid,
            } => disabled_launcher_activity_uids_reported::stats_write(
                calling_uid,
                disabled_activity_uid,
            ),
            CodegenAtom::BindServiceLockedWithBalFlagsReported {
                intent_package,
                flags,
                calling_package,
                intent_action,
                intent_component_name_package,
                intent_component_name_class,
            } => bind_service_locked_with_bal_flags_reported::stats_write(
                &intent_package,
                flags,
                &calling_package,
                &intent_action,
                &intent_component_name_package,
                &intent_component_name_class,
            ),
            CodegenAtom::BindServiceLockedWithBalFlagsUidsReported { binder_uid, bindee_uid } => {
                bind_service_locked_with_bal_flags_uids_reported::stats_write(
                    binder_uid, bindee_uid,
                )
            }
            CodegenAtom::AndroidGraphicsBitmapAllocated { uid, width, height } => {
                android_graphics_bitmap_allocated::stats_write(uid, width, height)
            }
            CodegenAtom::AndroidGraphicsBitmapScaled {
                uid,
                width,
                height,
                scaled_width,
                scaled_height,
                pixel_storage_type,
                activity_name,
            } => android_graphics_bitmap_scaled::stats_write(
                uid,
                width,
                height,
                scaled_width,
                scaled_height,
                convert_to_bitmap_scaled_pixel_storage_type_enum(pixel_storage_type),
                &activity_name,
            ),
            CodegenAtom::AndroidGraphicsBitmapAllocationSnapshot {
                uid,
                width,
                height,
                pixel_storage_type,
                snapshot_id,
                snapshot_type,
                activity_name,
            } => android_graphics_bitmap_allocation_snapshot::stats_write(
                uid,
                width,
                height,
                convert_to_pixel_storage_type_enum(pixel_storage_type),
                snapshot_id,
                convert_to_snapshot_type_enum(snapshot_type),
                &activity_name,
            ),
        }
        .map_err(|e| anyhow!(e))
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

fn convert_to_snapshot_type_enum(
    snapshot_type: i32,
) -> android_graphics_bitmap_allocation_snapshot::SnapshotType {
    match snapshot_type {
        1 => {
            android_graphics_bitmap_allocation_snapshot::SnapshotType::SnapshotTypeMaxAllocationSize
        }
        2 => android_graphics_bitmap_allocation_snapshot::SnapshotType::SnapshotTypeRandomSample,
        _ => android_graphics_bitmap_allocation_snapshot::SnapshotType::SnapshotTypeUnspecified,
    }
}
