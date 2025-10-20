//! Handles allow list of code that can be instrumented on user devices.
use anyhow::{anyhow, bail, Result};
use uprobestats_proto::config::{uprobestats_config::task::ProbeConfig, UprobestatsConfig};

const ALLOWED_METHOD_PREFIXES: [&str; 6] = [
    "com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist",
    "com.android.server.am.CachedAppOptimizer",
    "com.android.server.am.OomAdjuster",
    "com.android.server.am.OomAdjusterModernImpl",
    "com.android.server.pm.PackageManagerService$IPackageManagerImpl.setComponentEnabledSetting",
    "com.android.server.am.ActiveServices.bindServiceLocked",
];

/// Checks if the given config is allowed to be instrumented on user devices.
///
/// If the device is a user build, all configs are allowed. Otherwise, only configs that are
/// explicitly allowed are allowed.
pub fn is_allowed(
    config: &UprobestatsConfig,
    is_user_build: bool,
    offsets_api_enabled: bool,
) -> Result<bool> {
    if !is_user_build {
        return Ok(true);
    }
    for task in &config.tasks {
        for probe in &task.probe_configs {
            let full_method_name = get_full_method_name(probe, offsets_api_enabled)?;
            let mut allowed = false;
            for prefix in ALLOWED_METHOD_PREFIXES {
                if full_method_name == prefix
                    || full_method_name.starts_with(&(prefix.to_string() + "("))
                    || full_method_name.starts_with(&(prefix.to_string() + "."))
                    || full_method_name.starts_with(&(prefix.to_string() + "$"))
                {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn get_full_method_name(probe_config: &ProbeConfig, offsets_api_enabled: bool) -> Result<String> {
    if offsets_api_enabled {
        let Some(ref fqcn) = probe_config.fully_qualified_class_name else {
            bail!("Fully qualified class name is empty")
        };
        let Some(ref method_name) = probe_config.method_name else { bail!("Method name is empty") };
        Ok(format!("{fqcn}.{method_name}"))
    } else {
        let Some(ref method_signature) = probe_config.method_signature else {
            bail!("Method signature is empty")
        };
        let mut parts = method_signature.split(" ");
        parts.nth(1).map(String::from).ok_or(anyhow!("Method signature is invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::clone::Clone;
    use uprobestats_proto::config::uprobestats_config::Task;

    #[test]
    fn everything_allowed_on_userdebug() {
        let config = setup_config(vec![setup_probe_config(
            "com.android.server.am.SomeClass",
            "doWork",
            vec![],
        )]);

        assert!(is_allowed(&config, false, true).unwrap());
        assert!(is_allowed(&config, false, false).unwrap());
    }

    #[test]
    fn oom_adjuster_allowed() {
        let config = setup_config(vec![
            setup_probe_config(
                "com.android.server.am.OomAdjuster",
                "setUidTempAllowlistStateLSP",
                vec!["int".to_string(), "boolean".to_string()],
            ),
            setup_probe_config(
                "com.android.server.am.OomAdjuster$$ExternalSyntheticLambda0",
                "accept",
                vec!["java.lang.String".to_string()],
            ),
        ]);

        assert!(is_allowed(&config, false, false).unwrap());
        assert!(is_allowed(&config, true, false).unwrap());
        assert!(is_allowed(&config, false, true).unwrap());
        assert!(is_allowed(&config, true, true).unwrap());
    }

    #[test]
    fn update_device_idle_temp_allowlist_allowed() {
        let config = setup_config(vec![setup_probe_config(
            "com.android.server.am.ActivityManagerService$LocalService",
            "updateDeviceIdleTempAllowlist",
            vec![],
        )]);

        assert_eq!(
            "com.android.server.am.ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist()",
            &get_full_method_name(&config.tasks[0].probe_configs[0], false).unwrap()
        );

        assert!(is_allowed(&config, false, false).unwrap());
        // TODO: does this actually work in the c++ impl? @mattgilbride ask @yutingtseng
        // assert!(is_allowed(&config, true, false).unwrap());
        assert!(is_allowed(&config, false, true).unwrap());
        assert!(is_allowed(&config, true, true).unwrap());
    }

    #[test]
    fn oom_adjuster_with_suffix_disallowed() {
        let config = setup_config(vec![setup_probe_config(
            "com.android.server.am.OomAdjusterWithSomeSuffix",
            "doWork",
            vec![],
        )]);

        assert!(!is_allowed(&config, true, false).unwrap());
        assert!(!is_allowed(&config, true, true).unwrap());
    }

    #[test]
    fn disallowed_method_in_second_task_disallowed() {
        let config = setup_config(vec![
            setup_probe_config("com.android.server.am.OomAdjusterWithSomeSuffix", "doWork", vec![]),
            setup_probe_config("com.android.server.am.DisallowedClass", "doWork", vec![]),
        ]);

        assert!(!is_allowed(&config, true, false).unwrap());
        assert!(!is_allowed(&config, true, true).unwrap());
    }

    fn setup_config(probe_configs: Vec<ProbeConfig>) -> UprobestatsConfig {
        UprobestatsConfig {
            tasks: vec![Task { probe_configs, ..Task::default() }],
            ..UprobestatsConfig::default()
        }
    }

    fn setup_probe_config(
        class_name: &str,
        method_name: &str,
        fully_qualified_parameters: impl IntoIterator<Item = String> + Clone,
    ) -> ProbeConfig {
        ProbeConfig {
            fully_qualified_class_name: Some(class_name.to_string()),
            method_name: Some(method_name.to_string()),
            fully_qualified_parameters: fully_qualified_parameters.clone().into_iter().collect(),
            method_signature: Some(format!(
                "void {}.{}({})",
                class_name,
                method_name,
                fully_qualified_parameters.into_iter().collect::<Vec<String>>().join(", ")
            )),
            ..ProbeConfig::default()
        }
    }
}
