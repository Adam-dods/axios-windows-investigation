use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KernelProvider {
    Process,
    Thread,
    ImageLoad,
    DiskIo,
    NetworkTcpIp,
    Registry,
}

impl KernelProvider {
    pub fn provider_name(self) -> &'static str {
        match self {
            Self::Process => "Microsoft-Windows-Kernel-Process",
            Self::Thread => "Microsoft-Windows-Kernel-Thread",
            Self::ImageLoad => "Microsoft-Windows-Kernel-Image",
            Self::DiskIo => "Microsoft-Windows-Kernel-Disk",
            Self::NetworkTcpIp => "Microsoft-Windows-Kernel-Network",
            Self::Registry => "Microsoft-Windows-Kernel-Registry",
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Thread => "thread",
            Self::ImageLoad => "image_load",
            Self::DiskIo => "disk_io",
            Self::NetworkTcpIp => "network",
            Self::Registry => "registry",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProviderConfig {
    pub provider: KernelProvider,
    pub enabled: bool,
    pub capture_stack_traces: bool,
}

pub fn default_providers() -> Vec<EtwProviderConfig> {
    vec![
        EtwProviderConfig {
            provider: KernelProvider::Process,
            enabled: true,
            capture_stack_traces: false,
        },
        EtwProviderConfig {
            provider: KernelProvider::Thread,
            enabled: true,
            capture_stack_traces: false,
        },
        EtwProviderConfig {
            provider: KernelProvider::ImageLoad,
            enabled: true,
            capture_stack_traces: false,
        },
        EtwProviderConfig {
            provider: KernelProvider::DiskIo,
            enabled: true,
            capture_stack_traces: false,
        },
        EtwProviderConfig {
            provider: KernelProvider::NetworkTcpIp,
            enabled: true,
            capture_stack_traces: false,
        },
        EtwProviderConfig {
            provider: KernelProvider::Registry,
            enabled: false,
            capture_stack_traces: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_enables_core_providers() {
        let providers = default_providers();

        assert_eq!(providers.len(), 6);
        assert!(providers
            .iter()
            .any(|item| { item.provider == KernelProvider::Process && item.enabled }));
    }

    #[test]
    fn provider_names_are_stable() {
        assert_eq!(
            KernelProvider::ImageLoad.provider_name(),
            "Microsoft-Windows-Kernel-Image"
        );
    }
}
