use chrono::Utc;
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskResourceSample {
    pub name: String,
    pub mount_point: String,
    pub total_space_bytes: u64,
    pub available_space_bytes: u64,
    pub used_space_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResourceSample {
    pub pid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSample {
    pub timestamp: String,
    pub system_cpu_percent: f32,
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub total_swap_bytes: u64,
    pub used_swap_bytes: u64,
    pub disks: Vec<DiskResourceSample>,
    pub top_processes: Vec<ProcessResourceSample>,
    pub gpu_collection_status: String,
}

pub struct ResourceSampler {
    system: System,
    disks: Disks,
}

impl Default for ResourceSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceSampler {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
            disks: Disks::new_with_refreshed_list(),
        }
    }

    pub fn sample(&mut self, process_limit: usize) -> ResourceSample {
        self.system.refresh_all();
        self.disks.refresh(true);

        let mut processes: Vec<ProcessResourceSample> = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| ProcessResourceSample {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().to_string(),
                executable: process.exe().map(|path| path.to_string_lossy().to_string()),
                cpu_percent: process.cpu_usage(),
                memory_bytes: process.memory(),
                virtual_memory_bytes: process.virtual_memory(),
            })
            .collect();

        processes.sort_by(|left, right| {
            right
                .cpu_percent
                .partial_cmp(&left.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        processes.truncate(process_limit.max(1));

        let disks = self
            .disks
            .list()
            .iter()
            .map(|disk| {
                let total = disk.total_space();
                let available = disk.available_space();

                DiskResourceSample {
                    name: disk.name().to_string_lossy().to_string(),
                    mount_point: disk.mount_point().to_string_lossy().to_string(),
                    total_space_bytes: total,
                    available_space_bytes: available,
                    used_space_bytes: total.saturating_sub(available),
                }
            })
            .collect();

        ResourceSample {
            timestamp: Utc::now().to_rfc3339(),
            system_cpu_percent: self.system.global_cpu_usage(),
            total_memory_bytes: self.system.total_memory(),
            used_memory_bytes: self.system.used_memory(),
            available_memory_bytes: self.system.available_memory(),
            total_swap_bytes: self.system.total_swap(),
            used_swap_bytes: self.system.used_swap(),
            disks,
            top_processes: processes,
            gpu_collection_status: "pending_windows_gpu_engine_collector".to_string(),
        }
    }
}

pub fn classify_memory_pressure(used_memory_bytes: u64, total_memory_bytes: u64) -> &'static str {
    if total_memory_bytes == 0 {
        return "unknown";
    }

    let percentage = used_memory_bytes.saturating_mul(100) / total_memory_bytes;

    match percentage {
        0..=69 => "normal",
        70..=84 => "elevated",
        85..=94 => "high",
        _ => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_pressure_is_classified() {
        assert_eq!(classify_memory_pressure(7, 10), "elevated");

        assert_eq!(classify_memory_pressure(9, 10), "high");

        assert_eq!(classify_memory_pressure(98, 100), "critical");
    }

    #[test]
    fn zero_memory_is_unknown() {
        assert_eq!(classify_memory_pressure(0, 0), "unknown");
    }
}
