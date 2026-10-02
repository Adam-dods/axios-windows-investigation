use crate::{models::AxiosSnapshot, network, persistence, processes, security, system};
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use std::{thread, time::Duration};
use sysinfo::System;

pub fn collect() -> AxiosSnapshot {
    let mut host = System::new_all();
    host.refresh_all();

    thread::sleep(Duration::from_millis(500));
    host.refresh_all();

    AxiosSnapshot {
        schema_version: 1,
        axios_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().to_rfc3339(),
        system: json!({
            "inventory": system::inventory::collect(&host),
            "updates": system::updates::collect()
        }),
        processes: processes::collector::collect(&host),
        network: network::collector::collect(),
        services: persistence::services::collect(),
        drivers: persistence::drivers::collect(),
        security: json!({
            "defender": security::defender::collect(),
            "firewall": security::firewall::collect()
        }),
        persistence: json!({
            "startup": persistence::startup::collect(),
            "scheduled_tasks": persistence::tasks::collect()
        }),
    }
}

pub fn save(output: &str) -> Result<()> {
    let snapshot = collect();
    let json = serde_json::to_string_pretty(&snapshot)?;

    std::fs::write(output, json)
        .with_context(|| format!("failed to write snapshot to {output}"))?;

    println!("AXIOS snapshot saved: {output}");
    Ok(())
}
