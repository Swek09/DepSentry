use crate::snapshot::Dependency;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub summary: String,
    pub modified: Option<DateTime<Utc>>,
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReport {
    pub created_at: DateTime<Utc>,
    pub input_hash: String,
    pub vulns: Vec<OsvVuln>,
}

pub fn query_osv_vulns(deps: &[Dependency]) -> Result<Vec<OsvVuln>> {
    let queries: Vec<_> = deps
        .iter()
        .filter(|d| d.version != "unspecified" && d.version != "local")
        .map(|d| {
            let ecosystem = match d.ecosystem {
                crate::ecosystem::Ecosystem::Npm => "npm",
                crate::ecosystem::Ecosystem::Pypi => "PyPI",
                crate::ecosystem::Ecosystem::Crates => "crates.io",
                crate::ecosystem::Ecosystem::Java => "Maven",
            };
            json!({
                "version": d.version,
                "package": { "name": d.name, "ecosystem": ecosystem }
            })
        })
        .collect();

    if queries.is_empty() {
        return Ok(vec![]);
    }

    let client = Client::builder()
        .user_agent("depsentry-firewall/0.2.3")
        .build()
        .context("Failed to create HTTP client")?;

    let resp: serde_json::Value = client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&json!({ "queries": queries }))
        .send()
        .context("Failed to call OSV API")?
        .error_for_status()
        .context("OSV API returned error status")?
        .json()
        .context("Failed to parse OSV response JSON")?;

    let results = resp
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("Invalid OSV response: missing results[]"))?;

    // Deduplicate by vuln id, merge package list
    let mut map: BTreeMap<String, OsvVuln> = BTreeMap::new();
    for (i, res) in results.iter().enumerate() {
        let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) else {
            continue;
        };
        // Best-effort: align index back to dependency string for context
        let dep_label = deps
            .iter()
            .filter(|d| d.version != "unspecified" && d.version != "local")
            .nth(i)
            .map(|d| format!("{}@{}", d.name, d.version))
            .unwrap_or_else(|| "unknown".to_string());

        for vuln in vulns {
            let id = vuln.get("id").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string();
            let summary = vuln
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("No summary")
                .to_string();
            let modified = vuln
                .get("modified")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let entry = map.entry(id.clone()).or_insert_with(|| OsvVuln {
                id,
                summary,
                modified,
                packages: Vec::new(),
            });
            if !entry.packages.iter().any(|p| p == &dep_label) {
                entry.packages.push(dep_label.clone());
            }
        }
    }

    Ok(map.into_values().collect())
}
