/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Result;
use crate::ecosystem::Ecosystem;
use rayon::prelude::*;
use walkdir::WalkDir;
use entropy::shannon_entropy;
use regex::Regex;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};
use reqwest::Client;
use chrono::{Utc, Duration};
use crate::fetcher::PackageMetadata;
use colored::*;

#[derive(Debug, Default, Serialize)]
pub struct ScanResult {
    pub score: u8,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String, // "CVE", "Malware", "Suspicious"
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub description: String,
    pub file_path: Option<PathBuf>,
}

pub struct Analyzer {
    client: Client,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub check_osv: bool,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn scan(&self, path: &Path, metadata: &PackageMetadata, ecosystem: &Ecosystem) -> Result<ScanResult> {
        self.scan_with_options(path, metadata, ecosystem, ScanOptions { check_osv: true })
            .await
    }

    pub async fn scan_with_options(
        &self,
        path: &Path,
        metadata: &PackageMetadata,
        ecosystem: &Ecosystem,
        options: ScanOptions,
    ) -> Result<ScanResult> {
        let mut findings = Vec::new();

        // 1. Typosquatting Check
        if let Some(finding) = self.check_typosquatting(&metadata.name, ecosystem) {
            findings.push(finding);
        }

        // 2. Reputation Check (Age)
        if let Some(finding) = self.check_reputation(metadata) {
            findings.push(finding);
        }

        // 3. OSV Check (Network)
        if options.check_osv {
            println!("Querying OSV database...");
            match self.check_osv(&metadata.name, &metadata.version, ecosystem).await {
                Ok(osv_findings) => findings.extend(osv_findings),
                Err(e) => println!("OSV Check failed: {}", e),
            }
        }

        // 4. Local File Analysis (CPU-bound)
        println!("Scanning files...");
        let files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        // Use Rayon for parallel processing
        let local_findings: Vec<Finding> = files.par_iter().flat_map(|file_path| {
             self.analyze_file(file_path)
        }).collect();
        
        findings.extend(local_findings);
        
        // Calculate Score
        let score = self.calculate_score(&findings);

        Ok(ScanResult {
            score,
            findings,
        })
    }

    fn check_typosquatting(&self, name: &str, ecosystem: &Ecosystem) -> Option<Finding> {
        // Simple POC list
        let popular_npm = ["react", "lodash", "express", "chalk", "commander", "debug", "tslib", "requests", "vue", "next"];
        // requests is pypi, but ok
        let popular_pypi = ["requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3", "six", "pip"];

        let target_list = match ecosystem {
            Ecosystem::Npm => popular_npm.as_slice(),
            Ecosystem::Pypi => popular_pypi.as_slice(),
            Ecosystem::Crates | Ecosystem::Java => return None,
        };

        for &popular in target_list {
            if name == popular {
                return None; // Exact match is fine
            }
            if strsim::levenshtein(name, popular) <= 2 { // Distance of 1 or 2 is suspicious
                 return Some(Finding {
                    category: "Typosquatting".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Package name '{}' is very similar to popular package '{}'. Possible typosquatting.", name, popular),
                    file_path: None,
                });
            }
        }
        None
    }

    fn check_reputation(&self, metadata: &PackageMetadata) -> Option<Finding> {
        if let Some(published) = metadata.published_at {
             let age = Utc::now() - published;
             if age < Duration::days(7) {
                 return Some(Finding {
                    category: "Reputation".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!("Package is very new ({} days old). Verify legitimacy.", age.num_days()),
                    file_path: None,
                });
             }
        }
        None
    }

    async fn check_osv(&self, name: &str, version: &str, ecosystem: &Ecosystem) -> Result<Vec<Finding>> {
        let package_type = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
            Ecosystem::Crates => "crates.io",
            Ecosystem::Java => "Maven",
        };

        let query = json!({
            "version": version,
            "package": {
                "name": name,
                "ecosystem": package_type
            }
        });

        let resp = match self.client.post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await {
                Ok(r) => r,
                Err(e) => {
                    println!("{} Could not reach CVE database: {}. Proceeding with static analysis only.", "WARN:".yellow(), e);
                    return Ok(vec![]);
                }
            };
        
        if !resp.status().is_success() {
             return Ok(vec![]); 
        }

        let json: Value = resp.json().await?;
        
        let mut findings = Vec::new();
        if let Some(vulns) = json.get("vulns") {
            if let Some(arr) = vulns.as_array() {
                for vuln in arr {
                    let id = vuln["id"].as_str().unwrap_or("Unknown ID");
                    let summary = vuln["summary"].as_str().unwrap_or("No summary");
                    findings.push(Finding {
                        category: "CVE".to_string(),
                        severity: "HIGH".to_string(), 
                        description: format!("{}: {}", id, summary),
                        file_path: None,
                    });
                }
            }
        }

        Ok(findings)
    }

    fn analyze_file(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let path_str = path.to_string_lossy();
        
        // Exclude test files/directories from analysis
        if path_str.contains("test") || path_str.contains("Test") || filename.starts_with("test_") {
            return findings;
        }

        // 1. Lifecycle Analysis (NPM)
        if filename == "package.json" {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(scripts) = json["scripts"].as_object() {
                        for (script_name, script_cmd) in scripts {
                            let cmd_str = script_cmd.as_str().unwrap_or("");
                            if script_name.contains("install") || script_name.contains("post") || script_name.contains("pre") {
                                if cmd_str.contains("curl") || cmd_str.contains("wget") || cmd_str.contains("| bash") {
                                     findings.push(Finding {
                                        category: "Lifecycle".to_string(),
                                        severity: "CRITICAL".to_string(),
                                        description: format!("Suspicious lifecycle script '{}': {}", script_name, cmd_str),
                                        file_path: Some(path.to_path_buf()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Standard File Analysis
        if let Some(ext) = path.extension() {
             let ext_str = ext.to_string_lossy();
             if !["js", "py", "sh", "ts", "rs", "java", "kt", "class"].contains(&ext_str.as_ref())
                && filename != "package.json"
             {
                 return findings;
             }
        } else if filename != "package.json" {
             return findings;
        }

        let content = match fs::read(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        // Entropy Check
        if !filename.ends_with(".class") {
            let entropy = shannon_entropy(&content);
            if entropy > 7.5 && !filename.ends_with(".png") && !filename.ends_with(".jpg") {
                if !filename.contains(".min.") && !filename.contains("package.json") {
                    findings.push(Finding {
                        category: "Suspicious".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: format!(
                            "High entropy detected ({:.2}). Possible packed/obfuscated code.",
                            entropy
                        ),
                        file_path: Some(path.to_path_buf()),
                    });
                }
            }
        }

        // String Pattern Matching
        let text = String::from_utf8_lossy(&content);
        
        // Simple signatures
        if (text.contains("eval(") || text.contains("exec(")) && !filename.ends_with(".json") && filename != "setup.py" {
              findings.push(Finding {
                    category: "Suspicious".to_string(),
                    severity: "LOW".to_string(),
                    description: "Usage of eval/exec detected.".to_string(),
                    file_path: Some(path.to_path_buf()),
                });
        }
        
        let re_ip = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        for cap in re_ip.find_iter(&text) {
             let ip = cap.as_str();
             // Ignore versions appearing as IPs (common in comments or version constants)
             // Ignore localhost
             if ip != "127.0.0.1" && ip != "0.0.0.0" && !ip.starts_with("192.168.") && !ip.starts_with("10.") {
                 // Very naive, but reduces noise. A real malware usually uses an external IP.
                 // Also, check if it looks like a version number (usually followed by something other than port?)
                 // Let's just flag public IPs.
                 findings.push(Finding {
                    category: "Network".to_string(),
                    severity: "LOW".to_string(), // Reduced from MEDIUM
                    description: format!("Hardcoded IP address found: {}", ip),
                    file_path: Some(path.to_path_buf()),
                });
                break; // One per file is enough
             }
        }
        
        // Refined socket check
        if (text.contains("socket.connect") || text.contains("net.connect")) && !filename.contains("adapter") {
             findings.push(Finding {
                    category: "Network".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: "Socket connection logic detected.".to_string(),
                    file_path: Some(path.to_path_buf()),
                });
        }

        findings
    }
    
    fn calculate_score(&self, findings: &[Finding]) -> u8 {
        if findings.is_empty() {
            return 100;
        }
        
        let mut penalty = 0;
        for f in findings {
            match f.severity.as_str() {
                "CRITICAL" => penalty += 100,
                "HIGH" => penalty += 40,
                "MEDIUM" => penalty += 5,
                "LOW" => penalty += 1, // Reduced to avoid false positive accumulation
                _ => penalty += 1,
            }
        }
        
        if penalty >= 100 {
            0
        } else {
            100 - penalty
        }
    }
}
