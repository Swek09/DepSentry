/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

mod cli;
mod ecosystem;
mod fetcher;
mod analysis;
mod report;

use clap::Parser;
use cli::{Cli, Commands};
use ecosystem::Ecosystem;
use colored::*;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Check { name, r#type, version } => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            
            let ecosystem = if let Some(t) = r#type {
                Ecosystem::from_str(&t).expect("Invalid ecosystem type. Use 'npm' or 'pypi'")
            } else {
                Ecosystem::detect(&cwd).unwrap_or_else(|| {
                    println!("{}", "Could not auto-detect ecosystem. Please specify --type".yellow());
                    std::process::exit(1);
                })
            };

            println!("{} {} ({:?})", "Checking package:".green().bold(), name, ecosystem);

            let scan_path;
            let pkg_metadata;
            let mut is_temp = false;

            let local_path = std::path::Path::new(&name);
            if local_path.exists() {
                println!("{} Found local path: {:?}", "INFO:".blue(), local_path);
                if local_path.is_file() {
                     println!("{}", "Archives not supported in this version. Please extract and scan directory.".yellow());
                     std::process::exit(1);
                } else {
                    scan_path = local_path.to_path_buf();
                    pkg_metadata = fetcher::PackageMetadata {
                        name: name.clone(),
                        version: "local".to_string(),
                        published_at: None,
                    };
                }
            } else {
                // Remote Download
                let fetcher = fetcher::Fetcher::new();
                match fetcher.download(&name, version.as_deref(), &ecosystem).await {
                    Ok((path, metadata)) => {
                        println!("{} Downloaded and extracted to {:?} (Version: {})", "SUCCESS:".green(), path, metadata.version);
                        scan_path = path;
                        pkg_metadata = metadata;
                        is_temp = true;
                    }
                    Err(e) => {
                        println!("{} Failed to download package: {}", "ERROR:".red(), e);
                        std::process::exit(1);
                    }
                }
            }

            let analyzer = analysis::Analyzer::new();
            match analyzer.scan(&scan_path, &pkg_metadata, &ecosystem).await {
                Ok(result) => {
                    report::Reporter::print_report(&result);
                    report::Reporter::generate_audit_json(&result);
                    
                    if result.score < 50 { // Score < 50 means Risk > 50 (Critical/High)
                        println!("{}", "Build failed due to critical security risks.".red().bold());
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                        println!("{} Analysis failed: {}", "ERROR:".red(), e);
                }
            }
            
            if is_temp {
                 if let Err(e) = std::fs::remove_dir_all(&scan_path) {
                     println!("{} Failed to cleanup temp dir: {}", "WARN:".yellow(), e);
                 }
            }
        }
        Commands::Scan { path } => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let target_path = path.clone().map(std::path::PathBuf::from).unwrap_or_else(|| cwd.join("package.json"));

            if !target_path.exists() {
                println!("{} Manifest file not found at: {:?}", "ERROR:".red(), target_path);
                std::process::exit(1);
            }

            println!("{} Scanning manifest: {:?}", "INFO:".blue(), target_path);
            
            // Detect Type from filename
            let filename = target_path.file_name().unwrap_or_default().to_string_lossy();
            let mut dependencies = Vec::new();

            if filename == "package.json" {
                let content = std::fs::read_to_string(&target_path).expect("Failed to read file");
                let json: serde_json::Value = serde_json::from_str(&content).expect("Invalid JSON");
                
                if let Some(deps) = json["dependencies"].as_object() {
                    for (name, ver) in deps {
                        let clean_ver = ver.as_str().unwrap_or("latest")
                            .trim_start_matches('^').trim_start_matches('~');
                        dependencies.push((name.to_string(), clean_ver.to_string(), Ecosystem::Npm));
                    }
                }
                if let Some(deps) = json["devDependencies"].as_object() {
                    for (name, ver) in deps {
                        let clean_ver = ver.as_str().unwrap_or("latest")
                             .trim_start_matches('^').trim_start_matches('~');
                        dependencies.push((name.to_string(), clean_ver.to_string(), Ecosystem::Npm));
                    }
                }
            } else if filename == "requirements.txt" {
                 let content = std::fs::read_to_string(&target_path).expect("Failed to read file");
                 for line in content.lines() {
                     let line = line.trim();
                     if line.is_empty() || line.starts_with('#') { continue; }
                     // Very naive parsing for now
                     let parts: Vec<&str> = line.split("==").collect();
                     let name = parts[0].to_string();
                     let ver = if parts.len() > 1 { parts[1].to_string() } else { "latest".to_string() };
                     dependencies.push((name, ver, Ecosystem::Pypi));
                 }
            } else {
                 println!("{} Unsupported manifest file: {}", "ERROR:".red(), filename);
                 std::process::exit(1);
             }

            println!("Found {} dependencies. Starting analysis...", dependencies.len());
            
            let fetcher = fetcher::Fetcher::new();
            let analyzer = analysis::Analyzer::new();
            
            for (name, ver, ecosystem) in dependencies {
                println!("--------------------------------------------------");
                println!("Analyzing {}@{}...", name.blue().bold(), ver);
                
                let res = fetcher.download(&name, Some(&ver), &ecosystem).await;
                match res {
                    Ok((path, metadata)) => {
                         match analyzer.scan(&path, &metadata, &ecosystem).await {
                             Ok(result) => {
                                 let score_color = if result.score > 80 { "green" } else { "red" };
                                 println!("Score: {} | Findings: {}", result.score.to_string().color(score_color), result.findings.len());
                                 if result.score < 80 {
                                     report::Reporter::print_report(&result);
                                 }
                             }
                             Err(e) => println!("Analysis error: {}", e),
                         }
                         // Cleanup
                         if let Err(e) = std::fs::remove_dir_all(&path) {
                             println!("{} Failed to cleanup temp dir: {}", "WARN:".yellow(), e);
                         }
                    }
                    Err(e) => println!("Download failed: {}", e),
                }
            }
        }
    }
}
