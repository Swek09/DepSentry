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
mod firewall;
mod snapshot;
mod osv;

use clap::Parser;
use cli::{AutostartCommands, Cli, Commands, FirewallCommands, WebhookCommands, WebhookIgnoreCommands};
use ecosystem::Ecosystem;
use colored::*;

fn main() {
    // Enable ANSI support on Windows
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).ok();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Check { name, r#type, version } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime");
            rt.block_on(async {
                if let Err(e) = run_check(name, r#type.as_deref(), version.as_deref(), cli.json).await {
                    println!("{} {}", "ERROR:".red(), e);
                    std::process::exit(1);
                }
            });
        }
        Commands::Scan { path } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime");
            rt.block_on(async {
                if let Err(e) = run_scan(path.as_deref()).await {
                    println!("{} {}", "ERROR:".red(), e);
                    std::process::exit(1);
                }
            });
        }
        Commands::Firewall { command } => {
            let res = match command {
                FirewallCommands::Start => firewall::daemon_start(),
                FirewallCommands::Stop => firewall::daemon_stop(),
                FirewallCommands::Restart => firewall::daemon_restart(),
                FirewallCommands::Add { path } => firewall::project_add(path),
                FirewallCommands::Rm { name } => firewall::project_rm(name),
                FirewallCommands::Ls => firewall::project_ls(),
                FirewallCommands::Status { name } => firewall::project_status(name),
                FirewallCommands::Logs { name, lines } => firewall::show_logs(name.clone(), *lines),
                FirewallCommands::Save => firewall::snapshot_save(),
                FirewallCommands::Resurrect => firewall::snapshot_resurrect(),
                FirewallCommands::Scan { name, deep, cve_only } => {
                    firewall::scan_project(name, *deep, *cve_only)
                }
                FirewallCommands::Set {
                    name,
                    cve_interval_hours,
                    deep_max_packages,
                    deep_timeout_secs,
                    deep_cache_ttl_hours,
                } => {
                    firewall::project_set(
                        name,
                        *cve_interval_hours,
                        *deep_max_packages,
                        *deep_timeout_secs,
                        *deep_cache_ttl_hours,
                    )
                }
                FirewallCommands::Webhook { command } => match command {
                    WebhookCommands::Set { url } => firewall::webhook_set(url),
                    WebhookCommands::Clear => firewall::webhook_clear(),
                    WebhookCommands::SetDedupMinutes { minutes } => firewall::webhook_set_dedup_minutes(*minutes),
                    WebhookCommands::Ignore { command } => match command {
                        WebhookIgnoreCommands::Add { id } => firewall::webhook_ignore_add(id),
                        WebhookIgnoreCommands::Rm { id } => firewall::webhook_ignore_rm(id),
                        WebhookIgnoreCommands::Ls => firewall::webhook_ignore_ls(),
                    },
                    WebhookCommands::Test => firewall::webhook_test(),
                },
                FirewallCommands::Autostart { command } => match command {
                    AutostartCommands::Generate => firewall::autostart_generate(),
                    AutostartCommands::Install => firewall::autostart_install(),
                    AutostartCommands::Uninstall => firewall::autostart_uninstall(),
                },
                FirewallCommands::Daemon => firewall::daemon_run_loop(),
            };

            if let Err(e) = res {
                eprintln!("{} {}", "ERROR:".red(), e);
                std::process::exit(1);
            }
        }
    }
}

async fn run_check(
    name: &str,
    r#type: Option<&str>,
    version: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    let ecosystem = if let Some(t) = r#type {
        Ecosystem::from_str(t).ok_or_else(|| anyhow::anyhow!("Invalid ecosystem type. Use 'npm', 'pypi', or 'cargo'"))?
    } else {
        Ecosystem::detect(&cwd).ok_or_else(|| {
            anyhow::anyhow!("Could not auto-detect ecosystem. Please specify --type")
        })?
    };

    println!("{} {} ({:?})", "Checking package:".green().bold(), name, ecosystem);

    let scan_path;
    let pkg_metadata;
    let mut is_temp = false;

    let local_path = std::path::Path::new(name);
    if local_path.exists() {
        println!("{} Found local path: {:?}", "INFO:".blue(), local_path);
        if local_path.is_file() {
            anyhow::bail!("Archives not supported in this version. Please extract and scan directory.");
        } else {
            scan_path = local_path.to_path_buf();
            pkg_metadata = fetcher::PackageMetadata {
                name: name.to_string(),
                version: "local".to_string(),
                published_at: None,
            };
        }
    } else {
        let fetcher = fetcher::Fetcher::new();
        let (path, metadata) = fetcher.download(name, version, &ecosystem).await?;
        println!(
            "{} Downloaded and extracted to {:?} (Version: {})",
            "SUCCESS:".green(),
            path,
            metadata.version
        );
        scan_path = path;
        pkg_metadata = metadata;
        is_temp = true;
    }

    let analyzer = analysis::Analyzer::new();
    let result = analyzer.scan(&scan_path, &pkg_metadata, &ecosystem).await?;
    report::Reporter::print_report(&result);
    if json {
        report::Reporter::generate_audit_json(&result);
    }

    if is_temp {
        if let Err(e) = std::fs::remove_dir_all(&scan_path) {
            println!("{} Failed to cleanup temp dir: {}", "WARN:".yellow(), e);
        }
    }

    if result.score < 50 {
        anyhow::bail!("Build failed due to critical security risks.");
    }

    Ok(())
}

async fn run_scan(path: Option<&str>) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let target_path = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cwd.join("package.json"));

    if !target_path.exists() {
        anyhow::bail!("Manifest file not found at: {:?}", target_path);
    }

    println!("{} Scanning manifest: {:?}", "INFO:".blue(), target_path);

    let filename = target_path.file_name().unwrap_or_default().to_string_lossy();
    let mut dependencies = Vec::new();

    if filename == "package.json" {
        let content = std::fs::read_to_string(&target_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        if let Some(deps) = json["dependencies"].as_object() {
            for (name, ver) in deps {
                let clean_ver = ver
                    .as_str()
                    .unwrap_or("latest")
                    .trim_start_matches('^')
                    .trim_start_matches('~');
                dependencies.push((name.to_string(), clean_ver.to_string(), Ecosystem::Npm));
            }
        }
        if let Some(deps) = json["devDependencies"].as_object() {
            for (name, ver) in deps {
                let clean_ver = ver
                    .as_str()
                    .unwrap_or("latest")
                    .trim_start_matches('^')
                    .trim_start_matches('~');
                dependencies.push((name.to_string(), clean_ver.to_string(), Ecosystem::Npm));
            }
        }
    } else if filename == "requirements.txt" {
        let content = std::fs::read_to_string(&target_path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split("==").collect();
            let name = parts[0].to_string();
            let ver = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                "latest".to_string()
            };
            dependencies.push((name, ver, Ecosystem::Pypi));
        }
    } else if filename == "Cargo.lock" {
        let deps = snapshot::parse_cargo_lock_file(&target_path)?;
        for dep in deps {
            dependencies.push((dep.name, dep.version, dep.ecosystem));
        }
    } else if filename == "Cargo.toml" {
        let deps = snapshot::parse_cargo_toml_file(&target_path)?;
        for dep in deps {
            dependencies.push((dep.name, dep.version, dep.ecosystem));
        }
    } else {
        anyhow::bail!("Unsupported manifest file: {}", filename);
    }

    println!("Found {} dependencies. Starting analysis...", dependencies.len());

    let fetcher = fetcher::Fetcher::new();
    let analyzer = analysis::Analyzer::new();

    for (name, ver, ecosystem) in dependencies {
        println!("--------------------------------------------------");
        let version_arg = match ver.as_str() {
            "latest" | "unspecified" => None,
            _ => Some(ver.as_str()),
        };
        let display_ver = version_arg.unwrap_or("latest");
        println!("Analyzing {}@{}...", name.blue().bold(), display_ver);

        match fetcher.download(&name, version_arg, &ecosystem).await {
            Ok((path, metadata)) => {
                match analyzer.scan(&path, &metadata, &ecosystem).await {
                    Ok(result) => {
                        let score_color = if result.score > 80 { "green" } else { "red" };
                        println!(
                            "Score: {} | Findings: {}",
                            result.score.to_string().color(score_color),
                            result.findings.len()
                        );
                        if result.score < 80 {
                            report::Reporter::print_report(&result);
                        }
                    }
                    Err(e) => println!("Analysis error: {}", e),
                }
                if let Err(e) = std::fs::remove_dir_all(&path) {
                    println!("{} Failed to cleanup temp dir: {}", "WARN:".yellow(), e);
                }
            }
            Err(e) => println!("Download failed: {}", e),
        }
    }

    Ok(())
}
