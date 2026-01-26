/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "depsentry")]
#[command(about = "A software supply chain security tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Generate audit.json report
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check a single package for security issues
    Check {
        /// Name of the package to check
        name: String,

        /// Ecosystem (npm, pypi, cargo). If not provided, autodetection is attempted.
        #[arg(long, short)]
        r#type: Option<String>,

        /// Specific version to check
        #[arg(long, short)]
        version: Option<String>,
    },
    /// Scan all dependencies in a manifest file (package.json / requirements.txt / Cargo.toml / Cargo.lock)
    Scan {
        /// Path to manifest file. Autodetected if not provided.
        #[arg(long, short)]
        path: Option<String>,
    },
    /// Firewall daemon and project supervision
    Firewall {
        #[command(subcommand)]
        command: FirewallCommands,
    },
}

#[derive(Subcommand)]
pub enum FirewallCommands {
    /// Start the firewall daemon
    Start,
    /// Stop the firewall daemon
    Stop,
    /// Restart the firewall daemon
    Restart,

    /// Add a project to supervision
    Add {
        /// Path to the project directory
        path: String,
    },
    /// Remove a project from supervision
    Rm {
        /// Project name
        name: String,
    },
    /// List supervised projects
    Ls,
    /// Show project status
    Status {
        /// Project name
        name: String,
    },
    /// Show logs (daemon.log or project log)
    Logs {
        /// Project name (omit for daemon logs)
        name: Option<String>,
        /// Number of lines to show
        #[arg(long, default_value_t = 200)]
        lines: usize,
    },

    /// Save a snapshot of projects
    Save,
    /// Restore saved snapshot
    Resurrect,
    /// Trigger a scan (stub in stage 0)
    Scan {
        /// Project name
        name: String,
        /// Force deep scan (stub)
        #[arg(long)]
        deep: bool,
        /// OSV/CVE only (stub)
        #[arg(long = "cve-only")]
        cve_only: bool,
    },

    /// Configure project settings
    Set {
        /// Project name
        name: String,
        /// CVE check interval (hours)
        #[arg(long = "cve-interval-hours")]
        cve_interval_hours: Option<u64>,
        /// Deep scan max packages per run
        #[arg(long = "deep-max-packages")]
        deep_max_packages: Option<usize>,
        /// Deep scan per-package timeout (seconds)
        #[arg(long = "deep-timeout-secs")]
        deep_timeout_secs: Option<u64>,
        /// Deep scan cache TTL (hours)
        #[arg(long = "deep-cache-ttl-hours")]
        deep_cache_ttl_hours: Option<i64>,
    },

    /// Configure webhook notifications
    Webhook {
        #[command(subcommand)]
        command: WebhookCommands,
    },

    /// Autostart helpers (generate/install/uninstall service/task)
    Autostart {
        #[command(subcommand)]
        command: AutostartCommands,
    },

    /// Internal: run daemon loop
    #[command(hide = true)]
    Daemon,
}

#[derive(Subcommand)]
pub enum WebhookCommands {
    /// Set webhook URL
    Set { url: String },
    /// Clear webhook URL
    Clear,
    /// Set dedup window in minutes
    SetDedupMinutes { minutes: u64 },
    /// Ignore vuln IDs (no alerts for these IDs)
    Ignore {
        #[command(subcommand)]
        command: WebhookIgnoreCommands,
    },
    /// Send a test notification
    Test,
}

#[derive(Subcommand)]
pub enum WebhookIgnoreCommands {
    /// Add ignored vuln id
    Add { id: String },
    /// Remove ignored vuln id
    Rm { id: String },
    /// List ignored vuln ids
    Ls,
}

#[derive(Subcommand)]
pub enum AutostartCommands {
    /// Generate autostart files under ~/.depsentry/firewall/autostart
    Generate,
    /// Attempt to install autostart (platform-specific)
    Install,
    /// Attempt to uninstall autostart (platform-specific)
    Uninstall,
}
