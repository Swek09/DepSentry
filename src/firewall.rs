use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;
use std::time::{Duration, SystemTime};
use tabled::{Table, Tabled};

use crate::snapshot::{DependencySnapshot};
use std::collections::BTreeMap;
use crate::osv::OsvReport;
use crate::snapshot::Dependency;

const HEARTBEAT_STALE_SECS: u64 = 15;
const DEBOUNCE_MS: u64 = 2000;
const PROJECTS_REFRESH_SECS: u64 = 2;
const DEFAULT_CVE_INTERVAL_HOURS: i64 = 12;
const OSV_GLOBAL_MIN_INTERVAL_SECS: u64 = 30;
const OSV_PROJECT_MIN_INTERVAL_MINS: i64 = 10;
const DEEP_SCAN_MAX_PACKAGES: usize = 25;
const DEFAULT_DEEP_TIMEOUT_SECS: u64 = 120;
const DEFAULT_DEEP_CACHE_TTL_HOURS: i64 = 24 * 14;
const AUTOSTART_TASK_NAME: &str = "DepSentryFirewall";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FirewallConfig {
    webhook_url: Option<String>,
    #[serde(default)]
    webhook_dedup_minutes: u64,
    #[serde(default)]
    webhook_ignore_vuln_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    pub path: PathBuf,
    pub added_at: DateTime<Utc>,
    #[serde(default)]
    pub last_snapshot: Option<SnapshotInfo>,
    #[serde(default)]
    pub last_vuln_scan: Option<VulnScanInfo>,
    #[serde(default)]
    pub open_alerts: usize,
    #[serde(default)]
    pub cve_interval_hours: Option<i64>,
    #[serde(default)]
    pub last_deep_scan: Option<DeepScanInfo>,
    #[serde(default)]
    pub deep_max_packages: Option<usize>,
    #[serde(default)]
    pub deep_timeout_secs: Option<u64>,
    #[serde(default)]
    pub deep_cache_ttl_hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub created_at: DateTime<Utc>,
    pub deps_count: usize,
    pub hash_blake3: String,
    pub files: Vec<String>,
    pub snapshot_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanInfo {
    pub created_at: DateTime<Utc>,
    pub input_hash: String,
    pub vulns_count: usize,
    pub new_ids: usize,
    pub changed_ids: usize,
    pub gone_ids: usize,
    pub report_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanInfo {
    pub created_at: DateTime<Utc>,
    pub changed_packages: usize,
    pub scanned_packages: usize,
    pub cache_hits: usize,
    pub errors: usize,
    pub high_or_critical: usize,
    pub report_path: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProjectsDb {
    projects: Vec<Project>,
}

#[derive(Tabled)]
struct ProjectRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Path")]
    path: String,
    #[tabled(rename = "Added")]
    added: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Last Snapshot")]
    last_snapshot: String,
    #[tabled(rename = "Alerts")]
    alerts: String,
    #[tabled(rename = "Next CVE")]
    next_cve: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DaemonState {
    started_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    projects: BTreeMap<String, ProjectRuntime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProjectRuntime {
    status: String, // idle | pending | running | error
    pending: bool,
    last_event_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    next_cve_check_at: Option<DateTime<Utc>>,
}

fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return Ok(PathBuf::from(profile));
        }
    }
    Err(anyhow!(
        "Could not determine home directory (HOME/USERPROFILE not set)"
    ))
}

pub fn firewall_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".depsentry").join("firewall"))
}

fn logs_dir() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("logs"))
}

fn projects_db_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("projects.db"))
}

fn pid_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("daemon.pid"))
}

fn stop_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("daemon.stop"))
}

fn heartbeat_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("daemon.heartbeat"))
}

fn daemon_log_path() -> Result<PathBuf> {
    Ok(logs_dir()?.join("daemon.log"))
}

fn project_log_path(name: &str) -> Result<PathBuf> {
    let safe = sanitize_name(name);
    Ok(logs_dir()?.join(format!("{safe}.log")))
}

fn snapshots_dir() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("snapshots"))
}

fn project_snapshots_dir(project: &str) -> Result<PathBuf> {
    Ok(snapshots_dir()?.join(sanitize_name(project)))
}

fn vulns_dir() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("vulns"))
}

fn project_vulns_dir(project: &str) -> Result<PathBuf> {
    Ok(vulns_dir()?.join(sanitize_name(project)))
}

fn deep_dir() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("deep"))
}

fn deep_cache_dir() -> Result<PathBuf> {
    Ok(deep_dir()?.join("cache"))
}

fn deep_reports_dir() -> Result<PathBuf> {
    Ok(deep_dir()?.join("reports"))
}

fn project_deep_reports_dir(project: &str) -> Result<PathBuf> {
    Ok(deep_reports_dir()?.join(sanitize_name(project)))
}

fn state_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("state.json"))
}

fn config_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("config.json"))
}

fn webhook_state_path() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("webhook_state.json"))
}

fn autostart_dir() -> Result<PathBuf> {
    Ok(firewall_dir()?.join("autostart"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirewallDump {
    version: u32,
    created_at: DateTime<Utc>,
    config: FirewallConfig,
    projects: Vec<Project>,
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}

pub fn ensure_layout() -> Result<()> {
    let fw = firewall_dir()?;
    fs::create_dir_all(&fw)?;
    fs::create_dir_all(logs_dir()?)?;
    fs::create_dir_all(snapshots_dir()?)?;
    fs::create_dir_all(vulns_dir()?)?;
    fs::create_dir_all(deep_cache_dir()?)?;
    fs::create_dir_all(deep_reports_dir()?)?;
    if !config_path()?.exists() {
        let mut cfg = FirewallConfig::default();
        cfg.webhook_dedup_minutes = 60;
        fs::write(config_path()?, serde_json::to_string_pretty(&cfg)?)?;
    }
    if !webhook_state_path()?.exists() {
        fs::write(webhook_state_path()?, "{}")?;
    }
    let db_path = projects_db_path()?;
    if !db_path.exists() {
        let json = serde_json::to_string_pretty(&ProjectsDb::default())?;
        fs::write(db_path, json)?;
    }
    Ok(())
}

fn load_db() -> Result<ProjectsDb> {
    ensure_layout()?;
    let path = projects_db_path()?;
    let content = fs::read_to_string(&path).unwrap_or_else(|_| "{\"projects\":[]}".to_string());
    let db: ProjectsDb = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(db)
}

fn load_project_by_name(name: &str) -> Result<Project> {
    let db = load_db()?;
    db.projects
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| anyhow!("project not found: {name}"))
}

fn save_db(db: &ProjectsDb) -> Result<()> {
    let path = projects_db_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(db)?;
    fs::write(&path, json)?;
    Ok(())
}

fn append_line(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

fn load_state() -> DaemonState {
    let path = match state_path() {
        Ok(p) => p,
        Err(_) => return DaemonState::default(),
    };
    let Ok(content) = fs::read_to_string(path) else {
        return DaemonState::default();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_state(state: &DaemonState) -> Result<()> {
    let path = state_path()?;
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)?;
    Ok(())
}

fn load_config() -> FirewallConfig {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return FirewallConfig::default(),
    };
    let Ok(content) = fs::read_to_string(path) else {
        return FirewallConfig::default();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_config(config: &FirewallConfig) -> Result<()> {
    ensure_layout()?;
    let path = config_path()?;
    fs::write(path, serde_json::to_string_pretty(config)?)?;
    Ok(())
}

pub fn webhook_set(url: &str) -> Result<()> {
    ensure_layout()?;
    let mut cfg = load_config();
    cfg.webhook_url = Some(url.to_string());
    if cfg.webhook_dedup_minutes == 0 {
        cfg.webhook_dedup_minutes = 60;
    }
    save_config(&cfg)?;
    println!("{}", "webhook configured".green());
    Ok(())
}

pub fn webhook_clear() -> Result<()> {
    ensure_layout()?;
    let mut cfg = load_config();
    cfg.webhook_url = None;
    save_config(&cfg)?;
    println!("{}", "webhook cleared".green());
    Ok(())
}

pub fn webhook_set_dedup_minutes(minutes: u64) -> Result<()> {
    ensure_layout()?;
    let mut cfg = load_config();
    cfg.webhook_dedup_minutes = minutes.max(1);
    save_config(&cfg)?;
    println!("{}", format!("webhook dedup minutes set to {}", cfg.webhook_dedup_minutes).green());
    Ok(())
}

pub fn webhook_ignore_add(id: &str) -> Result<()> {
    ensure_layout()?;
    let mut cfg = load_config();
    if !cfg.webhook_ignore_vuln_ids.iter().any(|x| x == id) {
        cfg.webhook_ignore_vuln_ids.push(id.to_string());
        cfg.webhook_ignore_vuln_ids.sort();
        cfg.webhook_ignore_vuln_ids.dedup();
        save_config(&cfg)?;
    }
    println!("{}", "added to ignore list".green());
    Ok(())
}

pub fn webhook_ignore_rm(id: &str) -> Result<()> {
    ensure_layout()?;
    let mut cfg = load_config();
    cfg.webhook_ignore_vuln_ids.retain(|x| x != id);
    save_config(&cfg)?;
    println!("{}", "removed from ignore list".green());
    Ok(())
}

pub fn webhook_ignore_ls() -> Result<()> {
    ensure_layout()?;
    let cfg = load_config();
    if cfg.webhook_ignore_vuln_ids.is_empty() {
        println!("{}", "ignore list is empty".yellow());
        return Ok(());
    }
    for id in cfg.webhook_ignore_vuln_ids {
        println!("{id}");
    }
    Ok(())
}

pub fn webhook_test() -> Result<()> {
    ensure_layout()?;
    notify_webhook(
        "test",
        "DepSentry firewall webhook test",
        serde_json::json!({ "type": "test" }),
    )
}

fn notify_webhook(event_type: &str, message: &str, payload: serde_json::Value) -> Result<()> {
    let cfg = load_config();
    let Some(url) = cfg.webhook_url else {
        return Ok(());
    };
    let dedup_minutes = cfg.webhook_dedup_minutes.max(1);
    let dedup_key = format!("{event_type}:{}", blake3::hash(message.as_bytes()).to_hex());
    if should_dedup_webhook(&dedup_key, dedup_minutes) {
        return Ok(());
    }

    // Slack-compatible basic body + payload for custom consumers
    let body = serde_json::json!({
        "text": message,
        "depsentry": {
            "event": event_type,
            "payload": payload,
        }
    });

    let client = reqwest::blocking::Client::builder()
        .user_agent("depsentry-firewall/0.2.0")
        .build()
        .context("Failed to create webhook client")?;
    client
        .post(url)
        .json(&body)
        .send()
        .context("Failed to send webhook")?
        .error_for_status()
        .context("Webhook returned error status")?;

    mark_webhook_sent(&dedup_key).ok();
    Ok(())
}

fn should_dedup_webhook(key: &str, dedup_minutes: u64) -> bool {
    let Ok(path) = webhook_state_path() else { return false };
    let Ok(content) = fs::read_to_string(&path) else { return false };
    let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(&content) else { return false };
    let Some(ts) = map.get(key) else { return false };
    let Some(dt) = chrono::DateTime::parse_from_rfc3339(ts).ok() else { return false };
    let dt = dt.with_timezone(&Utc);
    let age = Utc::now() - dt;
    age < chrono::Duration::minutes(dedup_minutes as i64)
}

fn mark_webhook_sent(key: &str) -> Result<()> {
    let path = webhook_state_path()?;
    let content = fs::read_to_string(&path).unwrap_or_else(|_| "{}".to_string());
    let mut map = serde_json::from_str::<BTreeMap<String, String>>(&content).unwrap_or_default();
    map.insert(key.to_string(), Utc::now().to_rfc3339());
    // prune: keep only last 500 keys
    if map.len() > 500 {
        let mut keys: Vec<_> = map.keys().cloned().collect();
        keys.sort();
        for k in keys.into_iter().take(map.len() - 500) {
            map.remove(&k);
        }
    }
    fs::write(&path, serde_json::to_string_pretty(&map)?)?;
    Ok(())
}

pub fn is_daemon_running() -> Result<bool> {
    let hb = heartbeat_path()?;
    if !hb.exists() {
        return Ok(pid_path()?.exists());
    }
    let meta = fs::metadata(&hb)?;
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::from_secs(u64::MAX));
    Ok(age.as_secs() < HEARTBEAT_STALE_SECS)
}

pub fn daemon_start() -> Result<()> {
    ensure_layout()?;

    if is_daemon_running()? {
        println!("{}", "firewall daemon already running".green());
        return Ok(());
    }

    let exe = std::env::current_exe().context("Failed to locate current executable")?;
    let log_path = daemon_log_path()?;
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open {}", log_path.display()))?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("firewall").arg("daemon");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(log_file.try_clone()?);
    cmd.stderr(log_file);

    let child = cmd.spawn().context("Failed to spawn firewall daemon")?;
    fs::write(pid_path()?, child.id().to_string())?;

    println!(
        "{} pid={} log={}",
        "firewall daemon started".green(),
        child.id(),
        daemon_log_path()?.display()
    );
    Ok(())
}

pub fn daemon_stop() -> Result<()> {
    ensure_layout()?;

    if !pid_path()?.exists() && !heartbeat_path()?.exists() {
        println!("{}", "firewall daemon not running".yellow());
        let _ = fs::remove_file(pid_path()?);
        return Ok(());
    }

    fs::write(stop_path()?, "stop")?;
    let pid_file = pid_path()?;

    let deadline = SystemTime::now() + Duration::from_secs(10);
    while SystemTime::now() < deadline {
        if !pid_file.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = fs::remove_file(stop_path()?);
    let _ = fs::remove_file(pid_path()?);
    println!("{}", "firewall daemon stopped".green());
    Ok(())
}

pub fn daemon_restart() -> Result<()> {
    let _ = daemon_stop();
    daemon_start()
}

pub fn daemon_run_loop() -> Result<()> {
    ensure_layout()?;

    let pid = std::process::id();
    fs::write(pid_path()?, pid.to_string())?;
    append_line(
        &daemon_log_path()?,
        &format!("[{}] daemon started pid={}", Utc::now().to_rfc3339(), pid),
    )?;

    let mut state = load_state();
    state.started_at = Some(Utc::now());
    state.last_heartbeat_at = Some(Utc::now());
    save_state(&state).ok();

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        notify::Config::default(),
    )
    .context("Failed to create filesystem watcher")?;

    let mut projects = load_db().unwrap_or_default().projects;
    for p in &projects {
        let watch_root = strip_verbatim_prefix_path(&p.path);
        let _ = watcher.watch(&watch_root, RecursiveMode::NonRecursive);
        state.projects.entry(p.name.clone()).or_insert_with(|| ProjectRuntime {
            status: "idle".to_string(),
            pending: false,
            last_event_at: None,
            last_run_at: None,
            last_error: None,
            next_cve_check_at: compute_next_cve_check_at(p, None),
        });
    }
    save_state(&state).ok();

    let mut last_projects_refresh = Instant::now();
    let mut pending_deadlines: BTreeMap<String, Instant> = BTreeMap::new();
    let mut last_osv_call: Option<Instant> = None;

    loop {
        fs::write(heartbeat_path()?, Utc::now().to_rfc3339())?;
        state.last_heartbeat_at = Some(Utc::now());
        save_state(&state).ok();

        if stop_path()?.exists() {
            append_line(
                &daemon_log_path()?,
                &format!("[{}] stop requested", Utc::now().to_rfc3339()),
            )?;
            break;
        }

        // Refresh project list periodically (simple approach)
        if last_projects_refresh.elapsed() > Duration::from_secs(PROJECTS_REFRESH_SECS) {
            let new_projects = load_db().unwrap_or_default().projects;
            for p in &new_projects {
                if projects.iter().all(|old| old.name != p.name) {
                    let watch_root = strip_verbatim_prefix_path(&p.path);
                    let _ = watcher.watch(&watch_root, RecursiveMode::NonRecursive);
                }
                state.projects.entry(p.name.clone()).or_insert_with(|| ProjectRuntime {
                    status: "idle".to_string(),
                    pending: false,
                    last_event_at: None,
                    last_run_at: None,
                    last_error: None,
                    next_cve_check_at: compute_next_cve_check_at(p, None),
                });
            }
            projects = new_projects;
            last_projects_refresh = Instant::now();
            save_state(&state).ok();
        }

        // Drain watcher events
        while let Ok(res) = rx.try_recv() {
            if let Ok(event) = res {
                for path in event.paths {
                    if let Some((proj_name, filename)) = match_event_to_project(&projects, &path) {
                        if is_dependency_file(&filename) {
                            let deadline = Instant::now() + Duration::from_millis(DEBOUNCE_MS);
                            pending_deadlines.insert(proj_name.clone(), deadline);

                            let rt = state.projects.entry(proj_name.clone()).or_default();
                            rt.pending = true;
                            rt.status = "pending".to_string();
                            rt.last_event_at = Some(Utc::now());
                            rt.last_error = None;

                            append_line(
                                &daemon_log_path()?,
                                &format!(
                                    "[{}] change detected project={} file={}",
                                    Utc::now().to_rfc3339(),
                                    proj_name,
                                    filename
                                ),
                            )
                            .ok();
                        }
                    }
                }
            }
        }

        // Execute due scans (snapshot only)
        let now = Instant::now();
        let due: Vec<String> = pending_deadlines
            .iter()
            .filter(|(_k, v)| **v <= now)
            .map(|(k, _v)| k.clone())
            .collect();

        for proj_name in due {
            pending_deadlines.remove(&proj_name);
            let project = match load_project_by_name(&proj_name) {
                Ok(p) => p,
                Err(_) => continue,
            };

            {
                let rt = state.projects.entry(proj_name.clone()).or_default();
                rt.status = "running".to_string();
                rt.pending = false;
                rt.last_error = None;
            }
            save_state(&state).ok();

            let result = run_snapshot_for_project(&project);
            match result {
                Ok((prev_snapshot, snapshot, info)) => {
                    if let Some(rt) = state.projects.get_mut(&proj_name) {
                        rt.status = "idle".to_string();
                        rt.last_run_at = Some(Utc::now());
                        rt.last_error = None;
                    }
                    append_line(
                        &daemon_log_path()?,
                        &format!(
                            "[{}] snapshot ok project={} deps={} hash={}",
                            Utc::now().to_rfc3339(),
                            proj_name,
                            info.deps_count,
                            info.hash_blake3
                        ),
                    )
                    .ok();

                    // Stage 5: deep scan on lockfile changes (diff only)
                    let deep_res = run_deep_scan_for_snapshot(&project, prev_snapshot.as_ref(), &snapshot);
                    match deep_res {
                        Ok(d) => {
                            append_line(
                                &daemon_log_path()?,
                                &format!(
                                    "[{}] deep ok project={} changed={} scanned={} cache_hits={} high_or_critical={}",
                                    Utc::now().to_rfc3339(),
                                    proj_name,
                                    d.changed_packages,
                                    d.scanned_packages,
                                    d.cache_hits,
                                    d.high_or_critical
                                ),
                            )
                            .ok();
                        }
                        Err(e) => {
                            append_line(
                                &daemon_log_path()?,
                                &format!(
                                    "[{}] deep error project={} err={}",
                                    Utc::now().to_rfc3339(),
                                    proj_name,
                                    e
                                ),
                            )
                            .ok();
                        }
                    }
                }
                Err(e) => {
                    if let Some(rt) = state.projects.get_mut(&proj_name) {
                        rt.status = "error".to_string();
                        rt.last_run_at = Some(Utc::now());
                        rt.last_error = Some(e.to_string());
                    }
                    append_line(
                        &daemon_log_path()?,
                        &format!(
                            "[{}] snapshot error project={} err={}",
                            Utc::now().to_rfc3339(),
                            proj_name,
                            e
                        ),
                    )
                    .ok();
                }
            }
            save_state(&state).ok();
        }

        // Scheduler: periodic CVE-only checks even without file changes
        let now_utc = Utc::now();
        for p in &projects {
            let current_status = state
                .projects
                .get(&p.name)
                .map(|r| r.status.clone())
                .unwrap_or_else(|| "unknown".to_string());
            if current_status == "running" {
                continue;
            }

            if state
                .projects
                .get(&p.name)
                .and_then(|r| r.next_cve_check_at)
                .is_none()
            {
                {
                    let rt = state.projects.entry(p.name.clone()).or_default();
                    rt.next_cve_check_at = compute_next_cve_check_at(p, Some(now_utc));
                }
                save_state(&state).ok();
            }

            let Some(next_at) = state.projects.get(&p.name).and_then(|r| r.next_cve_check_at) else {
                continue;
            };
            if next_at > now_utc {
                continue;
            }

            // Global rate limit
            if let Some(last) = last_osv_call {
                if last.elapsed() < Duration::from_secs(OSV_GLOBAL_MIN_INTERVAL_SECS) {
                    break;
                }
            }

            // Per-project throttle (avoid repeated OSV calls if schedule jitter)
            if let Some(last_scan) = &p.last_vuln_scan {
                if now_utc - last_scan.created_at < chrono::Duration::minutes(OSV_PROJECT_MIN_INTERVAL_MINS) {
                    {
                        let rt = state.projects.entry(p.name.clone()).or_default();
                        rt.next_cve_check_at =
                            compute_next_cve_check_at(p, Some(now_utc + chrono::Duration::minutes(1)));
                    }
                    save_state(&state).ok();
                    continue;
                }
            }

            {
                let rt = state.projects.entry(p.name.clone()).or_default();
                rt.status = "running".to_string();
                rt.last_error = None;
            }
            save_state(&state).ok();

            let res = scheduled_cve_check(p);
            match res {
                Ok((vulns_count, new_ids, changed_ids, gone_ids)) => {
                    if let Some(rt) = state.projects.get_mut(&p.name) {
                        rt.status = "idle".to_string();
                        rt.last_run_at = Some(Utc::now());
                        rt.last_error = None;
                    }
                    append_line(
                        &daemon_log_path()?,
                        &format!(
                            "[{}] scheduled cve ok project={} vulns={} new={} changed={} gone={}",
                            Utc::now().to_rfc3339(),
                            p.name,
                            vulns_count,
                            new_ids,
                            changed_ids,
                            gone_ids
                        ),
                    )
                    .ok();
                }
                Err(e) => {
                    if let Some(rt) = state.projects.get_mut(&p.name) {
                        rt.status = "error".to_string();
                        rt.last_run_at = Some(Utc::now());
                        rt.last_error = Some(e.to_string());
                    }
                    append_line(
                        &daemon_log_path()?,
                        &format!(
                            "[{}] scheduled cve error project={} err={}",
                            Utc::now().to_rfc3339(),
                            p.name,
                            e
                        ),
                    )
                    .ok();
                }
            }
            last_osv_call = Some(Instant::now());
            if let Some(rt) = state.projects.get_mut(&p.name) {
                rt.next_cve_check_at = compute_next_cve_check_at(p, Some(Utc::now()));
            }
            save_state(&state).ok();
            break; // one scheduled CVE per loop
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    let _ = fs::remove_file(heartbeat_path()?);
    let _ = fs::remove_file(pid_path()?);
    append_line(
        &daemon_log_path()?,
        &format!("[{}] daemon exited", Utc::now().to_rfc3339()),
    )?;
    Ok(())
}

pub fn project_add(path: &str) -> Result<()> {
    ensure_layout()?;
    let p = shellexpand_home(path)?;
    let p = canonicalize_for_storage(&p).unwrap_or(p);

    if !p.exists() || !p.is_dir() {
        return Err(anyhow!("Project path not found or not a directory: {}", p.display()));
    }

    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "project".to_string());

    let mut db = load_db()?;
    if db.projects.iter().any(|proj| proj.name == name) {
        println!("{}", format!("project already exists: {name}").yellow());
        return Ok(());
    }

    db.projects.push(Project {
        name: name.clone(),
        path: p.clone(),
        added_at: Utc::now(),
        last_snapshot: None,
        last_vuln_scan: None,
        open_alerts: 0,
        cve_interval_hours: None,
        last_deep_scan: None,
        deep_max_packages: None,
        deep_timeout_secs: None,
        deep_cache_ttl_hours: None,
    });
    save_db(&db)?;

    append_line(
        &daemon_log_path()?,
        &format!("[{}] added project {} -> {}", Utc::now().to_rfc3339(), name, p.display()),
    )?;
    append_line(
        &project_log_path(&name)?,
        &format!("[{}] added path={}", Utc::now().to_rfc3339(), p.display()),
    )?;

    println!("{}", format!("added {name}").green());
    Ok(())
}

pub fn project_rm(name: &str) -> Result<()> {
    ensure_layout()?;
    let mut db = load_db()?;
    let before = db.projects.len();
    db.projects.retain(|p| p.name != name);
    if db.projects.len() == before {
        println!("{}", format!("project not found: {name}").yellow());
        return Ok(());
    }
    save_db(&db)?;
    append_line(
        &daemon_log_path()?,
        &format!("[{}] removed project {}", Utc::now().to_rfc3339(), name),
    )?;
    append_line(
        &project_log_path(name)?,
        &format!("[{}] removed", Utc::now().to_rfc3339()),
    )?;
    println!("{}", format!("removed {name}").green());
    Ok(())
}

pub fn project_ls() -> Result<()> {
    ensure_layout()?;
    let db = load_db()?;
    if db.projects.is_empty() {
        println!("{}", "no projects".yellow());
        return Ok(());
    }
    let state = load_state();
    let rows: Vec<ProjectRow> = db.projects.iter().map(|p| {
        let rt = state.projects.get(&p.name);
        let status = rt.map(|r| r.status.clone()).unwrap_or_else(|| "unknown".to_string());
        let last_snapshot = p
            .last_snapshot
            .as_ref()
            .map(|s| s.created_at.to_rfc3339())
            .unwrap_or_else(|| "-".to_string());
        let alerts = if p.open_alerts > 0 {
            p.open_alerts.to_string()
        } else {
            "-".to_string()
        };
        let next_cve = rt
            .and_then(|r| r.next_cve_check_at)
            .or_else(|| compute_next_cve_check_at(p, Some(Utc::now())))
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "-".to_string());
        ProjectRow {
            name: p.name.clone(),
            path: p.path.display().to_string(),
            added: p.added_at.to_rfc3339(),
            status,
            last_snapshot,
            alerts,
            next_cve,
        }
    }).collect();
    println!("{}", Table::new(rows));
    Ok(())
}

pub fn project_status(name: &str) -> Result<()> {
    ensure_layout()?;
    let db = load_db()?;
    let proj = db
        .projects
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| anyhow!("project not found: {name}"))?;

    let running = is_daemon_running().unwrap_or(false);
    let daemon = if running { "running".green() } else { "stopped".red() };

    println!("Project: {}", proj.name.bold());
    println!("Path: {}", proj.path.display());
    println!("Daemon: {}", daemon);
    match &proj.last_snapshot {
        Some(s) => {
            println!("Last snapshot: {}", s.created_at.to_rfc3339());
            println!("Deps: {}", s.deps_count);
            println!("Hash: {}", s.hash_blake3);
            println!("Files: {}", s.files.join(", "));
        }
        None => {
            println!("Last snapshot: {}", "-".yellow());
        }
    }
    if let Some(v) = &proj.last_vuln_scan {
        println!("Vulns: {}", proj.open_alerts);
        println!("Last CVE scan: {}", v.created_at.to_rfc3339());
        println!(
            "Diff: new={} changed={} gone={}",
            v.new_ids, v.changed_ids, v.gone_ids
        );
        println!("Report: {}", v.report_path);
    }
    let state = load_state();
    if let Some(rt) = state.projects.get(&proj.name) {
        println!("Status: {}", rt.status.clone());
        if rt.pending {
            println!("Pending: {}", "yes".yellow());
        }
        if let Some(t) = rt.last_event_at {
            println!("Last change: {}", t.to_rfc3339());
        }
        if let Some(t) = rt.last_run_at {
            println!("Last run: {}", t.to_rfc3339());
        }
        if let Some(err) = &rt.last_error {
            println!("Last error: {}", err.red());
        }
        if let Some(next) = rt.next_cve_check_at {
            println!("Next CVE check: {}", next.to_rfc3339());
        }
    } else if let Some(next) = compute_next_cve_check_at(proj, Some(Utc::now())) {
        println!("Next CVE check: {}", next.to_rfc3339());
    }
    println!("Log: {}", project_log_path(&proj.name)?.display());
    Ok(())
}

pub fn show_logs(name: Option<String>, lines: usize) -> Result<()> {
    ensure_layout()?;
    let path = match name.as_deref() {
        Some(project) => project_log_path(project)?,
        None => daemon_log_path()?,
    };

    if !path.exists() {
        println!("{}", format!("log not found: {}", path.display()).yellow());
        return Ok(());
    }

    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut all: Vec<&str> = content.lines().collect();
    if all.len() > lines {
        all = all[all.len() - lines..].to_vec();
    }

    println!(
        "{} {} (last {} lines)\n{}",
        "==>".blue(),
        path.display(),
        lines,
        all.join("\n")
    );
    Ok(())
}

pub fn snapshot_save() -> Result<()> {
    ensure_layout()?;
    let dump_path = firewall_dir()?.join("firewall.dump.json");
    let db = load_db()?;
    let dump = FirewallDump {
        version: 1,
        created_at: Utc::now(),
        config: load_config(),
        projects: db.projects,
    };
    fs::write(&dump_path, serde_json::to_string_pretty(&dump)?)?;
    println!("{}", format!("saved snapshot to {}", dump_path.display()).green());
    Ok(())
}

pub fn snapshot_resurrect() -> Result<()> {
    ensure_layout()?;
    let dump_path = firewall_dir()?.join("firewall.dump.json");
    if !dump_path.exists() {
        return Err(anyhow!("snapshot not found: {}", dump_path.display()));
    }
    let content = fs::read_to_string(&dump_path)?;

    // Backward compatible: either FirewallDump or ProjectsDb-like JSON
    if let Ok(dump) = serde_json::from_str::<FirewallDump>(&content) {
        save_config(&dump.config).ok();
        save_db(&ProjectsDb { projects: dump.projects })?;
        println!("{}", format!("restored snapshot from {}", dump_path.display()).green());
        return Ok(());
    }
    if let Ok(db) = serde_json::from_str::<ProjectsDb>(&content) {
        save_db(&db)?;
        println!("{}", format!("restored snapshot from {}", dump_path.display()).green());
        return Ok(());
    }

    Err(anyhow!("Unsupported snapshot format: {}", dump_path.display()))
}

pub fn autostart_generate() -> Result<()> {
    ensure_layout()?;
    let dir = autostart_dir()?;
    fs::create_dir_all(&dir)?;

    let exe = std::env::current_exe().context("Failed to locate current executable")?;

    #[cfg(target_os = "linux")]
    {
        let content = format!(
            r#"[Unit]
Description=DepSentry Firewall
After=network-online.target

[Service]
Type=simple
ExecStart="{}" {}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"#,
            exe.display(),
            "firewall daemon"
        );
        let path = dir.join("depsentry-firewall.service");
        fs::write(&path, content)?;
        fs::write(
            dir.join("INSTALL-linux.txt"),
            format!(
                "Copy to ~/.config/systemd/user/depsentry-firewall.service then run:\n  systemctl --user daemon-reload\n  systemctl --user enable --now depsentry-firewall.service\n\nUninstall:\n  systemctl --user disable --now depsentry-firewall.service\n  rm ~/.config/systemd/user/depsentry-firewall.service\n"
            ),
        )?;
    }

    #[cfg(target_os = "macos")]
    {
        let label = "com.depsentry.firewall";
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>{label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{exe}</string>
      <string>firewall</string>
      <string>daemon</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{log}</string>
    <key>StandardErrorPath</key><string>{log}</string>
  </dict>
</plist>
"#,
            exe = exe.display(),
            log = daemon_log_path()?.display(),
        );
        let path = dir.join("com.depsentry.firewall.plist");
        fs::write(&path, content)?;
        fs::write(
            dir.join("INSTALL-macos.txt"),
            "Copy to ~/Library/LaunchAgents/com.depsentry.firewall.plist then run:\n  launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.depsentry.firewall.plist\n\nUninstall:\n  launchctl bootout gui/$UID ~/Library/LaunchAgents/com.depsentry.firewall.plist\n  rm ~/Library/LaunchAgents/com.depsentry.firewall.plist\n",
        )?;
    }

    #[cfg(windows)]
    {
        let cmd = format!(
            "@echo off\r\n\"{}\" firewall daemon\r\n",
            exe.display()
        );
        let cmd_path = dir.join("depsentry-firewall.cmd");
        fs::write(&cmd_path, cmd)?;

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Name>{name}</Name></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{cmd}</Command>
    </Exec>
  </Actions>
</Task>
"#,
            name = AUTOSTART_TASK_NAME,
            cmd = cmd_path.display()
        );
        let xml_path = dir.join("depsentry-firewall-task.xml");
        fs::write(&xml_path, xml)?;
        fs::write(
            dir.join("INSTALL-windows.txt"),
            format!(
                "Run:\n  schtasks /Create /TN {name} /XML \"{xml}\" /F\n\nUninstall:\n  schtasks /Delete /TN {name} /F\n",
                name = AUTOSTART_TASK_NAME,
                xml = xml_path.display()
            ),
        )?;
    }

    println!("{}", format!("autostart files generated in {}", dir.display()).green());
    Ok(())
}

pub fn autostart_install() -> Result<()> {
    ensure_layout()?;
    autostart_generate().ok();
    let dir = autostart_dir()?;

    #[cfg(windows)]
    {
        let xml = dir.join("depsentry-firewall-task.xml");
        if !xml.exists() {
            return Err(anyhow!("Missing {}", xml.display()));
        }
        let status = std::process::Command::new("schtasks")
            .args(["/Create", "/TN", AUTOSTART_TASK_NAME, "/XML"])
            .arg(&xml)
            .args(["/F"])
            .status()
            .context("Failed to run schtasks")?;
        if !status.success() {
            return Err(anyhow!("schtasks exited with {}", status));
        }
        println!("{}", "autostart installed (scheduled task)".green());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let service_src = dir.join("depsentry-firewall.service");
        if !service_src.exists() {
            return Err(anyhow!("Missing {}", service_src.display()));
        }
        let target = home_dir()?.join(".config").join("systemd").join("user");
        fs::create_dir_all(&target)?;
        let service_dst = target.join("depsentry-firewall.service");
        fs::copy(&service_src, &service_dst)?;
        let status = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .context("Failed to run systemctl")?;
        if !status.success() {
            return Err(anyhow!("systemctl daemon-reload failed"));
        }
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "depsentry-firewall.service"])
            .status()
            .context("Failed to run systemctl")?;
        if !status.success() {
            return Err(anyhow!("systemctl enable failed"));
        }
        println!("{}", "autostart installed (systemd --user)".green());
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let plist_src = dir.join("com.depsentry.firewall.plist");
        if !plist_src.exists() {
            return Err(anyhow!("Missing {}", plist_src.display()));
        }
        let dst = home_dir()?.join("Library").join("LaunchAgents");
        fs::create_dir_all(&dst)?;
        let plist_dst = dst.join("com.depsentry.firewall.plist");
        fs::copy(&plist_src, &plist_dst)?;
        let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
        let status = std::process::Command::new("launchctl")
            .args(["bootstrap", &format!("gui/{}", uid)])
            .arg(&plist_dst)
            .status()
            .context("Failed to run launchctl")?;
        if !status.success() {
            return Err(anyhow!("launchctl bootstrap failed"));
        }
        println!("{}", "autostart installed (launchd)".green());
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn autostart_uninstall() -> Result<()> {
    ensure_layout()?;

    #[cfg(windows)]
    {
        let status = std::process::Command::new("schtasks")
            .args(["/Delete", "/TN", AUTOSTART_TASK_NAME, "/F"])
            .status()
            .context("Failed to run schtasks")?;
        if !status.success() {
            return Err(anyhow!("schtasks exited with {}", status));
        }
        println!("{}", "autostart uninstalled (scheduled task)".green());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "depsentry-firewall.service"])
            .status();
        let service_dst = home_dir()?
            .join(".config")
            .join("systemd")
            .join("user")
            .join("depsentry-firewall.service");
        let _ = fs::remove_file(service_dst);
        println!("{}", "autostart uninstalled (systemd --user)".green());
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_string());
        let plist_dst = home_dir()?
            .join("Library")
            .join("LaunchAgents")
            .join("com.depsentry.firewall.plist");
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{}", uid)])
            .arg(&plist_dst)
            .status();
        let _ = fs::remove_file(plist_dst);
        println!("{}", "autostart uninstalled (launchd)".green());
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn scan_project(name: &str, deep: bool, cve_only: bool) -> Result<()> {
    ensure_layout()?;
    let proj = load_project_by_name(name)?;

    if deep {
        // ok
    }

    let (prev_snapshot, snapshot, info) = run_snapshot_for_project(&proj)?;
    let vuln_info = if cve_only {
        Some(run_vuln_scan_for_snapshot(&proj, &snapshot)?)
    } else {
        None
    };
    let deep_info = if deep {
        Some(run_deep_scan_for_snapshot(&proj, prev_snapshot.as_ref(), &snapshot)?)
    } else {
        None
    };

    let mode = if cve_only {
        "--cve-only"
    } else if deep {
        "--deep"
    } else {
        "(default)"
    };

    append_line(
        &daemon_log_path()?,
        &format!(
            "[{}] snapshot created project={} mode={} deps={} hash={}",
            Utc::now().to_rfc3339(),
            name,
            mode,
            info.deps_count,
            info.hash_blake3
        ),
    )?;
    append_line(
        &project_log_path(name)?,
        &format!(
            "[{}] snapshot created mode={} deps={} hash={} file={}",
            Utc::now().to_rfc3339(),
            mode,
            info.deps_count,
            info.hash_blake3,
            info.snapshot_path
        ),
    )?;

    println!(
        "{} {} {} deps={} hash={}",
        "snapshot created for".green(),
        name.bold(),
        mode.yellow(),
        info.deps_count,
        info.hash_blake3
    );
    println!("Saved: {}", info.snapshot_path);
    println!("Files: {}", info.files.join(", "));
    if let Some(v) = vuln_info {
        println!(
            "{} vulns={} (new={} changed={} gone={})",
            "cve-only scan complete:".green(),
            v.vulns_count,
            v.new_ids,
            v.changed_ids,
            v.gone_ids
        );
        println!("Report: {}", v.report_path);
    }
    if let Some(d) = deep_info {
        println!(
            "{} changed={} scanned={} cache_hits={} high_or_critical={} report={}",
            "deep scan complete:".green(),
            d.changed_packages,
            d.scanned_packages,
            d.cache_hits,
            d.high_or_critical,
            d.report_path
        );
    }
    Ok(())
}

fn shellexpand_home(input: &str) -> Result<PathBuf> {
    let trimmed = input.trim();
    if trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        let rel = trimmed.trim_start_matches("~").trim_start_matches(['/', '\\']);
        return Ok(home_dir()?.join(rel));
    }
    Ok(PathBuf::from(trimmed))
}

fn save_snapshot_file(snapshot: &DependencySnapshot) -> Result<PathBuf> {
    let dir = project_snapshots_dir(&snapshot.project)?;
    fs::create_dir_all(&dir)?;
    let ts = snapshot.created_at.format("%Y%m%d-%H%M%S").to_string();
    let path = dir.join(format!("snapshot-{ts}.json"));
    let json = serde_json::to_string_pretty(snapshot)?;
    fs::write(&path, json)?;
    Ok(path)
}

fn update_project_last_snapshot(project: &str, snapshot: &DependencySnapshot, saved_path: &Path) -> Result<()> {
    let mut db = load_db()?;
    let Some(p) = db.projects.iter_mut().find(|p| p.name == project) else {
        return Ok(());
    };
    p.last_snapshot = Some(SnapshotInfo {
        created_at: snapshot.created_at,
        deps_count: snapshot.dependencies.len(),
        hash_blake3: snapshot.hash_blake3.clone(),
        files: snapshot.files.clone(),
        snapshot_path: saved_path.display().to_string(),
    });
    save_db(&db)?;
    Ok(())
}

fn run_snapshot_for_project(project: &Project) -> Result<(Option<DependencySnapshot>, DependencySnapshot, SnapshotInfo)> {
    let prev_snapshot = project
        .last_snapshot
        .as_ref()
        .and_then(|s| fs::read_to_string(&s.snapshot_path).ok())
        .and_then(|c| serde_json::from_str::<DependencySnapshot>(&c).ok());

    let snapshot = crate::snapshot::build_snapshot(&project.name, &project.path)?;
    let saved_path = save_snapshot_file(&snapshot)?;
    update_project_last_snapshot(&project.name, &snapshot, &saved_path)?;
    let info = SnapshotInfo {
        created_at: snapshot.created_at,
        deps_count: snapshot.dependencies.len(),
        hash_blake3: snapshot.hash_blake3.clone(),
        files: snapshot.files.clone(),
        snapshot_path: saved_path.display().to_string(),
    };
    Ok((prev_snapshot, snapshot, info))
}

pub fn project_set(
    name: &str,
    cve_interval_hours: Option<u64>,
    deep_max_packages: Option<usize>,
    deep_timeout_secs: Option<u64>,
    deep_cache_ttl_hours: Option<i64>,
) -> Result<()> {
    ensure_layout()?;
    let mut db = load_db()?;
    let idx = db
        .projects
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| anyhow!("project not found: {name}"))?;

    if let Some(h) = cve_interval_hours {
        db.projects[idx].cve_interval_hours = Some(h as i64);
        println!("{}", format!("updated {name}: cve_interval_hours={h}").green());
    }
    if let Some(v) = deep_max_packages {
        db.projects[idx].deep_max_packages = Some(v.max(1));
        println!("{}", format!("updated {name}: deep_max_packages={}", v.max(1)).green());
    }
    if let Some(v) = deep_timeout_secs {
        db.projects[idx].deep_timeout_secs = Some(v.max(5));
        println!("{}", format!("updated {name}: deep_timeout_secs={}", v.max(5)).green());
    }
    if let Some(v) = deep_cache_ttl_hours {
        db.projects[idx].deep_cache_ttl_hours = Some(v.max(1));
        println!("{}", format!("updated {name}: deep_cache_ttl_hours={}", v.max(1)).green());
    }

    if cve_interval_hours.is_none()
        && deep_max_packages.is_none()
        && deep_timeout_secs.is_none()
        && deep_cache_ttl_hours.is_none()
    {
        println!("{}", "no changes".yellow());
    }
    let project = db.projects[idx].clone();
    save_db(&db)?;

    // If daemon is running, update runtime schedule immediately.
    let mut state = load_state();
    if let Some(rt) = state.projects.get_mut(name) {
        rt.next_cve_check_at = compute_next_cve_check_at(&project, Some(Utc::now()));
        save_state(&state).ok();
    }
    Ok(())
}

fn is_dependency_file(filename: &str) -> bool {
    let f = filename.to_lowercase();
    if f == "package-lock.json"
        || f == "pnpm-lock.yaml"
        || f == "yarn.lock"
        || f == "poetry.lock"
        || f == "cargo.lock"
        || f == "cargo.toml"
        || f == "package.json"
        || f == "pyproject.toml"
    {
        return true;
    }
    f.starts_with("requirements") && f.ends_with(".txt")
}

fn match_event_to_project(projects: &[Project], path: &Path) -> Option<(String, String)> {
    let filename = path.file_name()?.to_string_lossy().to_string();
    let path_norm = normalize_for_match(path);
    let mut best: Option<(String, usize)> = None;
    for p in projects {
        let root_norm = normalize_for_match(&p.path);
        if path_norm.starts_with(&root_norm) {
            let len = root_norm.len();
            match &best {
                Some((_name, best_len)) if *best_len >= len => {}
                _ => best = Some((p.name.clone(), len)),
            }
        }
    }
    best.map(|(name, _)| (name, filename))
}

fn normalize_for_match(path: &Path) -> String {
    let mut s = path.to_string_lossy().to_string();
    if s.starts_with(r"\\?\") {
        s = s.trim_start_matches(r"\\?\").to_string();
    }
    s = s.replace('/', r"\");
    #[cfg(windows)]
    {
        s = s.to_lowercase();
    }
    s
}

fn strip_verbatim_prefix_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if s.starts_with(r"\\?\") {
            return PathBuf::from(s.trim_start_matches(r"\\?\").to_string());
        }
    }
    path.to_path_buf()
}

fn canonicalize_for_storage(path: &Path) -> Result<PathBuf> {
    let canon = fs::canonicalize(path)?;
    Ok(strip_verbatim_prefix_path(&canon))
}

fn compute_next_cve_check_at(project: &Project, now: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    let now = now.unwrap_or_else(Utc::now);
    let interval_hours = project
        .cve_interval_hours
        .unwrap_or(DEFAULT_CVE_INTERVAL_HOURS)
        .max(1);
    let interval = chrono::Duration::hours(interval_hours);

    if let Some(last) = &project.last_vuln_scan {
        return Some(last.created_at + interval);
    }
    Some(now + chrono::Duration::seconds(30))
}

fn scheduled_cve_check(project: &Project) -> Result<(usize, usize, usize, usize)> {
    // Build snapshot in memory; do not create snapshot files if unchanged.
    let snapshot = crate::snapshot::build_snapshot(&project.name, &project.path)?;
    let vuln_info = run_vuln_scan_for_snapshot(project, &snapshot)?;
    Ok((
        vuln_info.vulns_count,
        vuln_info.new_ids,
        vuln_info.changed_ids,
        vuln_info.gone_ids,
    ))
}

fn save_vuln_report(project: &str, report: &OsvReport) -> Result<PathBuf> {
    let dir = project_vulns_dir(project)?;
    fs::create_dir_all(&dir)?;
    let ts = report.created_at.format("%Y%m%d-%H%M%S").to_string();
    let path = dir.join(format!("osv-{ts}.json"));
    let json = serde_json::to_string_pretty(report)?;
    fs::write(&path, json)?;
    fs::write(dir.join("latest.json"), serde_json::to_string_pretty(report)?)?;
    Ok(path)
}

fn load_latest_vuln_report(project: &str) -> Option<OsvReport> {
    let path = project_vulns_dir(project).ok()?.join("latest.json");
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn diff_vuln_reports(prev: &OsvReport, next: &OsvReport) -> (usize, usize, usize) {
    let mut prev_map: BTreeMap<&str, (&str, Option<DateTime<Utc>>)> = BTreeMap::new();
    for v in &prev.vulns {
        prev_map.insert(v.id.as_str(), (v.summary.as_str(), v.modified));
    }
    let mut next_map: BTreeMap<&str, (&str, Option<DateTime<Utc>>)> = BTreeMap::new();
    for v in &next.vulns {
        next_map.insert(v.id.as_str(), (v.summary.as_str(), v.modified));
    }

    let mut new_ids = 0;
    let mut changed_ids = 0;
    let mut gone_ids = 0;

    for (id, (sum, modif)) in &next_map {
        match prev_map.get(id) {
            None => new_ids += 1,
            Some((ps, pm)) => {
                if ps != sum || pm != modif {
                    changed_ids += 1;
                }
            }
        }
    }
    for id in prev_map.keys() {
        if !next_map.contains_key(id) {
            gone_ids += 1;
        }
    }
    (new_ids, changed_ids, gone_ids)
}

fn run_vuln_scan_for_snapshot(project: &Project, snapshot: &DependencySnapshot) -> Result<VulnScanInfo> {
    let created_at = Utc::now();
    let prev = load_latest_vuln_report(&project.name);

    let vulns = crate::osv::query_osv_vulns(&snapshot.dependencies)?;
    let cfg = load_config();
    let ignore = cfg.webhook_ignore_vuln_ids;
    let vulns: Vec<_> = vulns.into_iter().filter(|v| !ignore.iter().any(|id| id == &v.id)).collect();
    let report = OsvReport {
        created_at,
        input_hash: snapshot.hash_blake3.clone(),
        vulns: vulns.clone(),
    };
    let report_path = save_vuln_report(&project.name, &report)?;

    let (new_ids, changed_ids, gone_ids) = prev
        .as_ref()
        .map(|p| diff_vuln_reports(p, &report))
        .unwrap_or((report.vulns.len(), 0, 0));

    let vuln_info = VulnScanInfo {
        created_at,
        input_hash: snapshot.hash_blake3.clone(),
        vulns_count: report.vulns.len(),
        new_ids,
        changed_ids,
        gone_ids,
        report_path: report_path.display().to_string(),
    };

    // Update db (open_alerts = current vulns after ignore)
    let mut db = load_db()?;
    if let Some(p) = db.projects.iter_mut().find(|p| p.name == project.name) {
        p.last_vuln_scan = Some(vuln_info.clone());
        p.open_alerts = vuln_info.vulns_count;
    }
    save_db(&db)?;

    if new_ids + changed_ids + gone_ids > 0 {
        append_line(
            &daemon_log_path()?,
            &format!(
                "[{}] CVE diff project={} vulns={} new={} changed={} gone={}",
                Utc::now().to_rfc3339(),
                project.name,
                vuln_info.vulns_count,
                new_ids,
                changed_ids,
                gone_ids
            ),
        )
        .ok();
        append_line(
            &project_log_path(&project.name)?,
            &format!(
                "[{}] CVE diff vulns={} new={} changed={} gone={} report={}",
                Utc::now().to_rfc3339(),
                vuln_info.vulns_count,
                new_ids,
                changed_ids,
                gone_ids,
                vuln_info.report_path
            ),
        )
        .ok();

        notify_webhook(
            "cve_diff",
            &format!(
                "DepSentry firewall: CVE diff for {} (vulns={}, new={}, changed={}, gone={})",
                project.name, vuln_info.vulns_count, new_ids, changed_ids, gone_ids
            ),
            serde_json::json!({
                "project": project.name,
                "vulns": vuln_info.vulns_count,
                "new": new_ids,
                "changed": changed_ids,
                "gone": gone_ids,
                "report": vuln_info.report_path,
                "snapshot_hash": vuln_info.input_hash,
            }),
        )
        .ok();
    }

    Ok(vuln_info)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeepCacheEntry {
    created_at: DateTime<Utc>,
    ecosystem: String,
    name: String,
    version: String,
    score: u8,
    findings: Vec<crate::analysis::Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeepReport {
    created_at: DateTime<Utc>,
    snapshot_hash: String,
    changed: Vec<String>,
    scanned: Vec<String>,
    cache_hits: Vec<String>,
    errors: Vec<String>,
    high_or_critical: Vec<String>,
}

fn run_deep_scan_for_snapshot(
    project: &Project,
    prev_snapshot: Option<&DependencySnapshot>,
    snapshot: &DependencySnapshot,
) -> Result<DeepScanInfo> {
    let changed = diff_dependencies(prev_snapshot, snapshot);
    let changed_packages = changed.len();
    if changed_packages == 0 {
        let info = DeepScanInfo {
            created_at: Utc::now(),
            changed_packages: 0,
            scanned_packages: 0,
            cache_hits: 0,
            errors: 0,
            high_or_critical: 0,
            report_path: "-".to_string(),
        };
        update_project_last_deep(project, &info)?;
        return Ok(info);
    }

    let max_packages = project
        .deep_max_packages
        .unwrap_or(DEEP_SCAN_MAX_PACKAGES)
        .max(1);
    let mut to_process = changed;
    if to_process.len() > max_packages {
        to_process.truncate(max_packages);
    }

    let created_at = Utc::now();
    let mut report = DeepReport {
        created_at,
        snapshot_hash: snapshot.hash_blake3.clone(),
        changed: to_process
            .iter()
            .map(|d| dep_label(d))
            .collect(),
        scanned: Vec::new(),
        cache_hits: Vec::new(),
        errors: Vec::new(),
        high_or_critical: Vec::new(),
    };

    let mut cache_hits = 0usize;
    let mut scanned_packages = 0usize;
    let mut errors = 0usize;
    let mut high_or_critical = 0usize;

    let per_pkg_timeout = project
        .deep_timeout_secs
        .unwrap_or(DEFAULT_DEEP_TIMEOUT_SECS)
        .max(5);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime for deep scan")?;

    for dep in &to_process {
        let label = dep_label(dep);
        match load_deep_cache_with_ttl(dep, project.deep_cache_ttl_hours) {
            Ok(Some(entry)) => {
                cache_hits += 1;
                report.cache_hits.push(label.clone());
                let hoc = entry
                    .findings
                    .iter()
                    .any(|f| f.severity == "HIGH" || f.severity == "CRITICAL");
                if hoc {
                    high_or_critical += 1;
                    report.high_or_critical.push(label);
                }
            }
            Ok(None) => {
                scanned_packages += 1;
                report.scanned.push(label.clone());
                let scan_res = rt.block_on(async { deep_scan_dependency(dep, per_pkg_timeout).await });
                match scan_res {
                    Ok(entry) => {
                        let hoc = entry
                            .findings
                            .iter()
                            .any(|f| f.severity == "HIGH" || f.severity == "CRITICAL");
                        if hoc {
                            high_or_critical += 1;
                            report.high_or_critical.push(label.clone());
                        }
                        save_deep_cache(dep, &entry).ok();
                    }
                    Err(e) => {
                        errors += 1;
                        report.errors.push(format!("{label}: {e}"));
                    }
                }
            }
            Err(e) => {
                errors += 1;
                report.errors.push(format!("{label}: {e}"));
            }
        }
    }

    let report_path = save_deep_report(&project.name, &report)?.display().to_string();

    let info = DeepScanInfo {
        created_at,
        changed_packages,
        scanned_packages,
        cache_hits,
        errors,
        high_or_critical,
        report_path,
    };
    update_project_last_deep(project, &info)?;

    append_line(
        &project_log_path(&project.name)?,
        &format!(
            "[{}] deep scan changed={} scanned={} cache_hits={} errors={} high_or_critical={} report={}",
            Utc::now().to_rfc3339(),
            info.changed_packages,
            info.scanned_packages,
            info.cache_hits,
            info.errors,
            info.high_or_critical,
            info.report_path
        ),
    )
    .ok();

    if info.high_or_critical > 0 || info.errors > 0 {
        notify_webhook(
            "deep_scan",
            &format!(
                "DepSentry firewall: deep scan for {} (changed={}, scanned={}, high_or_critical={}, errors={})",
                project.name, info.changed_packages, info.scanned_packages, info.high_or_critical, info.errors
            ),
            serde_json::json!({
                "project": project.name,
                "changed": info.changed_packages,
                "scanned": info.scanned_packages,
                "cache_hits": info.cache_hits,
                "high_or_critical": info.high_or_critical,
                "errors": info.errors,
                "report": info.report_path,
                "snapshot_hash": snapshot.hash_blake3,
            }),
        )
        .ok();
    }

    Ok(info)
}

async fn deep_scan_dependency(dep: &Dependency, timeout_secs: u64) -> Result<DeepCacheEntry> {
    let fetcher = crate::fetcher::Fetcher::new();
    let analyzer = crate::analysis::Analyzer::new();
    let duration = std::time::Duration::from_secs(timeout_secs);

    let work = async {
        let (path, metadata) = fetcher
            .download(&dep.name, Some(&dep.version), &dep.ecosystem)
            .await?;
        let result = analyzer
            .scan_with_options(
                &path,
                &metadata,
                &dep.ecosystem,
                crate::analysis::ScanOptions { check_osv: false },
            )
            .await?;
        let _ = std::fs::remove_dir_all(&path);
        anyhow::Ok(result)
    };

    let result = tokio::time::timeout(duration, work)
        .await
        .map_err(|_| anyhow!("timeout after {}s", timeout_secs))??;

    Ok(DeepCacheEntry {
        created_at: Utc::now(),
        ecosystem: format!("{:?}", dep.ecosystem),
        name: dep.name.clone(),
        version: dep.version.clone(),
        score: result.score,
        findings: result.findings,
    })
}

fn deep_cache_key(dep: &Dependency) -> String {
    blake3::hash(format!("{:?}|{}|{}", dep.ecosystem, dep.name, dep.version).as_bytes())
        .to_hex()
        .to_string()
}

fn deep_cache_path(dep: &Dependency) -> Result<PathBuf> {
    Ok(deep_cache_dir()?.join(format!("{}.json", deep_cache_key(dep))))
}

fn load_deep_cache_with_ttl(dep: &Dependency, ttl_override_hours: Option<i64>) -> Result<Option<DeepCacheEntry>> {
    let path = deep_cache_path(dep)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let entry: DeepCacheEntry = serde_json::from_str(&content)?;
    let ttl_hours = ttl_override_hours.unwrap_or(DEFAULT_DEEP_CACHE_TTL_HOURS).max(1);
    if Utc::now() - entry.created_at > chrono::Duration::hours(ttl_hours) {
        return Ok(None);
    }
    Ok(Some(entry))
}

fn save_deep_cache(dep: &Dependency, entry: &DeepCacheEntry) -> Result<()> {
    let path = deep_cache_path(dep)?;
    let json = serde_json::to_string_pretty(entry)?;
    fs::write(path, json)?;
    Ok(())
}

fn save_deep_report(project: &str, report: &DeepReport) -> Result<PathBuf> {
    let dir = project_deep_reports_dir(project)?;
    fs::create_dir_all(&dir)?;
    let ts = report.created_at.format("%Y%m%d-%H%M%S").to_string();
    let path = dir.join(format!("deep-{ts}.json"));
    fs::write(&path, serde_json::to_string_pretty(report)?)?;
    fs::write(dir.join("latest.json"), serde_json::to_string_pretty(report)?)?;
    Ok(path)
}

fn update_project_last_deep(project: &Project, info: &DeepScanInfo) -> Result<()> {
    let mut db = load_db()?;
    if let Some(p) = db.projects.iter_mut().find(|p| p.name == project.name) {
        p.last_deep_scan = Some(info.clone());
    }
    save_db(&db)?;
    Ok(())
}

fn dep_label(dep: &Dependency) -> String {
    format!("{:?}:{}@{}", dep.ecosystem, dep.name, dep.version)
}

fn diff_dependencies(prev: Option<&DependencySnapshot>, next: &DependencySnapshot) -> Vec<Dependency> {
    let mut out = Vec::new();
    if let Some(prev) = prev {
        let mut prev_map: BTreeMap<(crate::ecosystem::Ecosystem, String), String> = BTreeMap::new();
        for d in &prev.dependencies {
            prev_map.insert((d.ecosystem.clone(), d.name.clone()), d.version.clone());
        }
        for d in &next.dependencies {
            let key = (d.ecosystem.clone(), d.name.clone());
            match prev_map.get(&key) {
                None => out.push(d.clone()),
                Some(v) if v != &d.version => out.push(d.clone()),
                _ => {}
            }
        }
        return out;
    }

    // First scan: treat all as changed.
    out.extend(next.dependencies.iter().cloned());
    out
}
