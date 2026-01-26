use crate::ecosystem::Ecosystem;
use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencySnapshot {
    pub project: String,
    pub created_at: DateTime<Utc>,
    pub files: Vec<String>,
    pub dependencies: Vec<Dependency>,
    pub hash_blake3: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotInputs {
    pub files: Vec<PathBuf>,
    pub dependencies: Vec<Dependency>,
}

pub fn build_snapshot(project: &str, project_dir: &Path) -> Result<DependencySnapshot> {
    let inputs = collect_snapshot_inputs(project_dir)?;
    if inputs.files.is_empty() {
        return Err(anyhow!(
            "No supported dependency files found in {}",
            project_dir.display()
        ));
    }

    let mut deps = inputs.dependencies;
    deps.sort();
    deps.dedup();

    let mut files = inputs
        .files
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>();
    files.sort();

    let hash = hash_inputs(&inputs.files, &deps)?;

    Ok(DependencySnapshot {
        project: project.to_string(),
        created_at: Utc::now(),
        files,
        dependencies: deps,
        hash_blake3: hash,
    })
}

fn hash_inputs(files: &[PathBuf], deps: &[Dependency]) -> Result<String> {
    let mut hasher = Hasher::new();

    let mut sorted_files: Vec<PathBuf> = files.to_vec();
    sorted_files.sort();
    for path in sorted_files {
        hasher.update(path.display().to_string().as_bytes());
        match fs::read(&path) {
            Ok(content) => {
                hasher.update(&content);
            }
            Err(_) => {
                hasher.update(b"<unreadable>");
            }
        };
    }

    for dep in deps {
        hasher.update(format!("{:?}|{}|{}\n", dep.ecosystem, dep.name, dep.version).as_bytes());
    }

    Ok(hasher.finalize().to_hex().to_string())
}

pub fn collect_snapshot_inputs(project_dir: &Path) -> Result<SnapshotInputs> {
    let mut files = Vec::new();
    let mut deps: BTreeSet<Dependency> = BTreeSet::new();

    // Rust ecosystem
    let cargo_lock = project_dir.join("Cargo.lock");
    let cargo_toml = project_dir.join("Cargo.toml");
    if cargo_lock.exists() {
        files.push(cargo_lock.clone());
        for dep in parse_cargo_lock(&cargo_lock)? {
            deps.insert(dep);
        }
    } else if cargo_toml.exists() {
        files.push(cargo_toml.clone());
        for dep in parse_cargo_toml(&cargo_toml)? {
            deps.insert(dep);
        }
    }

    // JS ecosystem
    let package_lock = project_dir.join("package-lock.json");
    let pnpm_lock = project_dir.join("pnpm-lock.yaml");
    let yarn_lock = project_dir.join("yarn.lock");
    let package_json = project_dir.join("package.json");

    if package_lock.exists() {
        files.push(package_lock.clone());
        for dep in parse_package_lock(&package_lock)? {
            deps.insert(dep);
        }
    } else if pnpm_lock.exists() {
        files.push(pnpm_lock.clone());
        for dep in parse_pnpm_lock(&pnpm_lock)? {
            deps.insert(dep);
        }
    } else if yarn_lock.exists() {
        files.push(yarn_lock.clone());
        for dep in parse_yarn_lock(&yarn_lock)? {
            deps.insert(dep);
        }
    } else if package_json.exists() {
        files.push(package_json.clone());
        for dep in parse_package_json(&package_json)? {
            deps.insert(dep);
        }
    }

    // Python ecosystem
    for req in find_requirements_files(project_dir)? {
        files.push(req.clone());
        for dep in parse_requirements_txt(&req)? {
            deps.insert(dep);
        }
    }

    Ok(SnapshotInputs {
        files,
        dependencies: deps.into_iter().collect(),
    })
}

pub fn parse_cargo_lock_file(path: &Path) -> Result<Vec<Dependency>> {
    parse_cargo_lock(path)
}

pub fn parse_cargo_toml_file(path: &Path) -> Result<Vec<Dependency>> {
    parse_cargo_toml(path)
}

fn parse_cargo_lock(path: &Path) -> Result<Vec<Dependency>> {
    // Minimal parser: scan [[package]] sections for name/version pairs.
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();
    let mut in_pkg = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim().trim_start_matches('\u{feff}');
        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                deps.push(Dependency {
                    ecosystem: Ecosystem::Crates,
                    name: n,
                    version: v,
                });
            }
            in_pkg = true;
            name = None;
            version = None;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(unquote(rest));
        } else if let Some(rest) = line.strip_prefix("version = ") {
            version = Some(unquote(rest));
        } else if line.starts_with('[') && line != "[[package]]" {
            // leaving the package section
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                deps.push(Dependency {
                    ecosystem: Ecosystem::Crates,
                    name: n,
                    version: v,
                });
            }
            in_pkg = false;
        }
    }

    if let (Some(n), Some(v)) = (name.take(), version.take()) {
        deps.push(Dependency {
            ecosystem: Ecosystem::Crates,
            name: n,
            version: v,
        });
    }

    Ok(deps)
}

fn parse_cargo_toml(path: &Path) -> Result<Vec<Dependency>> {
    // Minimal parser for direct deps in Cargo.toml: look for [dependencies] section and `name = "x"` lines.
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut deps = Vec::new();

    let mut in_deps = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            let section = line.trim_start_matches('[').trim_end_matches(']');
            in_deps = section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies"
                || section == "workspace.dependencies"
                || section.ends_with(".dependencies");
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, rhs)) = line.split_once('=') {
            let name = name.trim().to_string();
            let ver = rhs.trim();
            let version = if ver.starts_with('"') {
                unquote(ver)
            } else if ver.starts_with('{') {
                // { version = "x", ... }
                extract_inline_version(ver).unwrap_or_else(|| "unspecified".to_string())
            } else {
                "unspecified".to_string()
            };
            deps.push(Dependency {
                ecosystem: Ecosystem::Crates,
                name,
                version,
            });
        }
    }

    Ok(deps)
}

fn unquote(input: &str) -> String {
    let s = input.trim().trim_end_matches(',');
    if let Some(stripped) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        stripped.to_string()
    } else {
        s.to_string()
    }
}

fn extract_inline_version(table: &str) -> Option<String> {
    let re = Regex::new(r#"version\s*=\s*"([^"]+)""#).ok()?;
    let cap = re.captures(table)?;
    Some(cap[1].to_string())
}

fn parse_package_json(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let json: JsonValue =
        serde_json::from_str(&content).with_context(|| format!("Invalid JSON in {}", path.display()))?;

    let mut deps = Vec::new();
    for key in ["dependencies", "devDependencies"] {
        if let Some(obj) = json.get(key).and_then(|v| v.as_object()) {
            for (name, ver) in obj {
                let version = ver.as_str().unwrap_or("unspecified").trim().to_string();
                deps.push(Dependency {
                    ecosystem: Ecosystem::Npm,
                    name: name.to_string(),
                    version,
                });
            }
        }
    }
    Ok(deps)
}

fn parse_package_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let json: JsonValue =
        serde_json::from_str(&content).with_context(|| format!("Invalid JSON in {}", path.display()))?;

    let mut deps: BTreeMap<String, String> = BTreeMap::new();

    // npm v7+ has "packages": { "node_modules/<name>": { "version": "x" } }
    if let Some(packages) = json.get("packages").and_then(|v| v.as_object()) {
        for (k, v) in packages {
            if k == "" {
                continue;
            }
            if let Some(ver) = v.get("version").and_then(|vv| vv.as_str()) {
                if let Some(name) = k.strip_prefix("node_modules/") {
                    deps.insert(name.to_string(), ver.to_string());
                }
            }
        }
    }

    // fallback: "dependencies": { "name": { "version": "x", "dependencies": {...}}}
    if deps.is_empty() {
        if let Some(root) = json.get("dependencies") {
            collect_npm_deps_recursive(root, &mut deps);
        }
    }

    Ok(deps
        .into_iter()
        .map(|(name, version)| Dependency {
            ecosystem: Ecosystem::Npm,
            name,
            version,
        })
        .collect())
}

fn collect_npm_deps_recursive(node: &JsonValue, out: &mut BTreeMap<String, String>) {
    let Some(obj) = node.as_object() else { return };
    for (name, v) in obj {
        if let Some(ver) = v.get("version").and_then(|vv| vv.as_str()) {
            out.entry(name.to_string()).or_insert_with(|| ver.to_string());
        }
        if let Some(child) = v.get("dependencies") {
            collect_npm_deps_recursive(child, out);
        }
    }
}

fn parse_pnpm_lock(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let yaml: YamlValue =
        serde_yaml::from_str(&content).with_context(|| format!("Invalid YAML in {}", path.display()))?;

    let mut deps = Vec::new();
    let Some(packages) = yaml.get("packages").and_then(|v| v.as_mapping()) else {
        return Ok(deps);
    };

    for (k, _v) in packages {
        let Some(key) = k.as_str() else { continue };
        // Most common: "/name/1.2.3"
        let key = key.trim();
        let key = key.trim_start_matches('/');
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() >= 2 {
            let version = parts[parts.len() - 1].to_string();
            let name = parts[..parts.len() - 1].join("/");
            deps.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name,
                version,
            });
        }
    }
    Ok(deps)
}

fn parse_yarn_lock(path: &Path) -> Result<Vec<Dependency>> {
    // Minimal parser for Yarn v1 lockfiles:
    // Entry header: "name@^1.0.0", "name@~2.0.0":
    // Next lines include: version "1.2.3"
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let re_header = Regex::new(r#"^"?([^@",\s]+)@[^:]+:"#).unwrap();
    let re_version = Regex::new(r#"^\s*version\s+"([^"]+)""#).unwrap();

    let mut deps = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    for line in content.lines() {
        if let Some(cap) = re_header.captures(line) {
            current_names.clear();
            current_names.push(cap[1].to_string());
            continue;
        }
        if let Some(cap) = re_version.captures(line) {
            let version = cap[1].to_string();
            for name in &current_names {
                deps.push(Dependency {
                    ecosystem: Ecosystem::Npm,
                    name: name.clone(),
                    version: version.clone(),
                });
            }
        }
    }

    Ok(deps)
}

fn find_requirements_files(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let re = Regex::new(r"^requirements.*\.txt$").unwrap();
    for entry in fs::read_dir(project_dir).with_context(|| format!("Failed to read {}", project_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        if re.is_match(name) {
            out.push(path);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let re = Regex::new(r"^([A-Za-z0-9_.-]+)").unwrap();

    let mut deps = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-r") || line.starts_with("--") {
            continue;
        }
        let Some(cap) = re.captures(line) else { continue };
        let name = cap[1].to_string();
        let version = if let Some((_, rhs)) = line.split_once("==") {
            rhs.split(';').next().unwrap_or(rhs).trim().to_string()
        } else {
            "unspecified".to_string()
        };
        deps.push(Dependency {
            ecosystem: Ecosystem::Pypi,
            name,
            version,
        });
    }
    Ok(deps)
}
