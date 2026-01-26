/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    Pypi,
    Crates,
    Java,
}

impl Ecosystem {
    pub fn detect(path: &Path) -> Option<Self> {
        if path.join("package.json").exists()
            || path.join("yarn.lock").exists()
            || path.join("pnpm-lock.yaml").exists()
        {
            return Some(Ecosystem::Npm);
        }

        if path.join("requirements.txt").exists()
            || path.join("Pipfile").exists()
            || path.join("pyproject.toml").exists()
            || path.join("setup.py").exists()
        {
            return Some(Ecosystem::Pypi);
        }

        if path.join("Cargo.toml").exists() || path.join("Cargo.lock").exists() {
            return Some(Ecosystem::Crates);
        }

        if path.join("pom.xml").exists()
            || path.join("build.gradle").exists()
            || path.join("build.gradle.kts").exists()
            || path.join("gradle.lockfile").exists()
        {
            return Some(Ecosystem::Java);
        }

        None
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "npm" | "node" | "javascript" | "js" => Some(Ecosystem::Npm),
            "pypi" | "pip" | "python" | "py" => Some(Ecosystem::Pypi),
            "cargo" | "crates" | "crates.io" | "rust" => Some(Ecosystem::Crates),
            "java" | "maven" | "mvn" => Some(Ecosystem::Java),
            _ => None,
        }
    }
}
