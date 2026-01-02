/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
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

        None
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "npm" | "node" | "javascript" | "js" => Some(Ecosystem::Npm),
            "pypi" | "pip" | "python" | "py" => Some(Ecosystem::Pypi),
            _ => None,
        }
    }
}
