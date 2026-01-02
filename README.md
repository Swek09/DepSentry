# 🛡️ DepSentry

[![Language](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Supply%20Chain-green)](https://mitre-attack.github.io/)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()

**DepSentry** is a high-performance **Supply Chain Security** tool designed for Blue Teams and DevSecOps.

Unlike standard auditors that only check for CVEs, DepSentry acts as a proactive **middleware**, analyzing packages for malware, obfuscation, and reputation issues **before** they are installed in your environment.

---

## 🔥 Key Features

### 1. Hybrid Analysis Engine
Combines database queries with real-time heuristic analysis:
* **CVE Scanning**: Instant verification against the Google OSV database.
* **Malware Heuristics**: Detects suspicious patterns (`eval`, `exec`, shell injection, hardcoded IPs).
* **Entropy Analysis**: Identifies packed or obfuscated code (Shannon Entropy > 7.5), a common indicator of hidden malware.

### 2. Ephemeral Sandboxing
* Downloads and extracts packages to a temporary, isolated directory.
* **Zero Footprint**: Malicious code is never executed or installed on the host machine during analysis.
* **Zip Slip Protection**: Prevents path traversal attacks during extraction.

### 3. High Performance
* Built with **Rust** for memory safety and speed.
* **Parallel Processing**: Powered by `Rayon` and `Tokio`, DepSentry analyzes thousands of files simultaneously, utilizing all CPU cores.

### 4. Supply Chain Guard
* **Typosquatting Detection**: Warns if a package name mimics popular libraries (e.g., `react` vs `reacct`).
* **Reputation Check**: Flags packages that are dangerously new (< 7 days old).

---

## 🛠️ Installation

DepSentry is built with Rust. Ensure you have `cargo` installed.

```bash
# 1. Clone the repository
git clone [https://github.com/egris/depsentry.git](https://github.com/egris/depsentry.git)
cd depsentry

# 2. Build in release mode (for maximum speed)
cargo build --release

# 3. Run the binary
./target/release/depsentry --help

```

---

## 🚀 Usage

### Mode A: Check a Single Package

Analyze a remote package without installing it. Useful for quick vetting.

```bash
# Auto-detect ecosystem (NPM/PyPI)
depsentry check axios

# Specify version and type explicitly
depsentry check requests --version 2.31.0 --type pip

```

### Mode B: Project Audit (CI/CD)

Scan an entire manifest (`package.json`) in the current directory. This mode is designed for CI/CD pipelines as a Quality Gate.

```bash
# Run in the root of your project
depsentry scan

```

**Output Example:**

```text
Risk Score: 100 (CRITICAL)
+----------+----------+-------------------------------------+
| Severity | Category | Description                         |
+----------+----------+-------------------------------------+
| HIGH     | CVE      | GHSA-4hjh: Axios vulnerable to DoS  |
| HIGH     | Malware  | Suspicious entropy in dist/index.js |
+----------+----------+-------------------------------------+

```

---

## 🏗️ Architecture

DepSentry follows a modular "Pipeline" architecture:

1. **CLI Parser (`clap`)**: Handles user input and flags.
2. **Fetcher Module (`reqwest`)**: Asynchronously downloads metadata and tarballs from NPM/PyPI registries.
3. **Sandbox Manager**: Creates secure temporary directories (`tempfile`).
4. **Analysis Engine (`rayon`)**:
* *Static Analyzer*: Regex-based signature matching.
* *Entropy Calculator*: Shannon entropy math.
* *OSV Client*: API queries for vulnerabilities.


5. **Reporter**: Aggregates results into a Risk Score (0-100) and renders the report.

---

## ⚖️ License

Copyright 2026 Mikhail Grishak.

Licensed under the **Apache License, Version 2.0**.

See `LICENSE` file for more details.
