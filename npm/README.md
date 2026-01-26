# DepSentry CLI (npm)

[![npm version](https://img.shields.io/npm/v/@swek09/depsentry.svg)](https://www.npmjs.com/package/@swek09/depsentry)
[![npm downloads](https://img.shields.io/npm/dm/@swek09/depsentry.svg)](https://www.npmjs.com/package/@swek09/depsentry)
[![license](https://img.shields.io/npm/l/@swek09/depsentry.svg)](https://github.com/Swek09/DepSentry/blob/main/LICENSE)

DepSentry is a fast Rust CLI for proactive supply-chain security. This npm package is a thin wrapper that downloads the prebuilt DepSentry binary for your platform and exposes the `depsentry` command.

## Quick start

```bash
npm install -g @swek09/depsentry
depsentry check axios
```

You can also run it without a global install:

```bash
npx @swek09/depsentry check axios
```

## What it does

- Downloads packages to a temporary sandbox (no execution)
- Runs static heuristics (entropy, suspicious scripts, network indicators)
- Optionally queries OSV for known vulnerabilities

## Supported platforms

- Windows x64
- Linux x64

Other platforms are not bundled yet. Use GitHub Releases for manual download.

## Commands and examples

Check a single package:

```bash
depsentry check axios
depsentry check requests --type pypi --version 2.31.0
depsentry check serde --type cargo --version 1.0.197
depsentry check org.slf4j:slf4j-api --type java --version 1.7.36
```

Scan a manifest:

```bash
depsentry scan --path ./package.json
depsentry scan --path ./requirements.txt
depsentry scan --path ./Cargo.lock
depsentry scan --path ./pom.xml
depsentry scan --path ./build.gradle
```

Firewall mode (daemon, stage 0):

```bash
depsentry firewall start
depsentry firewall add /path/to/project
depsentry firewall status my-project
```

## Notes

- `depsentry check` exits with code 1 if score < 50.
- This npm package downloads binaries from GitHub Releases during install.

## Links

- Homepage: https://depsentry.com/
- Repo: https://github.com/Swek09/DepSentry
- Releases: https://github.com/Swek09/DepSentry/releases
