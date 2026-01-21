# Changelog

## v0.2.0

- Added `firewall` mode: daemon lifecycle, project registry, logs, status, save/resurrect.
- Dependency snapshots from lock/manifest files with hashing and history.
- File watcher with debounce + queued runs and per-project runtime status.
- OSV CVE-only scans with diffing, alert counters, and scheduling.
- Deep scans on dependency diffs with cache, timeouts, and limits.
- Webhook notifications (dedup + vuln-id ignore list).
- Autostart helpers (generate/install/uninstall).

## v0.2.1

- Fixed GitHub release workflow: build with `ds-alias`, avoid `assets/` directory collision, and prevent rebuild in `cargo deb`.
