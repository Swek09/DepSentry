#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function getBinaryPath() {
  const binDir = path.join(__dirname);
  if (process.platform === "win32") {
    return path.join(binDir, "depsentry.exe");
  }
  return path.join(binDir, "depsentry");
}

const binPath = getBinaryPath();
if (!fs.existsSync(binPath)) {
  console.error("depsentry binary not found. Reinstall the package or check your platform support.");
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
process.exit(result.status === null ? 1 : result.status);
