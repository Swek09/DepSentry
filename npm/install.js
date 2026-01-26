"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");

const VERSION = process.env.npm_package_version;
const BIN_DIR = path.join(__dirname, "bin");

function platformAssetName() {
  if (process.platform === "win32" && process.arch === "x64") {
    return "depsentry-win-x64.exe";
  }
  if (process.platform === "linux" && process.arch === "x64") {
    return "depsentry-linux-x64";
  }
  return null;
}

function targetBinaryPath() {
  if (process.platform === "win32") {
    return path.join(BIN_DIR, "depsentry.exe");
  }
  return path.join(BIN_DIR, "depsentry");
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function download(url, dest, cb) {
  const file = fs.createWriteStream(dest);
  https
    .get(url, (res) => {
      if (res.statusCode !== 200) {
        cb(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      res.pipe(file);
      file.on("finish", () => file.close(cb));
    })
    .on("error", (err) => {
      fs.unlink(dest, () => cb(err));
    });
}

function main() {
  if (!VERSION) {
    console.error("Cannot determine package version for download.");
    process.exit(1);
  }

  const asset = platformAssetName();
  if (!asset) {
    console.error(`Unsupported platform: ${process.platform} ${process.arch}`);
    process.exit(1);
  }

  ensureDir(BIN_DIR);
  const dest = targetBinaryPath();
  const url = `https://github.com/Swek09/DepSentry/releases/download/v${VERSION}/${asset}`;

  download(url, dest, (err) => {
    if (err) {
      console.error(`Failed to download ${url}: ${err.message}`);
      process.exit(1);
    }
    if (process.platform !== "win32") {
      fs.chmodSync(dest, 0o755);
    }
  });
}

main();
