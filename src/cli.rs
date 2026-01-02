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
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check a single package for security issues
    Check {
        /// Name of the package to check
        name: String,

        /// Ecosystem (npm, pypi). If not provided, autodetection is attempted.
        #[arg(long, short)]
        r#type: Option<String>,

        /// Specific version to check
        #[arg(long, short)]
        version: Option<String>,
    },
    /// Scan all dependencies in a manifest file (package.json / requirements.txt)
    Scan {
        /// Path to manifest file. Autodetected if not provided.
        #[arg(long, short)]
        path: Option<String>,
    },
}
