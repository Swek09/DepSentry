/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use crate::analysis::ScanResult;
use tabled::{Table, Tabled};
use colored::*;

pub struct Reporter;

#[derive(Tabled)]
struct FindingRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "File")]
    file: String,
}

impl Reporter {
    pub fn print_report(result: &ScanResult) {
        println!("\n{}", "--- Analysis Report ---".bold().underline());
        
        // Invert score for display: 100 (Safe) -> 0 (Risk), 0 (Risk) -> 100 (Risk)
        let risk_score = 100 - result.score;
        
        let (score_color, label) = if risk_score == 0 {
             ("green", "SAFE")
        } else if risk_score < 50 {
             ("yellow", "LOW RISK")
        } else {
             ("red", "CRITICAL")
        };
        
        println!("Risk Score: {} ({})", risk_score.to_string().color(score_color).bold(), label.color(score_color).bold());
        
        if result.findings.is_empty() {
            println!("{}", "No threats detected.".green());
            return;
        }

        let mut rows = Vec::new();
        for f in &result.findings {
            rows.push(FindingRow {
                severity: f.severity.clone(),
                category: f.category.clone(),
                description: f.description.chars().take(50).collect::<String>() + "...", // Truncate long desc
                file: f.file_path.as_ref().map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string()).unwrap_or_else(|| "-".to_string()),
            });
        }

        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    pub fn generate_audit_json(result: &ScanResult) {
        let json = serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string());
        if let Err(e) = std::fs::write("audit.json", json) {
            println!("{}", format!("Failed to write audit.json: {}", e).red());
        } else {
            println!("{}", "Report saved to audit.json".blue().italic());
        }
    }
}
