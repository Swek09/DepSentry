/*
 * DepSentry
 * Copyright (c) 2026 Mikhail Grishak
 * Licensed under the Apache License, Version 2.0.
*/

use std::path::{Path, PathBuf};
use std::io::Cursor;
use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde_json::Value;
use tempfile::Builder;
use flate2::read::GzDecoder;
use tar::Archive;
use zip::ZipArchive;
use chrono::{DateTime, Utc};
use regex::Regex;
use crate::ecosystem::Ecosystem;

#[derive(Debug, Clone)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub published_at: Option<DateTime<Utc>>,
}

pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("depsentry-security-scanner/0.2.3")
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub async fn download(&self, name: &str, version: Option<&str>, ecosystem: &Ecosystem) -> Result<(PathBuf, PackageMetadata)> {
        println!("Fetching metadata for {} ({:?})...", name, ecosystem);
        
        let (url, filename, meta) = match ecosystem {
            Ecosystem::Npm => self.get_npm_metadata(name, version).await?,
            Ecosystem::Pypi => self.get_pypi_metadata(name, version).await?,
            Ecosystem::Crates => self.get_crates_metadata(name, version).await?,
            Ecosystem::Java => self.get_maven_metadata(name, version).await?,
        };

        println!("Downloading package version {} from {}...", meta.version, url);
        let response = self.client.get(&url).send().await?.error_for_status()?;
        let content = response.bytes().await?;

        #[allow(deprecated)]
        let temp_dir = Builder::new().prefix("depsentry-extract-").tempdir()?.into_path();
        
        println!("Extracting to {:?}...", temp_dir);
        match ecosystem {
            Ecosystem::Npm => self.extract_tar_gz(&content, &temp_dir)?,
            Ecosystem::Pypi => {
                if filename.ends_with(".whl") || filename.ends_with(".zip") {
                    self.extract_zip(&content, &temp_dir)?
                } else if filename.ends_with(".tar.gz") {
                    self.extract_tar_gz(&content, &temp_dir)?
                } else {
                     bail!("Unsupported file format for PyPI: {}", filename);
                }
            }
            Ecosystem::Crates => self.extract_tar_gz(&content, &temp_dir)?,
            Ecosystem::Java => self.extract_zip(&content, &temp_dir)?,
        }

        Ok((temp_dir, meta))
    }

    async fn get_npm_metadata(&self, name: &str, version: Option<&str>) -> Result<(String, String, PackageMetadata)> {
        let url = format!("https://registry.npmjs.org/{}", name);
        let resp: Value = self.client.get(&url).send().await?.json().await?;
        
        let version_tag = version.unwrap_or("latest");
        
        // Handle case where package not found or version tag missing
        if let Some(error) = resp.get("error") {
            bail!("NPM Registry Error: {}", error);
        }

        let specific_version = if version.is_some() {
             version_tag.to_string()
        } else {
             resp["dist-tags"][version_tag].as_str().context("No latest tag found in NPM response")?.to_string()
        };

        let tarball = resp["versions"][&specific_version]["dist"]["tarball"]
            .as_str()
            .context("No tarball URL found")?
            .to_string();
        
        let time_str = resp["time"][&specific_version].as_str();
        let published_at = time_str.and_then(|t| DateTime::parse_from_rfc3339(t).ok().map(|dt| dt.with_timezone(&Utc)));

        Ok((tarball, format!("{}-{}.tgz", name, specific_version), PackageMetadata {
            name: name.to_string(),
            version: specific_version,
            published_at,
        }))
    }

    async fn get_pypi_metadata(&self, name: &str, version: Option<&str>) -> Result<(String, String, PackageMetadata)> {
        let url = if let Some(v) = version {
            format!("https://pypi.org/pypi/{}/{}/json", name, v)
        } else {
            format!("https://pypi.org/pypi/{}/json", name)
        };

        let resp: Value = self.client.get(&url).send().await?.json().await?;
        
        if resp.get("message").and_then(|m| m.as_str()) == Some("Not Found") {
             bail!("Package not found on PyPI");
        }
        
        let releases = resp["urls"].as_array().context("No urls in PyPI response")?;
        let info_version = resp["info"]["version"].as_str().unwrap_or("unknown").to_string();
        
        let mut target_release = None;
        // Priority: sdist > bdist_wheel
        for release in releases {
            if release["packagetype"].as_str().unwrap_or("") == "sdist" {
                 target_release = Some(release);
                 break;
            }
        }
        if target_release.is_none() {
             for release in releases {
                if release["packagetype"].as_str().unwrap_or("") == "bdist_wheel" {
                     target_release = Some(release);
                     break;
                }
            }
        }

        let release = target_release.context("No suitable distribution found")?;
        let download_url = release["url"].as_str().context("No url found")?.to_string();
        let filename = release["filename"].as_str().context("No filename found")?.to_string();
        
        let upload_time = release["upload_time_iso_8601"].as_str();
        let published_at = upload_time.and_then(|t| DateTime::parse_from_rfc3339(t).ok().map(|dt| dt.with_timezone(&Utc)));

        Ok((download_url, filename, PackageMetadata {
            name: name.to_string(),
            version: info_version,
            published_at,
        }))
    }

    async fn get_crates_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<(String, String, PackageMetadata)> {
        // crates.io API: /api/v1/crates/<name>
        let url = format!("https://crates.io/api/v1/crates/{}", name);
        let resp: Value = self.client.get(&url).send().await?.json().await?;

        let versions = resp["versions"]
            .as_array()
            .context("No versions in crates.io response")?;
        if versions.is_empty() {
            bail!("No versions found for crate {}", name);
        }

        let chosen = if let Some(v) = version {
            versions
                .iter()
                .find(|x| x["num"].as_str() == Some(v))
                .context("Requested version not found on crates.io")?
        } else {
            // Usually first is newest
            &versions[0]
        };

        let ver = chosen["num"].as_str().unwrap_or("unknown").to_string();
        let dl = format!("https://crates.io/api/v1/crates/{}/{}/download", name, ver);
        let filename = format!("{}-{}.crate", name, ver);

        let published_at = chosen["created_at"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok().map(|dt| dt.with_timezone(&Utc)));

        Ok((
            dl,
            filename,
            PackageMetadata {
                name: name.to_string(),
                version: ver,
                published_at,
            },
        ))
    }

    async fn get_maven_metadata(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<(String, String, PackageMetadata)> {
        let (group_id, artifact_id) = parse_maven_name(name)?;
        let group_path = group_id.replace('.', "/");
        let base = format!(
            "https://repo1.maven.org/maven2/{}/{}/",
            group_path, artifact_id
        );

        let ver = if let Some(v) = version {
            v.to_string()
        } else {
            let meta_url = format!("{}maven-metadata.xml", base);
            let xml = self
                .client
                .get(&meta_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            parse_maven_latest_version(&xml)
                .with_context(|| format!("No versions found in {}", meta_url))?
        };

        let sources_filename = format!("{}-{}-sources.jar", artifact_id, ver);
        let jar_filename = format!("{}-{}.jar", artifact_id, ver);
        let sources_url = format!("{}{}/{}", base, ver, sources_filename);
        let jar_url = format!("{}{}/{}", base, ver, jar_filename);

        let (url, filename) = match self.client.head(&sources_url).send().await {
            Ok(resp) if resp.status().is_success() => (sources_url, sources_filename),
            _ => (jar_url, jar_filename),
        };

        Ok((
            url,
            filename,
            PackageMetadata {
                name: name.to_string(),
                version: ver,
                published_at: None,
            },
        ))
    }

    fn extract_tar_gz(&self, data: &[u8], target: &Path) -> Result<()> {
        let decoder = GzDecoder::new(Cursor::new(data));
        let mut archive = Archive::new(decoder);
        
        // Manual unpacking to prevent Zip Slip
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let dest_path = target.join(path);
            
            // SECURITY: Zip Slip Prevention
            if !dest_path.starts_with(target) {
                 bail!("Security Error: Zip Slip detected! Attempted to extract to {:?}", dest_path);
            }
            
            // Ensure parent directory exists
            if let Some(parent) = dest_path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                }
            }

            entry.unpack(&dest_path)?;
        }
        Ok(())
    }

    fn extract_zip(&self, data: &[u8], target: &Path) -> Result<()> {
        let mut archive = ZipArchive::new(Cursor::new(data))?;
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let enclosed_name = file.enclosed_name().context("Invalid file path in zip")?;
            let dest_path = target.join(enclosed_name);

            // SECURITY: Zip Slip Prevention (Double Check)
            if !dest_path.starts_with(target) {
                 bail!("Security Error: Zip Slip detected! Attempted to extract to {:?}", dest_path);
            }
            
            if file.is_dir() {
                std::fs::create_dir_all(&dest_path)?;
            } else {
                if let Some(parent) = dest_path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let mut outfile = std::fs::File::create(&dest_path)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }
        Ok(())
    }
}

fn parse_maven_name(name: &str) -> Result<(String, String)> {
    let Some((group_id, artifact_id)) = name.split_once(':') else {
        bail!("Java packages must be in groupId:artifactId format");
    };
    if group_id.trim().is_empty() || artifact_id.trim().is_empty() {
        bail!("Java packages must be in groupId:artifactId format");
    }
    Ok((group_id.trim().to_string(), artifact_id.trim().to_string()))
}

fn parse_maven_latest_version(xml: &str) -> Option<String> {
    let re_latest = Regex::new(r"<latest>\s*([^<\s]+)\s*</latest>").ok()?;
    if let Some(cap) = re_latest.captures(xml) {
        return Some(cap[1].to_string());
    }
    let re_release = Regex::new(r"<release>\s*([^<\s]+)\s*</release>").ok()?;
    if let Some(cap) = re_release.captures(xml) {
        return Some(cap[1].to_string());
    }
    let re_version = Regex::new(r"<version>\s*([^<\s]+)\s*</version>").ok()?;
    let mut versions = Vec::new();
    for cap in re_version.captures_iter(xml) {
        versions.push(cap[1].to_string());
    }
    versions.last().cloned()
}
