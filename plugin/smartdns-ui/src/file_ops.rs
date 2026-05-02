/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use crate::dns_log;
use crate::smartdns::geosite_resolve_dat_path;
use crate::smartdns::LogLevel;
use serde::Serialize;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Information about a geosite data file parsed from smartdns.conf
#[derive(Debug, Clone, Serialize)]
pub struct GeositeFileInfo {
    pub name: String,
    pub path: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Local cache file path (for remote sources, this is where the downloaded file is stored)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_path: Option<String>,
}

/// Result of reading a config file
#[derive(Debug, Clone, Serialize)]
pub struct ConfigFileContent {
    pub path: String,
    pub content: String,
}

/// Get the full path to the main smartdns.conf configuration file
fn get_conf_file_path() -> Result<String, Box<dyn Error>> {
    let conf_file = unsafe {
        let ptr = crate::smartdns::smartdns_c::conf_get_conf_file();
        if ptr.is_null() {
            dns_log!(LogLevel::ERROR, "[geosite] conf_get_conf_file() returned NULL");
            return Err("Config file path is not available".into());
        }
        let s = std::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned();
        dns_log!(LogLevel::DEBUG, "[geosite] conf_get_conf_file() = '{}'", s);
        s
    };

    Ok(conf_file)
}

/// Read the content of the main smartdns.conf file
pub fn read_main_config() -> Result<ConfigFileContent, Box<dyn Error>> {
    let path = get_conf_file_path()?;
    dns_log!(LogLevel::DEBUG, "[geosite] read_main_config: path='{}', cwd='{}'",
        path,
        std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "unknown".into())
    );
    let content = fs::read_to_string(&path).map_err(|e| {
        let msg = format!("Failed to read config file '{}': {}", path, e);
        dns_log!(LogLevel::ERROR, "[geosite] {}", msg);
        msg
    })?;

    Ok(ConfigFileContent { path, content })
}

/// Write content to the main smartdns.conf file
pub fn write_main_config(content: &str) -> Result<(), Box<dyn Error>> {
    let path = get_conf_file_path()?;
    fs::write(&path, content).map_err(|e| {
        format!(
            "Failed to write config file '{}': {}",
            path, e
        )
    })?;

    dns_log!(
        LogLevel::INFO,
        "Config file '{}' updated successfully",
        path
    );
    Ok(())
}

/// Extract domain and filename from URL for cache file naming.
/// Mirrors C code _extract_url_parts() in geosite.c.
fn extract_url_parts(url: &str) -> (String, String) {
    let p = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Extract domain (up to first '/')
    let domain = match p.find('/') {
        Some(slash_pos) => p[..slash_pos].to_string(),
        None => p.to_string(),
    };

    // Extract filename from last '/' in full URL
    let filename = url
        .rsplit('/')
        .find(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "index".to_string());

    (domain, filename)
}

/// Construct the cache file path for a remote geosite-dat URL.
/// Mirrors C code in _config_geosite_dat() for URL sources.
fn geosite_cache_path(name: &str, url: &str) -> String {
    let data_dir = unsafe {
        let config_ptr = crate::smartdns::smartdns_c::geosite_get_updater_config();
        if !config_ptr.is_null() {
            let config = &*config_ptr;
            if !config.data_dir.is_empty() {
                let dir = std::ffi::CStr::from_ptr(config.data_dir.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                dns_log!(LogLevel::DEBUG, "[geosite] geosite_cache_path: data_dir from C config = '{}'", dir);
                dir
            } else {
                let dir = std::env::current_dir().unwrap_or_else(|_| "/".into())
                    .join("data").to_string_lossy().into_owned();
                dns_log!(LogLevel::DEBUG, "[geosite] geosite_cache_path: C config data_dir is empty, fallback to cwd/data = '{}'", dir);
                dir
            }
        } else {
            let dir = std::env::current_dir().unwrap_or_else(|_| "/".into())
                .join("data").to_string_lossy().into_owned();
            dns_log!(LogLevel::DEBUG, "[geosite] geosite_cache_path: geosite_get_updater_config() returned NULL, fallback to cwd/data = '{}'", dir);
            dir
        }
    };

    let (url_domain, url_filename) = extract_url_parts(url);
    let cache = if !url_filename.is_empty() {
        format!("{}/{}-{}", data_dir, url_domain, url_filename)
    } else {
        format!("{}/geosite-{}.list", data_dir, name)
    };
    dns_log!(LogLevel::DEBUG, "[geosite] geosite_cache_path: name='{}', url='{}', cache='{}'",
        name, url, cache);
    cache
}

/// Parse geosite-dat directives from config content.
/// Returns a list of GeositeFileInfo.
///
/// Format: geosite-dat <name> <path> [refresh_interval]
/// Where <path> can be a local file path or a remote URL.
pub fn parse_geosite_list(config_content: &str) -> Vec<GeositeFileInfo> {
    let mut files = Vec::new();

    for line in config_content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 || parts[0] != "geosite-dat" {
            continue;
        }

        let name = parts[1].to_string();
        let raw_path = parts[2];

        // Determine if it's a remote URL or local file
        if raw_path.starts_with("http://") || raw_path.starts_with("https://") {
            let cache_path = geosite_cache_path(&name, raw_path);
            files.push(GeositeFileInfo {
                name,
                path: raw_path.to_string(),
                source: "remote".to_string(),
                url: Some(raw_path.to_string()),
                cache_path: Some(cache_path),
            });
        } else {
            // Resolve relative path against geosite data-dir (same logic as C config parser)
            let resolved = geosite_resolve_dat_path(raw_path);
            files.push(GeositeFileInfo {
                name,
                path: resolved.clone(),
                source: "local".to_string(),
                url: None,
                cache_path: None,
            });
        }
    }

    files
}

/// JSON entry returned by C geosite_dat_list_to_json()
#[derive(Debug, serde::Deserialize)]
struct GeositeDatJsonEntry {
    name: String,
    path: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    is_url: i32,
}

/// Get the list of geosite data files from the C geosite_dat_table.
/// This reads the already-parsed hash table, so it correctly handles
/// geosite-dat entries from conf-file includes.
pub fn get_geosite_list() -> Result<Vec<GeositeFileInfo>, Box<dyn Error>> {
    let json = crate::smartdns::geosite_dat_list_to_json().map_err(|e| {
        let msg = format!("geosite_dat_list_to_json failed: {}", e);
        dns_log!(LogLevel::ERROR, "[geosite] {}", msg);
        msg
    })?;

    let entries: Vec<GeositeDatJsonEntry> = serde_json::from_str(&json).map_err(|e| {
        let msg = format!("Failed to parse geosite JSON: {} (json: {})", e, json);
        dns_log!(LogLevel::ERROR, "[geosite] {}", msg);
        msg
    })?;

    dns_log!(LogLevel::DEBUG, "[geosite] get_geosite_list: {} entries from C hash table", entries.len());

    let files: Vec<GeositeFileInfo> = entries
        .into_iter()
        .map(|e| {
            let is_remote = e.is_url != 0;
            if is_remote {
                GeositeFileInfo {
                    name: e.name,
                    path: e.url.clone().unwrap_or_default(),
                    source: "remote".to_string(),
                    url: e.url,
                    cache_path: Some(e.path),
                }
            } else {
                GeositeFileInfo {
                    name: e.name,
                    path: e.path,
                    source: "local".to_string(),
                    url: None,
                    cache_path: None,
                }
            }
        })
        .collect();

    for f in &files {
        dns_log!(LogLevel::DEBUG, "[geosite]   - name='{}', source='{}', path='{}', cache_path={:?}",
            f.name, f.source, f.path, f.cache_path);
    }

    Ok(files)
}

/// Metadata for a geosite file on disk
#[derive(Debug, Clone, Serialize)]
pub struct GeositeFileMetadata {
    /// Resolved absolute path of the file on disk
    pub path: String,
    /// File size in bytes
    pub size: u64,
    /// Last modification time as ISO 8601 string (YYYY-mm-dd HH:MM:SS)
    pub modified: String,
}

/// Get metadata for a geosite file by its resolved absolute path.
pub fn get_geosite_file_metadata(path: &str) -> Result<GeositeFileMetadata, Box<dyn Error>> {
    let resolved_path = if path.starts_with('/') {
        path.to_string()
    } else {
        let resolved = geosite_resolve_dat_path(path);
        dns_log!(LogLevel::DEBUG, "[geosite] get_geosite_file_metadata: '{}' -> '{}'", path, resolved);
        resolved
    };

    let metadata = fs::metadata(&resolved_path).map_err(|e| {
        format!(
            "Failed to stat geosite file '{}': {}",
            resolved_path, e
        )
    })?;

    let modified = metadata
        .modified()
        .ok()
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        })
        .unwrap_or_else(|| "-".to_string());

    Ok(GeositeFileMetadata {
        path: resolved_path,
        size: metadata.len(),
        modified,
    })
}

/// Information about a config file (main or sub-config via conf-file).
#[derive(Debug, Clone, Serialize)]
pub struct ConfFileInfo {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: String, // "main" or "sub"
}

/// Parse conf-file directives from the main config file content.
/// Returns a list of sub-config file paths (after glob expansion and dedup).
fn parse_conf_file_directives(content: &str, conf_dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() || parts[0] != "conf-file" {
            continue;
        }

        // Skip options like -group, -p, -q, -r, -e, -s
        let mut idx = 1;
        while idx < parts.len() && parts[idx].starts_with('-') {
            idx += 1;
        }

        if idx >= parts.len() {
            continue;
        }

        let pattern = parts[idx];

        // Resolve relative path against conf_dir
        let full_pattern = if Path::new(pattern).is_absolute() {
            pattern.to_string()
        } else {
            conf_dir.join(pattern).to_string_lossy().into_owned()
        };

        // Glob expansion
        if let Ok(entries) = glob::glob(&full_pattern) {
            for entry in entries.flatten() {
                if entry.is_file() {
                    let entry_str = entry.to_string_lossy().into_owned();
                    if seen.insert(entry_str.clone()) {
                        files.push(entry_str);
                    }
                }
            }
        } else {
            // Not a glob pattern, try as literal path
            let p = Path::new(&full_pattern);
            if p.is_file() && seen.insert(full_pattern.clone()) {
                files.push(full_pattern);
            }
        }
    }

    files
}

/// Get the list of config files (main + sub-configs via conf-file).
/// Returns main config first, followed by sub-configs.
pub fn parse_conf_files() -> Result<Vec<ConfFileInfo>, Box<dyn Error>> {
    let main_path = get_conf_file_path()?;
    let main_name = Path::new(&main_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "smartdns.conf".to_string());

    let content = fs::read_to_string(&main_path).map_err(|e| {
        format!("Failed to read config file '{}': {}", main_path, e)
    })?;

    let conf_dir = Path::new(&main_path)
        .parent()
        .ok_or_else(|| "Cannot determine config directory".to_string())?;

    let sub_paths = parse_conf_file_directives(&content, conf_dir);

    let mut files = Vec::new();
    files.push(ConfFileInfo {
        name: main_name,
        path: main_path,
        file_type: "main".to_string(),
    });

    for path in sub_paths {
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        files.push(ConfFileInfo {
            name,
            path,
            file_type: "sub".to_string(),
        });
    }

    dns_log!(
        LogLevel::DEBUG,
        "[config] parse_conf_files: {} files (1 main, {} sub)",
        files.len(),
        files.len() - 1
    );

    Ok(files)
}

/// Read the content of a geosite file by its resolved absolute path.
pub fn read_geosite_file(path: &str) -> Result<String, Box<dyn Error>> {
    let resolved_path = if path.starts_with('/') {
        path.to_string()
    } else {
        geosite_resolve_dat_path(path)
    };

    let content = fs::read_to_string(&resolved_path).map_err(|e| {
        format!(
            "Failed to read geosite file '{}': {}",
            resolved_path, e
        )
    })?;

    Ok(content)
}

/// Write content to a geosite file.
pub fn write_geosite_file(path: &str, content: &str) -> Result<(), Box<dyn Error>> {
    let resolved_path = if path.starts_with('/') {
        path.to_string()
    } else {
        geosite_resolve_dat_path(path)
    };

    // Ensure the parent directory exists
    if let Some(parent) = Path::new(&resolved_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create directory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }
    }

    fs::write(&resolved_path, content).map_err(|e| {
        format!(
            "Failed to write geosite file '{}': {}",
            resolved_path, e
        )
    })?;

    dns_log!(
        LogLevel::INFO,
        "Geosite file '{}' updated successfully",
        resolved_path
    );
    Ok(())
}

/// Validate that a path is safe to access (no path traversal, within conf directory).
/// Returns Ok(canonicalized absolute path) or Err with message.
fn validate_config_path(path: &str, conf_dir: &Path) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let p = Path::new(path);

    // Reject paths containing ..
    if path.contains("..") {
        return Err(format!("Path traversal not allowed: {}", path).into());
    }

    // Canonicalize the path (resolves symlinks and .)
    let canonical = if p.is_absolute() {
        p.to_path_buf()
    } else {
        conf_dir.join(p)
    };

    let canonical = canonical
        .canonicalize()
        .map_err(|e| format!("Cannot access path '{}': {}", path, e))?;

    // Ensure it's a regular file (not a directory, symlink to dir, etc.)
    if !canonical.is_file() {
        return Err(format!("Path '{}' is not a regular file", path).into());
    }

    Ok(canonical)
}

/// Get the directory containing the main config file.
fn get_conf_dir() -> Result<PathBuf, Box<dyn Error>> {
    let path = get_conf_file_path()?;
    let parent = Path::new(&path)
        .parent()
        .ok_or_else(|| "Cannot determine config directory".to_string())?;
    Ok(parent.to_path_buf())
}

/// Read content of any config file within the config directory.
pub fn read_config_file(path: &str) -> Result<ConfigFileContent, Box<dyn Error>> {
    let conf_dir = get_conf_dir()?;
    let resolved = validate_config_path(path, &conf_dir)?;

    let content = fs::read_to_string(&resolved).map_err(|e| {
        format!(
            "Failed to read config file '{}': {}",
            resolved.display(),
            e
        )
    })?;

    let path_str = resolved.to_string_lossy().into_owned();
    dns_log!(LogLevel::DEBUG, "[config] read_config_file: path='{}'", path_str);

    Ok(ConfigFileContent {
        path: path_str,
        content,
    })
}

/// Write content to any config file within the config directory.
pub fn write_config_file(path: &str, content: &str) -> Result<(), Box<dyn Error>> {
    let conf_dir = get_conf_dir()?;
    let resolved = validate_config_path(path, &conf_dir)?;

    fs::write(&resolved, content).map_err(|e| {
        format!(
            "Failed to write config file '{}': {}",
            resolved.display(),
            e
        )
    })?;

    dns_log!(
        LogLevel::INFO,
        "Config file '{}' updated successfully",
        resolved.display()
    );
    Ok(())
}

use std::process::Command;

/// Result of a config file validation check
#[derive(Debug, Clone, Serialize)]
pub struct ConfigValidateResult {
    pub valid: bool,
    pub message: String,
}

/// Validate a config file by running `smartdns -t -c <path>` as a subprocess.
/// Returns Ok(result) with validation outcome, or Err if the subprocess itself failed to launch.
pub fn validate_config_file(path: &str) -> Result<ConfigValidateResult, Box<dyn Error>> {
    let output = Command::new("/usr/sbin/smartdns")
        .args(["-t", "-c", path])
        .output()
        .map_err(|e| {
            let msg = format!("Failed to run smartdns -t: {}", e);
            dns_log!(LogLevel::ERROR, "[config] {}", msg);
            msg
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Patterns in tlog output that indicate config problems but don't cause non-zero exit.
    const WARN_PATTERNS: &[&str] = &["unsupported config", "process config failed"];

    if output.status.success() {
        // Even with exit code 0, tlog may have emitted warnings (e.g. "unsupported config at ...").
        // Scan the combined output for known warning patterns.
        let combined = format!("{}\n{}", stdout, stderr);
        let warnings: Vec<&str> = WARN_PATTERNS.iter().filter(|p| combined.contains(**p)).copied().collect();

        if !warnings.is_empty() {
            let message = stdout.trim().to_string();
            dns_log!(
                LogLevel::WARN,
                "[config] config validation passed with warnings for '{}': {}",
                path,
                message
            );
            Ok(ConfigValidateResult {
                valid: false,
                message,
            })
        } else {
            dns_log!(LogLevel::INFO, "[config] config validation passed for '{}'", path);
            Ok(ConfigValidateResult {
                valid: true,
                message: stdout.trim().to_string(),
            })
        }
    } else {
        // stderr contains the final "load config failed" summary,
        // stdout contains detailed per-line errors from tlog (e.g. "process config failed at ...").
        // Merge both for a complete error report.
        let mut parts = Vec::new();
        let stdout_trimmed = stdout.trim();
        let stderr_trimmed = stderr.trim();
        if !stdout_trimmed.is_empty() {
            parts.push(stdout_trimmed.to_string());
        }
        if !stderr_trimmed.is_empty() && stderr_trimmed != stdout_trimmed {
            parts.push(stderr_trimmed.to_string());
        }
        let message = parts.join("\n");
        dns_log!(LogLevel::WARN, "[config] config validation failed for '{}': {}", path, message);
        Ok(ConfigValidateResult {
            valid: false,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_geosite_list() {
        let config = r#"
server 223.5.5.5
geosite-dat tencent /smartdns/data/tencent.list
geosite-dat sina ./sina.list
geosite-dat blibli https://raw.githubusercontent.com/example/bili.list
geosite-dat gfw https://example.com/gfw.list 10
# geosite-dat commented out /data/commented.list
"#;

        let files = parse_geosite_list(config);
        assert_eq!(files.len(), 4);

        assert_eq!(files[0].name, "tencent");
        assert_eq!(files[0].source, "local");
        assert!(files[0].url.is_none());
        assert!(files[0].cache_path.is_none());

        assert_eq!(files[1].name, "sina");
        assert_eq!(files[1].source, "local");
        assert!(files[1].cache_path.is_none());

        assert_eq!(files[2].name, "blibli");
        assert_eq!(files[2].source, "remote");
        assert_eq!(files[2].url.as_deref(), Some("https://raw.githubusercontent.com/example/bili.list"));
        assert!(files[2].cache_path.is_some());

        assert_eq!(files[3].name, "gfw");
        assert_eq!(files[3].source, "remote");
        assert!(files[3].cache_path.is_some());
    }
}
