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
use std::error::Error;
use std::fs;
use std::path::Path;

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
