# Geosite Configuration Guide

The geosite module provides group-based rule management over domain lists, supporting both local files and remote URL data sources, plus runtime hot updates (automatic download, diff comparison, incremental rule add/remove, and clearing the affected DNS caches).

---

## Directive Overview

| Directive | Description |
|------|------|
| `geosite-updater` | Global update settings (interval, diff algorithm, HTTP parameters, etc.) |
| `geosite-dat` | Register a domain data source (local file or remote URL) |
| `geosite-set` | Combine multiple geosite-dat sources into one set |
| `domain-rules` | Reference a geosite-set and apply DNS rules to matching domains |

---

## geosite-updater

Global update parameters that affect the download and change-detection behavior of all geosite-dat sources.

```
geosite-updater [interval] [options...]
```

### Positional Arguments

| Argument | Description | Default |
|------|------|--------|
| `interval` | Default update interval (seconds) for all geosite-dat sources | `300` (5 minutes) |

### Options

| Option | Description | Default |
|------|------|--------|
| `-data-dir DIR` | Local cache directory for URL data sources | `{working dir}/data` |
| `-diff-algo ALGO` | File change-detection algorithm: `mtime`, `crc32`, `md5` | `mtime` |
| `-http-use-etag yes/no` | Use HTTP ETag conditional requests (requires libcurl at build time) | `no` |
| `-user-agent UA` | User-Agent for HTTP downloads | `smartdns/{version}` |
| `-http-timeout SEC` | Per-download HTTP timeout (seconds), range 1-3600 | `300` |
| `-http-retry N` | Retry count on download failure, range 0-5 | `2` |
| `-http-retry-intval SEC` | Retry interval (seconds), range 1-60 | `3` |

### Example

```conf
geosite-updater 300 -data-dir /smartdns/data -diff-algo crc32 \
                  -http-use-etag yes -http-timeout 10 \
                  -http-retry 3 -http-retry-intval 3
```

---

## geosite-dat

Register a domain-list data source. It can be a local file path or a remote URL.

```
geosite-dat <name> <file-or-url> [interval] [options...]
```

### Arguments

| Argument | Description |
|------|------|
| `name` | Data source name (unique identifier), e.g. `google`, `gfw` |
| `file-or-url` | Local file path or HTTP(S) URL |
| `interval` | Update interval (seconds), overriding the global default. `0` disables automatic updates |

### Options

| Option | Description |
|------|------|
| `-name NAME` | Data source name (same as positional argument) |
| `-file FILE` | File path or URL (same as positional argument) |
| `-interval SEC` | Update interval (same as positional argument) |

### Path Resolution Rules

| Path Format | Resolution | Example |
|----------|----------|------|
| Absolute path | Used as-is | `/etc/smartdns/google.list` |
| `./xxx` or `../xxx` | Relative to data-dir | `./google.list` → `{data-dir}/google.list` |
| Bare filename | data-dir + filename | `google.list` → `{data-dir}/google.list` |
| `http://...` or `https://...` | Remote URL, auto-downloaded into data-dir | `https://example.com/domains.list` |

### Cache File Naming for URLs

Local cache files of URL sources are stored under data-dir, named `{domain}-{filename}`:
- `https://example.com/path/gfw.list` → `{data-dir}/example.com-gfw.list`
- `https://raw.githubusercontent.com/xxx/domains` → `{data-dir}/raw.githubusercontent.com-domains`

### Domain List Format

One domain per line, with the following formats supported:

```
# Comment line
*.google.com          # Wildcard match
.example.com          # Suffix match (equivalent to *.example.com + example.com)
+example.com          # Include match (matches itself and all subdomains)
google.com            # Exact match
xn--nxasmq6b.com      # Punycode domain (auto-converted from UTF-8)
```

### Examples

```conf
# Local file, checked for changes every 30 seconds
geosite-dat tencent /smartdns/data/tencent.list 30

# Bare filename, looked up automatically under data-dir
geosite-dat google google.list

# Remote URL, using the global default interval
geosite-dat gfw https://raw.githubusercontent.com/.../gfw.list

# Remote URL, 60-second update interval
geosite-dat openai https://raw.githubusercontent.com/.../openai.list 60

# Disable automatic updates
geosite-dat custom /etc/smartdns/custom.list 0
```

---

## geosite-set

Combine multiple geosite-dat sources into a single set for one-shot reference in `domain-rules`.

```
geosite-set <set-name> <dat1> [dat2] [dat3] ...
```

### Arguments

| Argument | Description |
|------|------|
| `set-name` | Set name |
| `dat1, dat2, ...` | Names of referenced geosite-dat sources (must be registered) |

### Example

```conf
# Define data sources
geosite-dat tencent /smartdns/data/tencent.list
geosite-dat sina /smartdns/data/sina.list
geosite-dat google google.list

# Combine into sets
geosite-set cn-services tencent sina
geosite-set search-services google
```

---

## domain-rules (Referencing geosite-sets)

Use the `/geosite-set:<name>/` syntax to reference a geosite-set in `domain-rules`.

```
domain-rules /geosite-set:<set-name>/ [options...]
```

When any data source in a geosite-set changes, the corresponding domain-rules are hot-updated automatically:
- Rules and DNS caches of removed domains are deleted
- Newly added domains have their rules created automatically

### Example

```conf
# Domains in the cn-services set use the domestic DNS server
domain-rules /geosite-set:cn-services/ -n cn

# Domains in the gfw set use the proxy DNS
domain-rules /geosite-set:gfw-services/ -n free

# Ad domains return an empty address
domain-rules /geosite-set:ad-services/ -n cn -address 127.0.0.1
```

---

## Full Configuration Example

```conf
# Upstream DNS server groups
server 223.5.5.5 -g cn -e
server 8.8.8.8   -g free -e
server 119.29.29.29 -g default

# Global update settings
geosite-updater 300 -data-dir /smartdns/data -diff-algo crc32 \
                  -http-use-etag yes -http-timeout 10 -http-retry 3

# Data source definitions
geosite-dat tencent /smartdns/data/tencent.list 30
geosite-dat sina    ./sina.list 30
geosite-dat gfw     https://raw.githubusercontent.com/.../gfw.list 60
geosite-dat openai  https://raw.githubusercontent.com/.../openai.list
geosite-dat ad      https://raw.githubusercontent.com/.../category-ads-all.list

# Set definitions
geosite-set cn-services tencent sina
geosite-set ai-services openai
geosite-set gfw-services gfw
geosite-set ad-services ad

# Rule references
domain-rules /geosite-set:cn-services/ -n cn
domain-rules /geosite-set:ai-services/ -n free -address #6
domain-rules /geosite-set:gfw-services/ -n free
domain-rules /geosite-set:ad-services/ -n cn -address 127.0.0.1
```

---

## Runtime Behavior

### Startup Phase

1. Parse the `geosite-updater` global settings
2. Parse `geosite-dat` and register data sources:
   - **Local file**: verify existence, record initial state (mtime/crc32/md5), cache the domain list
   - **Remote URL**: download synchronously if no local cache exists; otherwise use the cache directly
3. Parse `geosite-set` and build set-to-source references
4. Parse `domain-rules`, loading domains into the ART tree

### Runtime Updates (Linux)

1. Periodic polling (every 5 seconds by default) checks whether data sources need updating
2. **URL sources**: downloads are submitted to a background thread asynchronously, without blocking the main loop
3. When a download completes, the main thread is notified via eventfd and runs `geosite_reload_rules()`:
   - Diff the old and new domain lists (pure in-memory diff)
   - Delete ART rules + DNS caches of removed domains
   - Re-add rules for all current domains
4. After the update, the domain cache is swapped and the next change-detection cycle begins

### Change-Detection Algorithms

| Algorithm | Description | Typical Use |
|------|------|----------|
| `mtime` | Compare file modification times (default) | Local files, low overhead |
| `crc32` | Compare CRC32 checksums | URL-downloaded files requiring accurate content-change detection |
| `md5` | Compare MD5 hashes | Highest accuracy, slightly higher CPU cost |

### Startup Logs

Once running normally, the geosite feature logs at NOTICE level:
```
[2026-04-03 14:00:00,000][NOTICE] ... geosite feature geosite-mod-202604031400
[2026-04-03 14:00:00,000][NOTICE] ... geosite: 8 dat source(s) (3 local, 5 url), 5 set rule(s), interval=300, diff_algo=crc32
```

During updates, INFO-level logs are emitted:
```
[2026-04-03 14:05:00,000][ INFO] ... geosite: reloading domain rules (async update)
[2026-04-03 14:05:00,100][ INFO] ... geosite: reload complete, 15230 domains active, 12 rules removed
```
