# SmartDNS Pro Max — Design Intent and Development History

> This document records the design intent, major development history, and key
> problems solved along the way for the `feature/geosite` branch (SmartDNS Pro Max).
> For usage-level documentation, see [geosite-config_en.md](geosite-config_en.md)
> and the root [ReadMe_en.md](../ReadMe_en.md).
> 中文版见 [design-and-history.md](design-and-history.md)。

---

## 1. Design Intent

### 1.1 Background

Upstream [pymumu/smartdns](https://github.com/pymumu/smartdns) is a fast local DNS
server whose core strength is concurrent multi-upstream resolution with IP speed
testing. However, it has clear gaps in the real-world "domain-based traffic splitting"
scenario:

- No group-based routing mechanism over **geosite domain lists** (comparable to the
  geosite.dat capability in the v2ray/clash ecosystem);
- No **automatic download, change detection, or hot reload** of remote lists;
- No way to visually manage geosite data sources, and no way to answer the most
  common troubleshooting question — "why did this domain hit this rule and which
  upstream did it use?"

### 1.2 Design Goals

This fork is built around "a complete management loop for geosite domain routing",
with four goals:

1. **Core capability**: implement the `geosite-dat` / `geosite-set` / `domain-rules`
   rule system in the C core, supporting both local list files and remote URLs;
   clear the affected DNS caches when rules are hot-reloaded;
2. **Diagnostics**: provide the `--check-domain-rule` CLI and a WebUI rule inspector
   that output the complete rule-matching chain (rule ID, action, cache status, server
   group, and real query results per server), with JSON output for scripting;
3. **WebUI management**: reuse the smartdns-ui Rust plugin and expose geosite data
   source lists, file metadata, single-file download, forced download, sub-config
   editing, etc. over FFI, with a visual frontend;
4. **Reproducible builds**: rework the Docker build pipeline (amd64/arm64) with
   builder / dynamic / dev image variants, and solve static compilation of the Rust
   plugin (musl + OpenSSL/libcurl).

### 1.3 Architecture Layers

```
┌───────────────────────────────────┐
│  WebUI (Next.js, static export)   │  geosite panel / rule inspector / config editor
├───────────────────────────────────┤
│  smartdns-ui plugin (Rust cdylib) │  HTTP API (port 6080) + SQLite
│   └─ FFI wrappers (smartdns.rs)   │
├───────────────────────────────────┤
│  C core (src/)                    │
│   ├─ dns_conf/geosite.c           │  data sources, download, diff, hot reload
│   ├─ dns_conf/domain_rule.c       │  rule matching, chain export (check-domain-rule)
│   └─ smartdns.c                   │  CLI entry (--check-domain-rule)
└───────────────────────────────────┘
```

Key design constraints:

- **The plugin shares the address space with the main process** (loaded via dlopen),
  so all strings crossing the Rust↔C boundary follow the ownership convention
  "C mallocs → Rust takes over and frees via `CString::from_raw`", and panics must
  never cross the FFI boundary.
- **The geosite list treats the C hash table `geosite_dat_table` as the single source
  of truth.** The Rust side does not parse config files itself; instead it calls C-side
  JSON export functions, so geosite directives in the main config and in any
  `conf-file` sub-configs take effect uniformly by construction.

---

## 2. Development History

Organized by timeline (see git log for the full history; only major milestones are listed).

### 2026-04 — geosite core and management loop take shape

| Commit | Description |
|------|------|
| `eec96d7` | Initial geosite domain-list support: `geosite.c/h` (~2400 lines), `domain_rule.c` rule extensions, first WebUI geosite panel |
| `f6a7bd5` | Data-file hot reload; `a2ad637` code-review fixes (hash lookup, reload logic, log cleanup); `0b35f47` fixed reload crash |
| `fd27448` → `50167f4` | Iterations on the `--check-domain-rule` CLI: sync download, code dedup, download safety (temp dir + atomic write), fast geosite startup |
| `6629d7f` / `ff0ee93` / `bb8288a` | Docker build pipeline rework, static plugin release support, OpenSSL/libcurl static-build hardening |
| `3793493` / `c50ffaf` | geosite file metadata API, single-file download, reload fix; **geosite list now exported from the C hash table via FFI** (fixing Rust-side failure to see sub-configs) |
| `3c22682` | Sub-config online editing + config validation API + config parser fix |

### 2026-05 — rule-chain diagnostics and stability fixes

| Commit | Description |
|------|------|
| `cc84e3d` / `3fb2a10` / `ee2212e` | `--check-domain-rule` and rule-chain API: added `IpPingResult` and cache fields, IPv6 server support, result selection per `response_mode` |
| `f1b885f` / `873b456` | Correctly reset `last_update` timers when downloads report no change (both URL and local-file paths) |
| `2201d89` / `2600079` | Activated geosite config; fixed TCP ping use-after-free crash (see §3.2) |
| `e2df55b` / `4541604` | Merged upstream fast_ping race-condition fixes |

### 2026-11 — build system and documentation

| Commit | Description |
|------|------|
| `26adf04` | Build support for custom dependency paths via `LOCAL_DEPS_PREFIX` (e.g. `/opt`) |
| `55b289c` / `6c5338e` / `b62880e` | arm64 Dockerfile rework with gdb/strace debugging tools; amd64 support |
| `824cfca` | Switched to bindgen-cli for the musl target; fixed `http_server_stream` compile error |
| `5c6a19b` / `bc5685e` | README rewritten with the SmartDNS Pro Max fork positioning and cross-repo links |

Change scale (relative to upstream `origin/master`):

- C core: 23 files in `src/`, roughly **+4000 lines** (geosite.c alone ~2400 lines)
- Rust plugin: 5 files in `plugin/smartdns-ui/`, roughly **+1500 lines** (file_ops.rs ~675 lines)
- Total: 32 files changed, **+5662 / -58**

---

## 3. Key Problems and Solutions

Pitfalls encountered during development, grouped by topic.

### 3.1 Geosite subsystem

**Rust side could not see geosite directives in `conf-file` sub-configs** (`c50ffaf`)

- Problem: `file_ops::get_geosite_list()` initially parsed the main config file text
  directly in Rust and could not handle `geosite-dat` directives inside sub-configs
  included via `conf-file`, so the WebUI list diverged from the rules actually in effect.
- Solution: `geosite.c` gained `geosite_dat_list_to_json()`, which walks the parsed
  `geosite_dat_table` hash table (`hash_for_each`) and builds a
  `[{name, path, url, is_url}]` JSON array; Rust fetches it over FFI and frees the
  C memory; the frontend sorts alphabetically and invalidates its cache after saves.

**argv corrupted during reload, causing bogus `-n` parsing**

- Problem: `_config_domain_rules()` calls `getopt_long_only()` internally, which
  **reorders the argv array**. If the original argv is replayed during hot reload,
  subsequent entries can turn into `-n`, corrupting parsing.
- Solution: pass a shallow argv copy (`calloc + memcpy`) to the parsing function to
  protect the original replay argv. Verified by the three-step
  `integration-test-geosite-reload.sh` integration test.

**`last_update` not reset when downloads report no change** (`f1b885f` / `873b456`)

- Problem: when a remote URL returned 304 / a local file's mtime was unchanged, the
  update timer was not reset, causing an immediate repeated download check on the
  next cycle.
- Solution: reset the `last_update` timer on the "no change" branch in both the
  URL download and local-file detection paths.

### 3.2 Stability (crashes)

**TCP ping use-after-free**

- Problem: TCP ping triggered by `speed-check-mode tcp:443` had a use-after-free
  that crashed the process in practice.
- Solution: short-term workaround with `speed-check-mode ping` (ICMP) (`2600079`),
  followed by merging the upstream fast_ping race fix (`e2df55b`), then restoring
  TCP ping capability in `2201d89`.

**fast_ping race condition**

- Problem: upstream fast_ping had a race condition causing occasional crashes under
  high-concurrency probing.
- Solution: tracked and merged the upstream fix, keeping the branch regularly synced
  with `origin/master` (multiple merges).

**geosite hot-reload crash** (`0b35f47` / `f6a7bd5` series)

- Problem: consistency between the rule table and caches was not guaranteed during
  reload, triggering crashes.
- Solution: reworked reload logic (hash lookup instead of linear scan, phased rule
  table replacement, clearing caches of affected domains), plus code-review fixes
  (`a2ad637`).

### 3.3 Rule-chain diagnostics (check-domain-rule)

**No IPv6 server support**

- Problem: `_parse_server_addr()` and `_resolve_udp_query()` only handled IPv4.
- Solution: the parser now accepts `[::1]:53` format; the query layer switched to
  `sockaddr_storage` with `AF_INET6`.

**Inconsistent response_mode display** (`3fb2a10` / `ee2212e`)

- Problem: the rule-chain result did not reflect the effective `response-mode`, and
  Rust emitted enum values as raw numbers that the frontend mapped incorrectly.
- Solution: added a `response_mode` field to `domain_rule_check_result` and
  `domain_rule_resolve_chain` (defaults to the global setting, overridable per rule);
  `FIRST_PING_IP` takes the first server with an IP, while `FASTEST_RESPONSE` /
  `FASTEST_IP` take the one with the lowest ping_ms; Rust→frontend conversion is
  uniformly string-based.

**Safe staging for curl downloads**

- Solution: staging files moved to the system temp directory (`$TMPDIR` → `P_tmpdir`
  → `/tmp`); extracted `_geosite_download_one_url()` as a shared core used by both
  async/sync paths; `geosite_download_url_files_sync()` covers URL downloads
  (ETag/retries) and local-file change detection (mtime/crc32/md5).

### 3.4 Build and toolchain

**Makefile syntax errors** (`c6517eb`)

- Main Makefile: `export CFLAGS="$(pkg-config ...)"` is invalid syntax;
  changed to `export CFLAGS := $(shell pkg-config --cflags openssl)`;
- `src/Makefile`: `BASE_FILE_NAME` quote definition error, changed to
  `-DBASE_FILE_NAME=\"$(notdir $<)\"`; non-static builds were missing `-lz`,
  causing zlib link failures.

**musl-target bindgen**

- Problem: the default bindgen does not work for musl static builds, and
  `http_server_stream` failed to compile.
- Solution: switched to bindgen-cli for the musl target (`824cfca`) and fixed the
  corresponding stream-processing code.

**libgcc missing in the dynamic runtime image** (`ef17b73`)

- Problem: the cdylib plugin failed to load in the runtime image due to missing
  `libgcc_s`.
- Solution: installed libgcc in the runtime image.

**Rust incremental compilation cache reusing stale artifacts**

- Problem: after C header changes, bindgen-generated bindings could come from cache,
  leading to inconsistent behavior.
- Solution: agreed convention of running `rm -rf plugin/smartdns-ui/target` before
  every Docker build (documented in CODEBUDDY.md).

**Local compilation on macOS is not viable**

- Conclusion: FFI and linking depend on the Linux toolchain; always build via Docker
  (builder → dynamic, two stages); macOS locally is used for frontend development only.
