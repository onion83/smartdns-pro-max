# CODEBUDDY.md This file provides guidance to CodeBuddy when working with code in this repository.

## Build Commands

**C Core (Makefile):**
```bash
make -j$(nproc)                    # Build smartdns binary only
make WITH_UI=1 -j$(nproc)          # Build with Rust UI plugin
make clean                         # Clean build artifacts
make install DESTDIR=/path         # Install to destination
```

**Rust Plugin (plugin/smartdns-ui/):**
```bash
cd plugin/smartdns-ui
cargo build --release              # Build smartdns_ui.so (cdylib)
cargo test                         # Run Rust unit tests
```
Build system uses bindgen to generate FFI bindings from C headers. The plugin is a cdylib loaded by C via dlopen().

**Tests (test/):**
```bash
make -C test test                  # Build and run gtest suite
./test/test.bin --gtest_filter=*geosite*  # Run specific test pattern
```
Tests use gtest framework, link against libsmartdns-test.a built from src/.

**虚拟化环境**
```bash
orb start
```

**Docker (默认使用 arm64 原生镜像，macOS Apple Silicon 无需模拟):**
```bash
# Build base image ONCE (~5 min):
docker buildx build -f Dockerfile.builder-base-arm64 --platform linux/arm64 \
  --load -t smartdns-builder-arm64-base .

# Build dynamic image (~2 min):
docker buildx build -f Dockerfile.dynamic-arm64 --platform linux/arm64 \
  --load -t smartdns-dynamic-arm64 .
```
Base image contains: musl toolchain, Rust + bindgen, static OpenSSL/libcurl.
Dynamic image: fully dynamic linking, plugin loads via dlopen(), runtime image includes gdb + strace.

**注意**: 每次 Docker 构建前建议删除 Rust 插件 target 目录避免缓存问题：
```bash
rm -rf plugin/smartdns-ui/target
```

**Docker Run:**
```bash
docker stop $(docker ps -q --filter ancestor=smartdns-dynamic-arm64) 2>/dev/null

docker run --rm -d --name smartdns-arm64-test \
    -v /Users/onion/C/smartdns/smartdns-geosite-ui.conf:/etc/smartdns/smartdns.conf \
    -v /Users/onion/C/smartdns/sub-conf-a.conf:/etc/smartdns/sub-conf-a.conf \
    -v /Users/onion/C/smartdns/sub-conf-b.conf:/etc/smartdns/sub-conf-b.conf \
    -v /Users/onion/C/smartdns/data:/smartdns/data \
    -v /tmp/smartdns-lib:/var/lib/smartdns \
    -p 53:53/udp -p 53:53 -p 6080:6080 \
    smartdns-dynamic-arm64 smartdns -f -x
```

**x86_64 镜像**（仅在需要 x86 环境时使用）:
```bash
# Base: docker buildx build -f Dockerfile.builder-base --platform linux/amd64 --load -t smartdns-builder-x86_64-base .
# Build: DOCKER_BUILDKIT=0 docker build -f Dockerfile.dynamic-x86_64 --platform linux/amd64 -t smartdns-dynamic-x86_64 .
```

## Architecture Overview

### C Core (src/, ~265 files, ~100K LOC)

**Major Subsystems:**
- `dns_server/` — DNS server core: UDP/TCP/DoT/DoH/DoQ/DoH3 listeners, request handling, caching
- `dns_client/` — Upstream DNS query client, speed measurement, parallel queries
- `dns_conf/` — Configuration parser (smartdns.conf), geosite/geodata loading, domain rules
- `fast_ping/` — ICMP/TCP ping for IP speed testing
- `dns_plugin.c` — Plugin loader using POSIX dlopen/dlsym

**Entry Point:** `src/smartdns.c` — main() parses CLI args, loads config, starts DNS server

**Plugin System (C side):**
- Plugins are C dynamic libraries (.so) loaded at runtime via dlopen()
- Must export 3 ABI symbols:
  - `dns_plugin_init(struct dns_plugin *)` — initialize plugin
  - `dns_plugin_exit(struct dns_plugin *)` — cleanup
  - `dns_plugin_api_version()` — returns `0x00000101`
- Register hooks via `struct smartdns_operations`:
  - `server_recv()` — intercept incoming DNS packets
  - `server_query_complete()` — called when query finishes
  - `server_log()` / `server_audit_log()` — receive log messages
- Plugin shares address space with main process — plugin crash crashes main process
- Monitor process (`_smartdns_run_monitor()`) forks and auto-restarts on crash

### Rust Plugin (plugin/smartdns-ui/)

**Purpose:** Provides HTTP REST API + SQLite database for WebUI on port 6080

**Structure:**
- `Cargo.toml` — cdylib crate, dependencies: hyper, tokio, rusqlite, serde_json, bindgen
- `build.rs` — runs bindgen to generate FFI bindings from `src/include/smartdns/*.h`
- `src/lib.rs` — plugin entry: ctor/dtor register `SmartdnsOperations` trait impl
- `src/smartdns.rs` — FFI wrappers for C functions (config, geosite, logging)
- `src/http_server_api.rs` — REST API handlers (~1800 lines)
- `src/file_ops.rs` — File I/O for config/geosite files
- `src/db/` — SQLite schema and queries for stats/logs

**FFI Pattern:**
```rust
// C function: int geosite_download_url_files_sync(void);
pub fn geosite_download_url_files_sync() -> Result<(), String> {
    unsafe {
        let ret = smartdns_c::geosite_download_url_files_sync();
        if ret == 0 { Ok(()) } else { Err("failed".to_string()) }
    }
}
```
Bindgen generates `smartdns_c` module from C headers. Rust wraps unsafe calls with Result types.

**HTTP API Endpoints (examples):**
- `GET /api/config` — Get main config file content
- `PUT /api/config` — Save config file
- `GET /api/config/geosite/list` — List geosite data sources
- `POST /api/config/geosite/download` — Force download remote geosite files
- `GET /api/stats` — Query statistics from SQLite

**Threading:** Plugin creates independent Tokio runtime inside cdylib. HTTP server runs on this runtime, not on C's threads.

### Frontend (smartdns-webui/)

**Tech Stack:** Next.js 16 (App Router) + React 19 + MUI 7 + TanStack Query + CodeMirror

**Key Files:**
- `next.config.mjs` — Dev mode rewrites `/api/*` → `http://127.0.0.1:6080/api/*`; Production uses `output: 'export'` for static SPA
- `src/lib/backend/server.ts` — API client class with typed fetch methods
- `src/components/dashboard/settings/` — Config editor panels (main config, geosite)

**Data Fetching Pattern:**
- TanStack Query's `useQuery` for declarative data fetching
- `useMutation` for save/download operations
- Query invalidation after mutations to refetch fresh data

**Development:**
```bash
cd smartdns-webui
npm run dev              # Dev server on :3000 with API proxy
npm run build            # Production build (static export)
npm run lint             # ESLint
```

### Geosite System

**C Side (src/dns_conf/geosite.c):**
- `geosite_dat_table` — Hash table of configured geosite data sources
- `geosite_download_url_files_sync()` — Download remote URLs with ETag caching
- `geosite_download_url_files_sync_force()` — Force download (clear ETags, bypass 304)
- `geosite_reload_rules()` — Reload domain rules from downloaded files

**Rust FFI:**
- `smartdns.rs` wraps C functions for download/reload
- `file_ops.rs` provides `get_geosite_file_metadata()` for file info (path, size, mtime)

**Frontend:**
- `geosite-config-panel.tsx` — Lists sources, editor with 3-line metadata header, Update button for remote sources

### Configuration

**Main Config (smartdns.conf):**
- Parsed by `dns_conf/conf.c` via `config_load()`
- Supports `conf-file` directive to include sub-configs
- Geosite: `geosite-dat <name> <path-or-url>` — path can be local file or URL

**Geodata Directory:** `/smartdns/data/` — stores downloaded geosite files, cache for remote URLs

### Memory Management Across FFI

**C → Rust:**
- C functions returning strings (e.g., `geosite_dat_list_to_json()`) malloc memory
- Rust receives `CString`, converts to `String`, then must free C memory:
  ```rust
  let c_str = smartdns_c::geosite_dat_list_to_json();
  let result = CString::from_raw(c_str).into_string()?;
  // CString destructor frees the C memory
  ```

**Rust → C:**
- Rust strings passed to C must be null-terminated: `CString::new(s)?.as_ptr()`
- C callbacks must not panic across FFI boundary — catch_unwind in Rust wrappers

### Testing Strategy

**Unit Tests (test/):**
- gtest framework, link against `libsmartdns-test.a` (C code compiled with -DTEST)
- Integration tests for geosite reload, updater, datadir

**Rust Tests:**
- Standard `cargo test` in plugin/smartdns-ui/
- Mock C functions via trait injection where possible

**Manual Testing:**
- Docker container with config file mounts
- Frontend dev server proxying to container's API port
- 根据修改的文件，确认是否需要重新编译 rust 插件，然后重新启动容器（如有运行实例可以自动kill掉），然后再访问前端页面，查看是否生效