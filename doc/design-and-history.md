# SmartDNS Pro Max — 设计意图与开发历史

> 本文档记录 `feature/geosite` 分支（SmartDNS Pro Max）的设计意图、主要历史修改，
> 以及开发过程中遇到的关键问题与解决方案。功能层面的使用说明见
> [geosite-config.md](geosite-config.md) 与根目录 [ReadMe.md](../ReadMe.md)。
> English version: [design-and-history_en.md](design-and-history_en.md)。

---

## 1. 设计意图

### 1.1 背景

上游 [pymumu/smartdns](https://github.com/pymumu/smartdns) 是一个高速本地 DNS 服务器，
核心优势在于多上游并发解析与 IP 测速。但在「域名分流」这一真实使用场景中存在明显缺口：

- 缺少基于 **geosite 域名列表** 的分组分流机制（类似 v2ray/clash 生态的 geosite.dat 能力）；
- 没有远程列表的 **自动下载、变更检测与热重载**；
- 没有可视化手段管理 geosite 数据源，排障时也无法回答
  「这个域名为什么命中了这条规则、走了哪台上游」这类最常见的问题。

### 1.2 设计目标

本分支围绕「geosite 域名分流的完整管理闭环」展开，设定了四个目标：

1. **内核能力**：在 C 核心中实现 `geosite-dat` / `geosite-set` / `domain-rules` 规则体系，
   支持本地 list 文件与远程 URL 两种数据源，热重载规则时同步清除受影响的 DNS 缓存；
2. **诊断工具**：提供 `--check-domain-rule` CLI 与 WebUI 规则检查器，输出完整规则匹配链
   （规则 ID、动作、cache 状态、服务器组、每台服务器的真实查询结果），JSON 输出便于脚本化；
3. **WebUI 管理**：复用 smartdns-ui Rust 插件，通过 FFI 暴露 geosite 数据源列表、文件元数据、
   单文件下载、强制下载、子配置编辑等 API，前端可视化编辑；
4. **可复现构建**：重构 Docker 构建管线（amd64/arm64），提供 builder / dynamic / dev 三类镜像，
   并解决 Rust 插件静态编译（musl + OpenSSL/libcurl）问题。

### 1.3 架构分层

```
┌─────────────────────────────┐
│  WebUI (Next.js, 静态导出)   │  geosite 面板 / 规则检查器 / 配置编辑器
├─────────────────────────────┤
│  smartdns-ui 插件 (Rust cdylib) │  HTTP API (端口 6080) + SQLite
│   └─ FFI 封装 (smartdns.rs)  │
├─────────────────────────────┤
│  C 核心 (src/)               │
│   ├─ dns_conf/geosite.c      │  数据源管理、下载、diff、热重载
│   ├─ dns_conf/domain_rule.c  │  规则匹配、规则链导出 (check-domain-rule)
│   └─ smartdns.c              │  CLI 入口 (--check-domain-rule)
└─────────────────────────────┘
```

关键设计约束：

- **插件与主进程共享地址空间**（dlopen 加载），因此所有 Rust↔C 边界上的字符串
  都遵循「C malloc 分配 → Rust `CString::from_raw` 接管并释放」的内存归属约定，
  并避免 panic 跨越 FFI 边界。
- **geosite 列表以 C 哈希表 `geosite_dat_table` 为唯一事实来源**。Rust 端不自行解析
  配置文件，而是调用 C 侧导出的 JSON 接口，保证主配置 / `conf-file` 子配置中的
  geosite 指令天然统一生效。

---

## 2. 历史修改记录

按时间线整理（完整提交历史见 git log，此处只列主要节点）。

### 2026-04 — geosite 内核与管理闭环成型

| 提交 | 内容 |
|------|------|
| `eec96d7` | 初始 geosite 域名列表支持：`geosite.c/h`（约 2400 行）、`domain_rule.c` 规则扩展、WebUI geosite 面板雏形 |
| `f6a7bd5` | 数据文件热重载支持；`a2ad637` 代码评审修复（哈希查找、reload 逻辑、日志清理）；`0b35f47` 修复 reload 崩溃 |
| `fd27448` → `50167f4` | `--check-domain-rule` CLI 多轮迭代：同步下载、代码去重、下载安全（临时目录 + 原子写入）、geosite 快速启动 |
| `6629d7f` / `ff0ee93` / `bb8288a` | Docker 构建管线重构、插件静态 release 支持、OpenSSL/libcurl 静态编译加固 |
| `3793493` / `c50ffaf` | geosite 文件元数据 API、单文件下载、reload 修复；**geosite 列表改由 C 哈希表经 FFI 导出**（解决 Rust 解析子配置失效问题） |
| `3c22682` | 子配置在线编辑 + 配置校验 API + 配置解析器修复 |

### 2026-05 — 规则链诊断增强与稳定性修复

| 提交 | 内容 |
|------|------|
| `cc84e3d` / `3fb2a10` / `ee2212e` | `--check-domain-rule` 与规则链 API：加入 `IpPingResult` 与 cache 字段、IPv6 服务器支持、按 `response_mode` 选择展示结果 |
| `f1b885f` / `873b456` | 下载内容无变化时正确重置 `last_update` 定时器（本地文件与 URL 两种路径） |
| `2201d89` / `2600079` | 激活 geosite 配置；修复 TCP ping use-after-free 崩溃（详见 §3.2） |
| `e2df55b` / `4541604` | 合并上游 fast_ping 竞态修复 |

### 2026-11 — 构建体系与文档完善

| 提交 | 内容 |
|------|------|
| `26adf04` | 构建支持 `LOCAL_DEPS_PREFIX`(/opt) 自定义依赖路径 |
| `55b289c` / `6c5338e` / `b62880e` | arm64 Dockerfile 重构、加 gdb/strace 调试工具、amd64 架构支持 |
| `824cfca` | musl 目标改用 bindgen-cli，修复 `http_server_stream` 编译错误 |
| `5c6a19b` / `bc5685e` | README 重写为 SmartDNS Pro Max fork 定位，跨仓库互链 |

改动规模（相对上游 `origin/master`）：

- C 核心：`src/` 23 个文件，约 **+4000 行**（geosite.c 单文件 ~2400 行）
- Rust 插件：`plugin/smartdns-ui/` 5 个文件，约 **+1500 行**（file_ops.rs ~675 行）
- 合计 32 个文件，**+5662 / -58**

---

## 3. 关键问题与解决方案

开发过程中踩过的坑，按主题归类如下。

### 3.1 geosite 子系统

**Rust 端无法感知 `conf-file` 子配置中的 geosite 指令**（`c50ffaf`）

- 问题：最初 `file_ops::get_geosite_list()` 在 Rust 端直接解析主配置文件文本，
  无法处理 `conf-file` 引入的子配置中的 `geosite-dat`，导致 WebUI 列表与实际生效规则不一致。
- 方案：C 端 `geosite.c` 新增 `geosite_dat_list_to_json()`，遍历已解析的
  `geosite_dat_table` 哈希表（`hash_for_each`），构建 `[{name, path, url, is_url}]` JSON 数组；
  Rust 端经 FFI 取回并释放 C 内存；前端按字母序展示，保存后主动失效缓存重新拉取。

**reload 时 argv 被破坏导致误解析 `-n`**

- 问题：`_config_domain_rules()` 内部调用 `getopt_long_only()` 会**重排 argv 数组**。
  热重载时若直接 replay 原始 argv，后续项会变成 `-n`，造成解析错乱。
- 方案：用 `calloc + memcpy` 构造 argv 浅拷贝传给解析函数，保护原始 replay argv。
  配套集成测试 `integration-test-geosite-reload.sh` 三步验证。

**下载无变化时 `last_update` 不重置**（`f1b885f` / `873b456`）

- 问题：远程 URL 返回 304 / 本地文件 mtime 未变时，更新定时器未重置，
  导致下一次周期到达后立即重复触发下载检测。
- 方案：分别在 URL 下载与本地文件两条检测路径上，于「无变更」分支中重置
  `last_update` 计时。

### 3.2 稳定性（崩溃类）

**TCP ping use-after-free**

- 问题：`speed-check-mode tcp:443` 触发 TCP ping 时存在 use-after-free，
  实测导致进程崩溃。
- 方案：短期以 `speed-check-mode ping`（ICMP）规避（`2600079`），随后合并
  上游 fast_ping 竞态修复（`e2df55b`），并在 `2201d89` 中恢复 TCP ping 能力。

**fast_ping 竞态**

- 问题：上游 fast_ping 存在竞态条件，高并发探测时偶发崩溃。
- 方案：跟踪并合并上游修复，保持分支与 `origin/master` 定期同步（多次 merge）。

**geosite 热重载崩溃**（`0b35f47` / `f6a7bd5` 系列修复）

- 问题：reload 过程中规则表与缓存的一致性未保证，触发崩溃。
- 方案：重构 reload 逻辑（hash 查找替代线性扫描、分阶段替换规则表、
  清除受影响域名缓存），并做代码评审修复（`a2ad637`）。

### 3.3 规则链诊断（check-domain-rule）

**IPv6 服务器不支持**

- 问题：`_parse_server_addr()` 与 `_resolve_udp_query()` 只支持 IPv4。
- 方案：解析层支持 `[::1]:53` 格式；查询层改用 `sockaddr_storage` 与 `AF_INET6`。

**response_mode 展示不一致**（`3fb2a10` / `ee2212e`）

- 问题：规则链结果未反映实际生效的 `response-mode`；Rust 端把枚举值
  以数字直出，前端映射错乱。
- 方案：`domain_rule_check_result` 与 `domain_rule_resolve_chain` 增加
  `response_mode` 字段（默认取全局配置，规则级覆盖）；`FIRST_PING_IP` 取首个
  有 IP 的服务器，`FASTEST_RESPONSE` / `FASTEST_IP` 取 ping_ms 最小者；
  Rust→前端统一转换为字符串。

**curl 下载暂存文件安全**

- 方案：暂存文件移至系统临时目录（`$TMPDIR` → `P_tmpdir` → `/tmp`）；
  提取 `_geosite_download_one_url()` 公共核心函数供 async/sync 两路复用；
  `geosite_download_url_files_sync()` 覆盖 URL 下载（ETag/重试）与本地文件
  变更检测（mtime/crc32/md5）。

### 3.4 构建与工具链

**Makefile 语法错误**（`c6517eb`）

- 主 Makefile：`export CFLAGS="$(pkg-config ...)"` 语法非法，
  改为 `export CFLAGS := $(shell pkg-config --cflags openssl)`；
- `src/Makefile`：`BASE_FILE_NAME` 引号定义错误，改为
  `-DBASE_FILE_NAME=\"$(notdir $<)\"`；非静态构建缺 `-lz` 导致 zlib 链接失败。

**musl 目标 bindgen**

- 问题：musl 静态编译时默认 bindgen 无法工作，且 `http_server_stream` 报编译错误。
- 方案：musl 目标改用 bindgen-cli（`824cfca`），并修复对应的流处理代码。

**动态镜像缺 libgcc**（`ef17b73`）

- 问题：runtime 镜像运行 cdylib 插件时因缺 `libgcc_s` 加载失败。
- 方案：runtime 镜像补装 libgcc。

**Rust 增量编译缓存导致旧产物被复用**

- 问题：C 头文件变更后，bindgen 生成的 bindings 可能来自缓存，行为不一致。
- 方案：约定每次 Docker 构建前 `rm -rf plugin/smartdns-ui/target`（已写入 CODEBUDDY.md）。

**macOS 本地编译不可行**

- 结论：FFI 与链接依赖 Linux 工具链，统一走 Docker（builder → dynamic 二阶段），
  本地 macOS 仅用于前端开发。
