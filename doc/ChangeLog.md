# ChangeLog

> SmartDNS Pro Max（`feature/geosite` 分支）变更记录。按日期倒序排列。

## 2026-11-26：域名规则检查器全面升级

本次迭代围绕「域名规则检查器」（CLI `--check-domain-rule` / WebUI 设置页 / 插件 API 三端共用的
诊断工具）展开，涉及主程序（C）、UI 插件（Rust FFI）、WebUI（Next.js）三层。

### 新功能

- **记录类型选择**：检查器支持查询 smartdns 内置的全部记录类型
  （A / AAAA / CNAME / NS / MX / SRV / TXT / SOA / PTR / HTTPS）。
  - C 核心：`dns_conf_resolve_domain_ex()` 增加 `qtype` 参数，参数非法时回落 `DNS_T_A`；
  - 非 IP 类型跳过测速与 response_mode 选路，取第一个成功应答；空 NOERROR 应答报告为
    NODATA（NOERROR）而非「无应答」；
  - smartdns 解码库对非 IP 类型只存原始 wire 字节，新增 `_resolve_parse_wire_answers()`
    直接解析应答报文（含域名压缩解压），将 rdata 转为可读文本（如
    `10 mx.baidu.com`、`dns.baidu.com sa.baidu.com`）；
  - 缓存策略与主解析管线对齐：仅 A / AAAA / HTTPS 参与缓存读写；
  - 三端入口：CLI `--check-record-type`、API `&qtype=MX`（支持类型名与数字）、
    WebUI 搜索栏「记录类型」下拉框（默认 A，快照式联动不变）；
  - HTTPS 记录完整解析 SvcParams，输出与 dig 一致的格式
    （alpn / port / ipv4hint / ipv6hint / dohpath / ech / mandatory）。
- **查询所有服务器**：新增选项强制查询组内全部服务器（含 fallback），结果只读不写缓存。
  CLI `--query-all-servers`、API `&query_all_servers=1`、WebUI 复选框；
  勾选时联动强制勾选并锁定「清除缓存」。
- **清除缓存重查**：CLI `--clear-cache`、API `&clear_cache=1`，先按域名删除缓存条目
  再实时查询；检查器的成功应答会写回共享缓存（含原始响应包），后续检查可正常 HIT。

### 修复

- **缓存测速值溢出（显示近 4 亿 ms）**：测速失败的域名缓存值是 `-10`（0.1ms 单位），
  在 `unsigned int` / Rust `u32` 链路上回绕成 4294967286。整条链路改为有符号
  （`int cache_speed` → Rust `i32`），缓存命中路径对无效值钳位为 0。
- **CLI 清缓存段错误**：`dns_cache_remove_by_suffix()` 在缓存模块未初始化时
  （CLI 检查模式）访问零值链表，增加 `_dns_cache_is_ready()` 守卫。
- **wire 解析器两个 bug**：压缩指针指向问题区 QNAME（offset 12）被误判非法；
  指针跳转后读取位置未推进导致记录类型字段读错。
- **HTTPS 记录只显示优先级**（如 cloudflare.com 显示 "1"）：根目标 `.` 编码为空字符串
  被丢弃，SvcParams 未解析。已完整解析。
- **复制按钮在 HTTP 访问下失效**：`navigator.clipboard` 仅在安全上下文可用，
  非 HTTPS 时降级为 textarea + `document.execCommand("copy")`。

### WebUI 界面调整

- 规则匹配流程：NAMESERVER 动作显示 DNS 出口组，NONE（未命中规则）只显示
  「域名 → 未匹配规则 → 服务器组」，隐藏「动作： NONE」标签；
- 服务器组标签样式统一为 primary outlined，随主题变化；
- 缓存状态：MISS 显示黄色，移除 from group 展示；命中来源统一显示 `cache`；
- 文案：各服务器查询结果、清除缓存、服务器组详情等统一更新，中/德文翻译同步。

### 已知限制

- CAA / DNSKEY 等罕见类型暂未支持（qtype 传入时回落为 A）；
- MX / SRV / TXT 等 rdata 中的压缩指针依赖上游响应不压缩原始包（主流服务器均如此）。
