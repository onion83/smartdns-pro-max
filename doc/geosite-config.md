# Geosite 配置说明

Geosite 模块提供基于域名列表的分组规则管理，支持本地文件和远程 URL 数据源，
以及运行时热更新（自动下载、diff 比较、增量删除/添加规则、清除对应 DNS 缓存）。

---

## 指令一览

| 指令 | 说明 |
|------|------|
| `geosite-updater` | 全局更新配置（间隔、算法、HTTP 参数等） |
| `geosite-dat` | 注册一个域名数据源（本地文件或远程 URL） |
| `geosite-set` | 将多个 geosite-dat 组合为一个集合 |
| `domain-rules` | 引用 geosite-set，对匹配域名应用 DNS 规则 |

---

## geosite-updater

全局更新参数，影响所有 geosite-dat 的下载和变更检测行为。

```
geosite-updater [interval] [options...]
```

### 位置参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `interval` | 所有 geosite-dat 的默认更新间隔（秒） | `300`（5 分钟） |

### 选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-data-dir DIR` | URL 数据源的本地缓存目录 | `{工作目录}/data` |
| `-diff-algo ALGO` | 文件变更检测算法：`mtime`、`crc32`、`md5` | `mtime` |
| `-http-use-etag yes/no` | 是否使用 HTTP ETag 条件请求（需编译启用 libcurl） | `no` |
| `-user-agent UA` | HTTP 下载的 User-Agent | `smartdns/{version}` |
| `-http-timeout SEC` | 单次 HTTP 下载超时（秒），范围 1-3600 | `300` |
| `-http-retry N` | 下载失败重试次数，范围 0-5 | `2` |
| `-http-retry-intval SEC` | 重试间隔（秒），范围 1-60 | `3` |

### 示例

```conf
geosite-updater 300 -data-dir /smartdns/data -diff-algo crc32 \
                  -http-use-etag yes -http-timeout 10 \
                  -http-retry 3 -http-retry-intval 3
```

---

## geosite-dat

注册一个域名列表数据源。可以是本地文件路径或远程 URL。

```
geosite-dat <name> <file-or-url> [interval] [options...]
```

### 参数

| 参数 | 说明 |
|------|------|
| `name` | 数据源名称（唯一标识），如 `google`、`gfw` |
| `file-or-url` | 本地文件路径或 HTTP(S) URL |
| `interval` | 更新间隔（秒），覆盖全局默认值。`0` 表示不自动更新 |

### 选项

| 选项 | 说明 |
|------|------|
| `-name NAME` | 数据源名称（同位置参数） |
| `-file FILE` | 文件路径或 URL（同位置参数） |
| `-interval SEC` | 更新间隔（同位置参数） |

### 文件路径规则

| 路径格式 | 解析方式 | 示例 |
|----------|----------|------|
| 绝对路径 | 直接使用 | `/etc/smartdns/google.list` |
| `./xxx` 或 `../xxx` | 相对于 data-dir | `./google.list` → `{data-dir}/google.list` |
| 纯文件名 | data-dir + 文件名 | `google.list` → `{data-dir}/google.list` |
| `http://...` 或 `https://...` | 远程 URL，自动下载到 data-dir | `https://example.com/domains.list` |

### URL 缓存文件命名

URL 源的本地缓存文件自动存放在 data-dir 下，命名格式为 `{域名}-{文件名}`：
- `https://example.com/path/gfw.list` → `{data-dir}/example.com-gfw.list`
- `https://raw.githubusercontent.com/xxx/domains` → `{data-dir}/raw.githubusercontent.com-domains`

### 域名列表格式

每行一个域名，支持以下格式：

```
# 注释行
*.google.com          # 通配符匹配
.example.com          # 后缀匹配（等价于 *.example.com + example.com）
+example.com          # 包含匹配（匹配自身及所有子域名）
google.com            # 精确匹配
xn--nxasmq6b.com      # Punycode 域名（自动从 UTF-8 转换）
```

### 示例

```conf
# 本地文件，30 秒检测一次变更
geosite-dat tencent /smartdns/data/tencent.list 30

# 纯文件名，自动在 data-dir 下查找
geosite-dat google google.list

# 远程 URL，使用全局默认间隔
geosite-dat gfw https://raw.githubusercontent.com/.../gfw.list

# 远程 URL，60 秒更新间隔
geosite-dat openai https://raw.githubusercontent.com/.../openai.list 60

# 禁用自动更新
geosite-dat custom /etc/smartdns/custom.list 0
```

---

## geosite-set

将多个 geosite-dat 组合为一个集合，便于在 `domain-rules` 中一次性引用。

```
geosite-set <set-name> <dat1> [dat2] [dat3] ...
```

### 参数

| 参数 | 说明 |
|------|------|
| `set-name` | 集合名称 |
| `dat1, dat2, ...` | 引用的 geosite-dat 名称（必须已注册） |

### 示例

```conf
# 定义数据源
geosite-dat tencent /smartdns/data/tencent.list
geosite-dat sina /smartdns/data/sina.list
geosite-dat google google.list

# 组合集合
geosite-set cn-services tencent sina
geosite-set search-services google
```

---

## domain-rules（引用 geosite-set）

使用 `/geosite-set:名称/` 语法在 `domain-rules` 中引用 geosite-set。

```
domain-rules /geosite-set:<set-name>/ [options...]
```

当 geosite-set 中的任何数据源发生变更时，对应的 domain-rules 会自动热更新：
- 删除已移除域名的规则和 DNS 缓存
- 新增域名自动添加规则

### 示例

```conf
# cn-services 集合中的域名使用国内 DNS 服务器
domain-rules /geosite-set:cn-services/ -n cn

# gfw 集合中的域名使用代理 DNS
domain-rules /geosite-set:gfw-services/ -n free

# 广告域名返回空地址
domain-rules /geosite-set:ad-services/ -n cn -address 127.0.0.1
```

---

## 完整配置示例

```conf
# 上游 DNS 服务器分组
server 223.5.5.5 -g cn -e
server 8.8.8.8   -g free -e
server 119.29.29.29 -g default

# 全局更新配置
geosite-updater 300 -data-dir /smartdns/data -diff-algo crc32 \
                  -http-use-etag yes -http-timeout 10 -http-retry 3

# 数据源定义
geosite-dat tencent /smartdns/data/tencent.list 30
geosite-dat sina    ./sina.list 30
geosite-dat gfw     https://raw.githubusercontent.com/.../gfw.list 60
geosite-dat openai  https://raw.githubusercontent.com/.../openai.list
geosite-dat ad      https://raw.githubusercontent.com/.../category-ads-all.list

# 集合定义
geosite-set cn-services tencent sina
geosite-set ai-services openai
geosite-set gfw-services gfw
geosite-set ad-services ad

# 规则引用
domain-rules /geosite-set:cn-services/ -n cn
domain-rules /geosite-set:ai-services/ -n free -address #6
domain-rules /geosite-set:gfw-services/ -n free
domain-rules /geosite-set:ad-services/ -n cn -address 127.0.0.1
```

---

## 运行时行为说明

### 启动阶段

1. 解析 `geosite-updater` 全局配置
2. 解析 `geosite-dat`，注册数据源：
   - **本地文件**：验证存在，记录初始状态（mtime/crc32/md5），缓存域名列表
   - **远程 URL**：本地缓存不存在时同步下载；已存在则直接使用
3. 解析 `geosite-set`，建立集合引用关系
4. 解析 `domain-rules`，将域名加载到 ART 树

### 运行时更新（Linux）

1. 定时轮询（默认 5 秒检查一次）检测数据源是否需要更新
2. **URL 数据源**：提交到后台线程异步下载，不阻塞主循环
3. 下载完成后通过 eventfd 通知主线程，执行 `geosite_reload_rules()`：
   - 比较新旧域名列表（纯内存 diff）
   - 删除已移除域名的 ART 规则 + DNS 缓存
   - 重新添加所有当前域名规则
4. 更新完成后交换域名缓存，等待下次变更检测

### 变更检测算法

| 算法 | 说明 | 适用场景 |
|------|------|----------|
| `mtime` | 比较文件修改时间（默认） | 本地文件，低开销 |
| `crc32` | 比较 CRC32 校验和 | URL 下载文件，需要准确检测内容变化 |
| `md5` | 比较 MD5 哈希 | 最高准确度，计算开销略大 |

### 启动日志

正常运行后，geosite 功能会输出 NOTICE 级别日志：
```
[2026-04-03 14:00:00,000][NOTICE] ... geosite feature geosite-mod-202604031400
[2026-04-03 14:00:00,000][NOTICE] ... geosite: 8 dat source(s) (3 local, 5 url), 5 set rule(s), interval=300, diff_algo=crc32
```

更新时会输出 INFO 级别日志：
```
[2026-04-03 14:05:00,000][ INFO] ... geosite: reloading domain rules (async update)
[2026-04-03 14:05:00,100][ INFO] ... geosite: reload complete, 15230 domains active, 12 rules removed
```
