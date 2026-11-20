# TalkThatTalk

基于 Rust 构建的高性能、零拷贝 AI 统一网关。单二进制部署（约 **14 MB**，已内嵌 Web 控制台与本地 SQLite），同时支持 **API Key** 与 **OAuth 2.0**（兼容 Codex / Claude Code）上游鉴权、跨协议互转、内置多协议代理调度（`eycorsican/leaf`）以及多用户权限管理。

---

## 核心特性

### 1. 高性能零拷贝数据面（`ttt-proxy`）
- **极低延迟转发**：基于 `Tokio` + `Hyper 1.x` + `rustls`，支持 HTTP/1.1 与 HTTP/2 多路复用、`TCP_NODELAY` 及长连接池复用。
- **同协议零拷贝透传**：当下游与上游协议一致且无需改写模型时，直接流式透传 `hyper::body::Incoming`，不做全量 JSON 反序列化。
- **零反序列化模型路由与切片改写**：使用 SIMD `memchr::memmem` 在原始字节中定位 `"model"` 字段，并通过三段式零拷贝 `SegmentedBody` 完成模型别名映射。
- **零拷贝 SSE 旁路计量**：`TapBody` 通过 O(1) `Bytes::clone()` 切片异步采集 TTFT 与 Token 用量，`UsageAccumulator` 在热路径之外批量写入 SQLite。
- **首包前失败重试与 401 无感刷新**：遇到 `429`/`502`/`503`/`504` 自动切换健康上游；OAuth Token 过期返回 `401` 时通过 `Singleflight` 自动刷新并透明重试。

### 2. 多协议支持与互转（`ttt-protocol`）
- 支持 **OpenAI Chat Completions**（`/v1/chat/completions`）、**OpenAI Responses**（`/v1/responses`）、**Anthropic Messages**（`/v1/messages`）、**Google Gemini** 以及 **OpenCode Go** 接入。
- 同协议走零拷贝直通；跨协议（如 OpenAI ↔ Anthropic、OpenAI ↔ Gemini、OpenAI Chat ↔ Responses）自动完成请求与流式 SSE 事件转换。

### 3. 双模式上游鉴权（`ttt-auth`）
- **API Key 模式**：无锁轮询多 Key 池（预编码 `HeaderValue`，热路径零分配），支持独立 Key 输入块管理与单 Key `429` 冷却摘除。
- **原生 OAuth 2.0 模式（Codex & Claude Code 预设）**：
  - 支持 Authorization Code + PKCE（RFC 7636）、Device Code（RFC 8628）与 Client Credentials。
  - `ArcSwap` 无锁读取、后台主动续期、`Singleflight` 并发去重以及 **AES-256-GCM** 加密持久化。

### 4. 内置代理调度（`leaf_manager`）
- 集成 `eycorsican/leaf` 代理引擎，在控制台独立管理代理节点（HTTP / SOCKS5 / Shadowsocks / VMess / Trojan 等）并支持按上游渠道分配独立代理与连通性测试。

### 5. 控制面与内嵌前端（`ttt-control` / `ttt-server` / `web`）
- **单二进制内嵌前端**：`web/`（React + Vite）构建产物通过 `ttt-server/build.rs` 直接编译进 Rust 二进制，无需额外 Nginx 或 Node 运行时。
- **多用户与 RBAC**：支持管理员与普通用户注册/登录、普通用户默认授权渠道、用户自建私有渠道开关、API Key 独立配额与用户限制。
- **数据看板隔离**：普通用户仅查看个人用量与请求日志，管理员可切换查看全局数据。

---

## 同台性能实测

测试环境：同宿主机、本地 Mock 上游（`127.0.0.1:19000`）、Docker `--network host`、并发 `32`、每轮 `2000` 请求（全部 `200 OK`）。

### 同协议透传（OpenAI → OpenAI）

| 网关 | 非流式 RPS | 非流式 P50 / P99 | 流式 SSE RPS | 流式 P50 / P99 | 运行内存 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **TalkThatTalk（Release）** | **88,297.4 req/s** | **0.32 ms / 0.84 ms** | **87,197.2 req/s** | **0.34 ms / 0.70 ms** | **~24.9 MiB** |
| **Sub2API（PG + Redis）** | 1,998.2 req/s | 14.68 ms / 34.35 ms | 2,112.0 req/s | 14.83 ms / 19.33 ms | 293.03 MiB（含组件） |
| **New API（SQLite）** | 145.7 req/s | 20.37 ms / 2436.69 ms | 155.2 req/s | 19.72 ms / 2345.09 ms | 81.89 MiB |

### 跨协议互转（OpenAI `/v1/chat/completions` → Anthropic `/v1/messages`）

| 网关 | 非流式 RPS | 非流式 P50 / P99 | 流式 SSE RPS | 流式 P50 / P99 |
| :--- | :---: | :---: | :---: | :---: |
| **TalkThatTalk（Release）** | **88,221.5 req/s** | **0.33 ms / 1.25 ms** | **43,030.7 req/s** | **0.56 ms / 4.46 ms** |
| **Sub2API（PG + Redis）** | 2,258.6 req/s | 13.31 ms / 23.04 ms | 2,293.1 req/s | 13.19 ms / 22.69 ms |
| **New API（SQLite）** | 150.2 req/s | 21.82 ms / 2149.10 ms | 157.1 req/s | 20.79 ms / 2142.09 ms |

---

## 仓库结构

```text
├── Cargo.toml
├── config.example.toml
├── crates/
│   ├── ttt-core/       # 配置模型、错误信封、协议类型定义
│   ├── ttt-auth/       # ApiKeyPool、OAuthTokenManager、PKCE、AES-256-GCM 存储
│   ├── ttt-protocol/   # OpenAI / Anthropic / Gemini / Responses 协议互转与流式改写
│   ├── ttt-proxy/      # 零拷贝代理引擎、TapBody、SegmentedBody、Leaf 代理调度、计量
│   ├── ttt-control/    # SQLite 控制面、用户/权限/渠道/Key/代理/统计 API
│   └── ttt-server/     # 主程序入口（talkthattalk）、内嵌前端资源、CLI 与优雅停机
└── web/                # React + Vite 管理控制台源码
```

---

## 快速开始

### 1. 构建并启动（含内嵌前端）

```bash
# 构建前端静态资源（会被 ttt-server 内嵌进二进制）
cd web && pnpm install && pnpm build && cd ..

# 编译 Release 二进制
cargo build --release --bin talkthattalk

# 启动网关（默认持久化到 SQLite，浏览器访问管理后台即可完成初始化）
./target/release/talkthattalk serve --listen 0.0.0.0:18080 --db data/talkthattalk.db
```

### 2. CLI OAuth 登录（可选）

```bash
cp config.example.toml config.toml

# 登录 OAuth 上游（Codex / Claude Code）
./target/release/talkthattalk auth login --upstream codex-oauth --config config.toml
./target/release/talkthattalk auth login --upstream claude-code-oauth --config config.toml

# 查看 Token 状态
./target/release/talkthattalk auth status --config config.toml
```

### 3. 运行测试与代码检查

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
