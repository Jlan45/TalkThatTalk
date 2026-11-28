# TalkThatTalk

基于 Rust 构建的高性能、零拷贝 AI 统一网关。单二进制部署，内嵌 Web 控制台与本地 SQLite，同时支持 **API Key** 与 **OAuth 2.0**（兼容 Codex / Claude Code）上游鉴权、跨协议互转、Clash 多协议代理调度以及多用户权限管理。

---

## 核心特性

### 1. 高性能零拷贝数据面（`ttt-proxy`）
- **极低延迟转发**：基于 `Tokio` + `Hyper 1.x` + `rustls`，支持 HTTP/1.1 与 HTTP/2 多路复用、`TCP_NODELAY` 及长连接池复用。
- **同协议零拷贝透传**：当下游与上游协议一致且无需改写模型时，直接流式透传 `hyper::body::Incoming`，不做全量 JSON 反序列化。
- **零反序列化模型路由与切片改写**：使用 SIMD `memchr::memmem` 在原始字节中定位 `"model"` 字段，并通过三段式零拷贝 `SegmentedBody` 完成模型别名映射。
- **零拷贝 SSE 旁路计量**：`TapBody` 通过 O(1) `Bytes::clone()` 切片异步采集 TTFT 与 Token 用量，`UsageAccumulator` 在热路径之外批量写入 SQLite。
- **首包前失败重试与 401 无感刷新**：遇到可重试的 `429` 或上游过载可切换健康上游；OAuth Token 过期返回 `401` 时通过 `Singleflight` 自动刷新并重试，撤销的授权会提示重新登录。

### 2. 多协议支持与互转（`ttt-protocol`）
- 支持 **OpenAI Chat Completions**（`/v1/chat/completions`）、**OpenAI Responses**（`/v1/responses`）、**Anthropic Messages**（`/v1/messages`）、**Google Gemini** 以及 **OpenCode Go** 接入。
- 同协议走零拷贝直通；跨协议（如 OpenAI ↔ Anthropic、OpenAI ↔ Gemini、OpenAI Chat ↔ Responses）自动完成请求与流式 SSE 事件转换。

### 3. 双模式上游鉴权（`ttt-auth`）
- **API Key 模式**：无锁轮询多 Key 池（预编码 `HeaderValue`，热路径零分配），支持独立 Key 输入块管理与单 Key `429` 冷却摘除。
- **原生 OAuth 2.0 模式（Codex & Claude Code 预设）**：
  - 支持 Authorization Code + PKCE（RFC 7636）、Device Code（RFC 8628）与 Client Credentials。
  - `ArcSwap` 无锁读取、后台主动续期、`Singleflight` 并发去重以及 **AES-256-GCM** 加密持久化。

### 4. 内置代理调度（`clash_manager`）
- 在网关进程内通过 `clash-lib` 直连 SOCKS5、Shadowsocks、Trojan、VMess、VLESS、AnyTLS 和 Hysteria2 节点。HTTP 节点使用网关的 HTTP CONNECT。[ClashRS](https://github.com/Watfaq-legacy/clash-rs/tree/v0.10.12)
- 控制台继续使用 SQLite 中的节点配置与上游代理绑定，并提供连通性测试。旧配置中启用了 REALITY 的 Trojan 或 VMess 节点会显示为未加载。
- 管理员可在「代理管理 → 导入订阅」输入返回 Clash YAML 的公网订阅地址。同名节点会跳过，导入结果会显示新增与跳过的数量。

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
│   ├── ttt-proxy/      # 零拷贝代理引擎、TapBody、SegmentedBody、Clash 代理调度、计量
│   ├── ttt-control/    # SQLite 控制面、用户/权限/渠道/Key/代理/统计 API
│   └── ttt-server/     # 主程序入口（talkthattalk）、内嵌前端资源、CLI 与优雅停机
└── web/                # React + Vite 管理控制台源码
```

---

## 快速开始

### Linux 一键安装

适用于运行 systemd 的 Linux x86_64 和 ARM64 系统。发布包基于 Ubuntu 22.04 构建，已内嵌 Web 控制台。

```bash
# 安装或升级到最新发布版
curl -fsSL https://github.com/Jlan45/TalkThatTalk/releases/latest/download/install.sh | sudo bash

# 安装指定版本
curl -fsSL https://github.com/Jlan45/TalkThatTalk/releases/download/v0.0.9/install.sh | sudo bash -s -- v0.0.9

# 卸载服务，保留配置和数据
curl -fsSL https://github.com/Jlan45/TalkThatTalk/releases/latest/download/uninstall.sh | sudo bash
```

安装后访问 `http://127.0.0.1:18080` 初始化管理员。监听地址可在 `/etc/talkthattalk/config.toml` 中修改，修改后运行 `sudo systemctl restart talkthattalk`。SQLite 数据保存在 `/var/lib/talkthattalk`。若要一并删除配置和数据，在卸载命令末尾传入 `-s -- --purge`。

GitHub Actions 会在提交到 `main` 或向它发起 PR 时构建前端并运行 Rust 测试。推送 `vX.Y.Z` 标签会为两种架构编译 Release、生成 SHA-256 校验文件，并发布到 [GitHub Releases](https://github.com/Jlan45/TalkThatTalk/releases)。

### 1. 构建并启动（含内嵌前端）

```bash
# 构建前端静态资源（会被 ttt-server 内嵌进二进制）
cd web && pnpm install && pnpm build && cd ..

# 导入 pi-antigravity 的默认桌面 OAuth 客户端（GitHub Actions 会自动执行）
node scripts/prepare-antigravity-oauth.mjs

# 编译 Release 二进制
cargo build --release --bin talkthattalk

# 启动网关（默认持久化到 SQLite，浏览器访问管理后台即可完成初始化）
./target/release/talkthattalk serve --listen 0.0.0.0:18080 --db data/talkthattalk.db
```

### 2. CLI OAuth 登录（可选）

```bash
cp config.example.toml config.toml

# 登录 OAuth 上游（传入渠道 ID）
./target/release/talkthattalk auth login --upstream '<渠道 ID>' --config config.toml

# 查看 Token 状态
./target/release/talkthattalk auth status --config config.toml
```

渠道名称可以修改或重复。管理接口、OAuth 和用户渠道授权都使用渠道 ID。`X-TTT-Preferred-Upstream` 优先接受渠道 ID，也兼容唯一的旧渠道名称。响应里的 `X-TTT-Upstream-Id` 标识实际渠道，`X-TTT-Upstream` 显示其名称。升级时 SQLite 会为旧渠道生成 ID，并迁移可识别的权限、额度和请求记录。旧 OAuth 账户键若被多个渠道共用，对应渠道需要重新授权。

Claude Code 建议使用控制台的「Anthropic API · Claude Code」渠道。CLI 设置 `ANTHROPIC_BASE_URL` 为网关地址，并用 `ANTHROPIC_AUTH_TOKEN` 传 TalkThatTalk 的客户端 Key。可用 `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1` 在 CLI 中发现已配置且当前 Key 有权使用的 Claude 模型。原生 Anthropic 渠道支持 `/v1/messages` 和 `/v1/messages/count_tokens`。使用支持函数调用的 OpenAI Chat 或 Responses 上游时，网关会转换普通函数调用和结果。Claude 原生的思考签名、原生服务器工具和专属 beta 功能适用于原生 Anthropic 渠道。

Antigravity 预设沿用 `pi-antigravity 0.15.0` 发布包中的桌面 OAuth Client ID（App ID）、配套 Client Secret 和授权范围。Release 构建会导入默认客户端，保存渠道即可发起授权。控制台显示实际使用的 App ID。离线构建或使用自己的 OAuth 应用时，可为渠道填写配套的 Client ID 和 Client Secret，或在服务端同时设置 `ANTIGRAVITY_CLIENT_ID` 和 `ANTIGRAVITY_CLIENT_SECRET`。通过安装脚本部署时，可将环境变量写入仅管理员可读的 `/etc/talkthattalk/environment`，再重启服务。默认 Redirect URI 为 `http://localhost:51121/oauth-callback`，也可填写与 OAuth 客户端配置一致的地址。授权后网关会发现并保存账号的 Project ID，供模型请求和后续令牌刷新使用。

客户端可用 `X-TTT-Preferred-Upstream` 为本次模型请求指定优先渠道。例如 `-H 'X-TTT-Preferred-Upstream: volcengine-agent-plan'`。值填写控制台的渠道名称，中文名称可用 UTF-8 百分号编码。渠道不存在、不支持当前模型、无权使用或处于降级状态时，网关沿用默认路由。响应头 `X-TTT-Upstream` 返回实际使用的渠道。

### 3. 运行测试与代码检查

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
