# TServerMonitor

一个**零侵入、只读**的服务器旁路监控守护进程，自带 AI 运维参谋。

它只“看”不“动”：采集宿主机、Docker 容器、应用日志、数据库和安全基线数据，在本地脱敏和降噪后，由规则引擎实时告警，再由大模型做根因分析并每天给出可落地的改良建议。结果通过本地大屏、Telegram、REST API、MCP 和 Webhook 对外提供。

```
┌──────────── 交互与协同 ────────────┐
│ 本地大屏(SSE)  Telegram  REST / MCP / Webhook │
└───────────────▲───────────────────┘
                │
┌──────── Rust 守护进程 (tsmonitor) ────────┐      ┌─ Node 子进程 ─┐
│ 调度器 ─ 规则/告警 ─ 只读工具 ─ 报告       │◀────▶│ Vercel AI SDK │──▶ 模型接口
│ SQLite                                   │ stdio │ (只负责对话)   │   /responses 或 /messages
└───────▲───────────────────────▲──────────┘      └───────────────┘
        │ 只读采集                │ 样本导出到隔离工作区
┌───────┴──────────┐   ┌────────┴───────────────┐
│ 主机/Docker/日志/DB │   │ 沙箱：专属目录 + Python  │
└──────────────────┘   └────────────────────────┘
```

## 功能

| 模块 | 内容 |
| --- | --- |
| 主机 | CPU、内存/Swap、磁盘空间与 IO、网络、负载；阈值持续超标告警 |
| 容器 | 自动发现；资源占用、重启循环、OOM、健康检查、限额触顶；标准输出日志跟读 |
| 日志 | 旁路跟读 PHP 错误/慢日志、Nginx、Node、MySQL 慢查询、通用格式；脱敏、模板折叠、速率统计 |
| 安全（Linux） | 端口暴露、SSH 爆破与 root 登录、待装安全更新（只做模拟）、内核参数、SSH 配置 |
| 数据库 | MySQL / PostgreSQL 只读指标（固定白名单查询，会话强制只读） |
| 调度 | 10 秒采样；每小时巡检；每日简报；日志/错误突增切换深度分析；夜间空闲深度审计；主机繁忙时自动让路 |
| AI | 只读查询工具 + 隔离工作区 Python 分析；结构化输出健康评分、根因、安全隐患、改良建议；不可用时自动退回规则报告 |
| 输出 | 本地大屏（实时）、Telegram 分级推送与日报、REST API、MCP、签名 Webhook |

## 安全边界

- **只读**：代码中没有任何写宿主机、重启容器、改配置的调用。Docker 只用 list/inspect/stats/logs/events；数据库只执行内置白名单语句；模型无法传入 SQL 或任意路径。
- **脱敏**：密码、令牌、API Key、JWT、邮箱、卡号等在入库和进入模型上下文之前就被替换。
- **AI 子进程**：Node 进程只拿到模型密钥（通过环境变量），没有任何读文件或执行命令的工具；所有工具都在 Rust 侧执行。
- **沙箱**：AI 写的 Python 脚本只能放在 `<data_dir>/workspace/scripts/`，运行时清空环境变量、限制内存/CPU/文件大小、有超时和输出上限。在 Linux 上额外启用 Landlock：只能读系统运行库、只能写工作区；内核 6.7 及以上还会禁止联网。启动日志和 `/api/v1/status` 会显示实际隔离级别。
- **资源配额**：用 `deploy/tsmonitor.service` 部署时，守护进程及其派生的 Node/Python 进程共享 `CPUQuota=25%`、`MemoryMax=512M`、IO 空闲优先级。
- **网络暴露**：大屏默认只监听 `127.0.0.1`；改为其他地址时必须设置 `TSM_API_TOKEN`，否则拒绝启动。

## 部署（Linux 服务器）

需要：Linux x86_64 或 aarch64（glibc 2.35+），Node.js 20+（AI 功能需要），Python 3（AI 分析脚本需要，可选）。

1. 从 GitHub Release 下载 `tsmonitor-<版本>-linux-<架构>.tar.gz` 并解压。二进制已内置大屏和 AI 子进程脚本。
2. 按 `tsmonitor.service` 文件头部的注释创建用户、安装二进制和配置。
3. 编辑 `/etc/tsmonitor/config.toml`：填写要跟读的日志文件、模型接口等。
4. 把密钥写进 `/etc/tsmonitor/env`（权限 600）：

   ```sh
   TSM_LLM_API_KEY=你的模型密钥
   TSM_TELEGRAM_BOT_TOKEN=你的机器人令牌     # 可选
   TSM_DB_MAIN_DSN=mysql://tsm:密码@127.0.0.1:3306/   # 可选，只读账号
   DOCKER_HOST=tcp://127.0.0.1:2375          # 指向只读 Docker 代理，见下文
   ```

5. `sudo systemctl enable --now tsmonitor`，然后在服务器上访问 `http://127.0.0.1:8787`（远程可用 `ssh -L 8787:127.0.0.1:8787 服务器`）。

检查配置：`tsmonitor --config /etc/tsmonitor/config.toml check-config`。

### Docker 只读接入

不要把 `tsmonitor` 用户加入 `docker` 组（等同 root）。推荐用只读代理：

```sh
docker run -d --name docker-ro-proxy --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -p 127.0.0.1:2375:2375 \
  -e CONTAINERS=1 -e EVENTS=1 -e INFO=1 -e POST=0 \
  tecnativa/docker-socket-proxy
```

然后设置 `DOCKER_HOST=tcp://127.0.0.1:2375`。

### 数据库只读账号

```sql
-- MySQL
CREATE USER 'tsm'@'127.0.0.1' IDENTIFIED BY '...';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'tsm'@'127.0.0.1';
-- PostgreSQL
CREATE ROLE tsm LOGIN PASSWORD '...';
GRANT pg_monitor TO tsm;
```

## 配置要点

完整示例见 [`deploy/config.example.toml`](deploy/config.example.toml)。所有密钥只从环境变量读取，配置文件里只写变量名。

| 环境变量 | 用途 |
| --- | --- |
| `TSM_LLM_API_KEY` | 模型密钥（变量名可在 `api_key_env` 中改） |
| `TSM_API_TOKEN` | 大屏/API/MCP 访问令牌；非回环监听时必填 |
| `TSM_TELEGRAM_BOT_TOKEN` | Telegram 机器人令牌 |
| `TSM_DB_<名称>_DSN` | 数据库只读连接串（变量名在 `dsn_env` 中配置） |
| `DOCKER_HOST` | Docker 地址（推荐指向只读代理） |
| `TSM_LOG` | 日志级别，例如 `info`、`debug` |

### 接入任意模型来源

支持两种接口格式，任何兼容其中一种的来源都可以用（官方、中转、自建网关）：

```toml
[ai.profiles.default]
api_format = "messages"     # POST {base_url}/messages，Anthropic Messages 格式
base_url = "https://api.anthropic.com/v1"
model = "claude-sonnet-5-5"
api_key_env = "TSM_LLM_API_KEY"
# auth = "bearer"           # 中转要求 Authorization: Bearer 时打开

[ai.profiles.fast]
api_format = "responses"    # POST {base_url}/responses，OpenAI Responses 格式
base_url = "https://your-gateway.example.com/v1"
model = "your-model"
api_key_env = "TSM_LLM_FAST_KEY"

[ai.routing]                # 不同任务用不同模型；未列出的用 default
hourly = "fast"
```

如果某个来源不支持结构化输出，子进程会自动改为“让模型输出 JSON 文本再校验”。每天的模型调用次数受 `daily_budget` 限制。

## 对外接口

- REST + SSE：见 [`docs/api.md`](docs/api.md)。
- MCP（Streamable HTTP）：`http://127.0.0.1:8787/mcp`，工具有 `get_health_snapshot`、`list_alerts`、`get_latest_report`、`get_report`、`list_findings`。
- Webhook：`[[notify.webhooks]]` 配置后，告警和报告会 POST 过去；配置 `secret_env` 后带 `X-TSM-Signature: sha256=<HMAC>`。

## 本地开发

```sh
# AI 子进程
pnpm -C agent-sidecar install && pnpm -C agent-sidecar build

# 大屏（Arc Pro 组件需要授权，见下文）
pnpm -C web install
pnpm -C web arc:pro          # 需要 ARC_PRO_TOKEN
pnpm -C web dev              # 代理到 127.0.0.1:8787
pnpm -C web dev:mock         # 不需要后端，使用模拟数据

# 守护进程
cp deploy/config.example.toml config.toml   # 改 data_dir 为 ./data、日志路径为本机路径
cargo run -- --config config.toml
```

检查命令：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`、`pnpm -C agent-sidecar build`、`pnpm -C web build`。

`cargo test` 包含两种模型格式的端到端测试（本地假模型服务），需要先构建 `agent-sidecar`；Landlock 测试只在 Linux 上执行。

### Arc Pro 组件

大屏使用 [Arc](https://uiarc.dev) 组件库。免费组件直接提交在仓库里；**Pro 组件受授权限制，源码不进仓库**，目录 `web/src/components/arc-pro/` 已被忽略，清单在 `web/arc-pro.json`。

- 本地：在 `web/.env.local` 写入 `ARC_PRO_TOKEN=<你的 key>`（该文件已被忽略），执行 `pnpm -C web arc:pro`。
- CI：在 GitHub 仓库 Settings → Secrets and variables → Actions 添加 `ARC_PRO_TOKEN`。没有该密钥时 CI 会跳过大屏构建，发布流程会直接失败。

## 已知限制

- 单机部署，不做多服务器集中管理；不做任何自动修复。
- 安全体检只支持 Linux；待装更新检查只支持 apt 和 dnf，且基于本机已有索引（不会刷新）。
- 数据库只支持 MySQL 和 PostgreSQL（PostgreSQL 连接不启用 TLS，建议连本机）。
- Landlock 需要 Linux 5.13+ 并在内核中启用；网络隔离需要 6.7+。其他平台只有路径守卫、资源上限和超时。
- Telegram 只推送，不接收指令。

## 许可

MIT
