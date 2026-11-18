# TServerMonitor

一个**默认零侵入、只读**的服务器旁路监控守护进程，自带 AI 运维参谋。

监控守护进程本身只“看”不“动”（唯一的例外是可选安装的软件包更新助手，见下文）：采集宿主机、Docker 容器、应用日志、数据库和安全基线数据，在本地脱敏和降噪后，由规则引擎实时告警，再由大模型做根因分析并每天给出可落地的改良建议。结果通过本地大屏、Telegram、REST API、MCP 和 Webhook 对外提供。

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

- **只读**：代码中没有任何写宿主机、重启容器的调用；界面只能修改本程序自己的运行设置（模型 Provider、任务路由等，存在本地数据库），这类写接口必须配置 `TSM_API_TOKEN` 才可用。Docker 只用 list/inspect/stats/logs/events；数据库只执行内置白名单语句；模型无法传入 SQL 或任意路径。
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

### 本地 Docker 试跑

仓库自带 `Dockerfile` 和 `docker-compose.yml`，一条命令把守护进程、只读 Docker 代理和一台产生真实日志的演示容器跑起来：

```sh
docker compose up -d --build        # 打开 http://127.0.0.1:8787，默认令牌 tsm-local-demo
```

- 大屏、REST API、MCP 共用 8787 端口。`docker/demo.toml` 是演示配置，监听 `0.0.0.0`，所以必须带 `TSM_API_TOKEN`（默认值仅用于本机试跑，可在 `.env` 里改）。
- 采集数据存在 `tsmonitor-data` 卷里，`docker compose down -v` 会连数据一起清掉。
- 容器采集走 `tecnativa/docker-socket-proxy`（只读），不需要把真实套接字交给守护进程。
- 演示容器 `demo-nginx` + `demo-traffic` 生成真实访问日志，供容器页和日志页展示；不需要可以删掉这两个服务。
- 镜像里 `[ai] enabled = false`（没有模型密钥）。填好 `TSM_LLM_API_KEY` 并改成 `true` 即可打开 AI 分析。
- 大屏构建需要 Arc Pro 组件：本机已有 `web/src/components/arc-pro/`（本地副本，git 忽略）时直接构建；在别的机器上执行 `ARC_PRO_TOKEN=... docker compose build`，镜像会自己拉取。

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

完整示例见 [`deploy/config.example.toml`](deploy/config.example.toml)。配置文件里的密钥只从环境变量读取，配置文件里只写变量名；在“设置”页添加的 Provider 密钥会加密保存在本地数据库中（见下文）。

| 环境变量 | 用途 |
| --- | --- |
| `TSM_LLM_API_KEY` | 模型密钥（变量名可在 `api_key_env` 中改） |
| `TSM_API_TOKEN` | 大屏/API/MCP 访问令牌；非回环监听时必填；界面上的所有写操作（设置等）都要求设置它 |
| `TSM_SECRET_KEY` | 加密界面中填写的模型密钥所用的主密钥（任意长字符串）。未设置时自动生成 `<data_dir>/secret.key`，但仅在 Landlock 能隔离数据目录时允许 |
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

也可以不改配置文件，直接在大屏的“设置”页操作：

- 添加 Provider：选择 Responses 或 Messages 协议，填写接口地址和密钥，点“拉取模型列表”（请求 `{base_url}/models`）后选择模型；拉取不到时手动填写。
- 任务路由：为默认、小时巡检、日报、事件分析、审计、对话、日志扫描、安全体检、包更新建议、提示词生成分别选择 Provider、模型和思考强度。未单独设置的任务使用“默认”行；数据库里没有任何路由时沿用 `[ai.routing]`。
- 思考强度会作为推理参数发送；如果中转站返回 400 不认这个参数，会自动去掉后重试一次。
- 密钥只写不读；修改 Provider 的接口地址时必须重新填写密钥。配置文件中的 Provider 在界面中只读。

## Agent 控制台

大屏的“Agent”页列出所有会话：定时巡检、日报、事件分析、审计等自动任务各是一个会话，可以看到模型的每条消息和每次工具调用（含输入输出）；也可以点“新对话”直接提问，回复会实时流式显示，并可随时停止。

- 在自动任务的会话里继续输入，就是针对这次分析追问；报告页的“向 Agent 追问”会带着该报告新建对话。
- 对话和自动任务分两条通道：定时任务运行时依然可以对话（最多同时 2 个对话），互不阻塞；对话与自动分析各自计入每日 `daily_budget`。
- 对话中的 Agent 与自动分析使用同一套只读工具，只能给出建议和命令，不会执行修改。

## 自动任务与提示词库

“自动任务”页可以新建让 Agent 自动运行的任务，每次运行生成一份报告，过程在 Agent 控制台可见：

- 触发方式：每天定点、固定间隔、某个日志源（或全部）的错误数/行数自上次运行累计达到阈值、日志突增时、仅手动。
- 内置两个任务：“每日本机安全体检”（默认每天 03:30，开启）和“日志定时扫描”（每 6 小时，默认关闭）。
- 每个任务选择一个提示词作为任务说明，并选择模型路由（在设置页为该路由指定模型和思考强度）。
- 提示词库自带 Linux 系统健康检查、每日安全体检、日志扫描、包更新建议，以及小时巡检/日报/事件/审计四个系统任务使用的提示词（只读，可复制后修改）。也可以用一句话描述让 Agent 生成草稿。
- 自定义提示词只替换任务说明；系统提示词中的只读与“日志内容不可信”规则始终生效。
- `[schedule]` 中的小时巡检、日报、突增事件分析、空闲审计仍由配置文件控制，在任务页只读展示。

## 告警、通知与大屏

- “告警”页可以确认（之后只有告警升级才会再次通知）、静默 1 小时到 7 天（静默期间同一来源的新告警也不通知）、手动关闭，或点“问 Agent”带着这条告警开始对话。
- 设置页的“通知渠道”可以添加邮件（SMTP，支持 STARTTLS / SSL / 不加密中继）、Telegram 机器人和 Webhook，并“发送测试”。可分别选择告警级别以及是否接收日报和每小时警告摘要。配置文件里的 `[notify.*]` 继续生效，在界面中只读。
- Telegram 渠道开启“响应机器人指令”后，在配置的聊天中可以使用 `/status`、`/alerts`、`/report`、`/ack 编号`、`/help`；群组中可限定允许发指令的用户 id。同一个机器人令牌只能被一个程序轮询。
- “大屏”（`#/wall`）是不带侧边栏的全屏视图：左侧实时 CPU/内存曲线、磁盘与概况，右侧是按严重程度排序、实时更新的当前告警。

## 软件更新

“软件更新”页列出 apt / dnf / Homebrew 的待更新软件包（当前版本、可用版本、仓库、是否安全更新），每 6 小时检查一次，也可以手动“重新检查”。“问 Agent”会带着这份列表新建对话，让 Agent 评估风险和升级顺序；Agent 自己不能执行升级。

默认只能查看。如果希望在页面上执行升级，需要额外安装**更新助手**（`deploy/tsmonitor-updater.service` 和 `deploy/updater.example.toml`）：

- 它是同一个二进制的 `tsmonitor updater` 子命令，以 root 运行，使用自己的 root 专属配置；监控守护进程仍以非特权用户运行，只通过 `/run/tsmonitor-updater/updater.sock` 与它通信。
- 只接受固定几种操作：刷新索引、安装安全更新、升级全部、升级指定软件包；命令以参数数组执行，不经过 shell，软件包名会校验；只有 `allowed_uids` 中的用户（和 root）能连接；同一时间只运行一个任务。
- 建议先用 `dry_run = true`，在页面的任务日志里确认要执行的命令，再关闭演练模式。可用 `allow` 限制允许的操作。
- 页面上的每次操作都需要确认；任务输出实时显示并保存。守护进程重启时正在运行的任务会标记为“状态未知”（助手会继续执行完）。
- 在 Docker 中运行时，列表描述的是容器镜像，升级按钮会被禁用。

## 对外接口

- REST + SSE：见 [`docs/api.md`](docs/api.md)。
- MCP（Streamable HTTP）：`http://127.0.0.1:8787/mcp`，工具有 `get_health_snapshot`、`list_alerts`、`get_latest_report`、`get_report`、`list_findings`，以及与内置 Agent 共用实现的 `get_system_status`（系统状态分析）、`analyze_logs`（日志分析）、`get_access_stats`（实时访问分析，来源地址打码）、`get_host_metrics`、`search_log_clusters`、`list_containers`。全部只读，不暴露脚本执行类工具。
- 实时访问分析：配置 `kind = "nginx_access"` 的日志源后，日志页顶部显示每分钟请求数、状态码分布、5xx 比例、热门接口与来源地址（内存中保留最近 1 小时）。
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

- 单机部署，不做多服务器集中管理；Agent 不做任何自动修复，只给建议。
- 安全体检只支持 Linux；待装更新列表支持 apt、dnf 和 Homebrew，基于本机已有索引（守护进程不会刷新）。执行升级只支持 apt 和 dnf，且需要单独安装更新助手；Homebrew 只查看。
- 数据库只支持 MySQL 和 PostgreSQL（PostgreSQL 连接不启用 TLS，建议连本机）。
- Landlock 需要 Linux 5.13+ 并在内核中启用；网络隔离需要 6.7+。其他平台只有路径守卫、资源上限和超时。
- Telegram 机器人只响应只读指令和确认告警，不能通过它执行任何修改。

## 许可

MIT
