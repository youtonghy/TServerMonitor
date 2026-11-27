# TServerMonitor

一个**默认零侵入、只读**的服务器旁路监控守护进程，自带 AI 运维参谋，并可选地通过独立的 root 助手管理 nginx、防火墙、SSH 和 Docker。

监控守护进程本身只“看”不“动”；所有修改都由可选安装的 root 助手执行（软件包更新助手、运维助手，见下文），而且每一项都要由主机管理员在助手自己的配置里显式开启：采集宿主机、Docker 容器、应用日志、数据库和安全基线数据，在本地脱敏和降噪后，由规则引擎实时告警，再由大模型做根因分析并每天给出可落地的改良建议。结果通过本地大屏、Telegram、REST API、MCP 和 Webhook 对外提供。

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

- **守护进程只读**：守护进程里没有写宿主机、重启容器的调用；它自己只能修改本程序的运行设置（模型 Provider、任务路由等，存在本地数据库），这类写接口需要登录。Docker 只用 list/inspect/stats/logs/events；数据库只执行内置白名单语句；模型无法传入 SQL 或任意路径。
- **修改只经过 root 助手**：管理 nginx、防火墙、SSH、Docker 的请求由守护进程转交给可选的运维助手（`tsmonitor helper`）执行。助手只接受 root 或 `allowed_uids` 用户的连接，并且要求共享密钥；每个领域默认关闭，开启后也只能执行 `allow` 中列出的操作；命令以参数数组执行，不经过 shell。没有安装助手时，界面和 MCP 只能查看。
- **登录**：首次启动时由 setup 向导创建管理员（需要服务器上 `<data_dir>/setup-code` 中的一次性 setup 码，防止他人抢先注册）；之后面板、REST、SSE、MCP 都需要认证。浏览器使用 HttpOnly、SameSite=Strict 的会话 Cookie；密码用 argon2id 存储，连续 5 次失败锁定 15 分钟。忘记密码时在主机上执行 `tsmonitor --config /etc/tsmonitor/config.toml reset-password --user <名字>`。
- **修改服务器需二次确认**：面板上的运维修改、账号与令牌管理，需要在 10 分钟内确认过一次密码。机器访问（MCP、脚本）使用「设置 → API 令牌」签发的令牌：`read` 可访问 REST 读接口与 `/mcp`，`ops` 还可访问 `/mcp/ops` 申请修改服务器。内置 Agent 只有只读工具和“提交变更申请”。
- **Agent 的修改要人批准**：内置 Agent 和外部 Agent（MCP）都不能直接改东西，只能提交带调用理由的变更申请；服务器变更会先预演，在「变更审批」页由人确认密码后批准才执行，30 分钟无人处理自动过期。哪些操作需要批准、哪些自动放行，在「变更审批 → 批准策略」里按操作设置（修改需确认密码）。账号、API 令牌和密钥类设置不对 Agent 开放。
- **等同 root 的能力**：Docker 管理和 nginx 配置编辑本质上等同 root 权限（nginx 以 root 加载配置；能控制容器就能控制宿主机）。面板拦截了明显的越权写法（`load_module`、`user`、perl/js/lua、/var/log 之外的日志路径等），但请只把账号和 `ops` 令牌交给可以拥有 root 的人或 Agent。
- **脱敏**：密码、令牌、API Key、JWT、邮箱、卡号等在入库和进入模型上下文之前就被替换。
- **AI 子进程**：Node 进程只拿到模型密钥（通过环境变量），没有任何读文件或执行命令的工具；所有工具都在 Rust 侧执行。
- **沙箱**：AI 写的 Python 脚本只能放在 `<data_dir>/workspace/scripts/`，运行时清空环境变量、限制内存/CPU/文件大小、有超时和输出上限。在 Linux 上额外启用 Landlock：只能读系统运行库、只能写工作区；内核 6.7 及以上还会禁止联网。启动日志和 `/api/v1/status` 会显示实际隔离级别。
- **资源配额**：用 `deploy/tsmonitor.service` 部署时，守护进程及其派生的 Node/Python 进程共享 `CPUQuota=25%`、`MemoryMax=512M`、IO 空闲优先级。
- **网络暴露**：大屏默认只监听 `127.0.0.1`。对外提供时建议放在 TLS 反向代理之后（`[auth] secure_cookie` 会据此给 Cookie 加 `Secure`）。

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
docker compose up -d --build        # 打开 http://127.0.0.1:8787，按 setup 向导创建管理员
```

- 大屏、REST API、MCP 共用 8787 端口。首次打开会进入 setup 向导，setup 码用 `docker compose exec tsmonitor cat /var/lib/tsmonitor/setup-code` 或 `docker compose logs tsmonitor | grep "setup code"` 查看。
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
| `TSM_API_TOKEN` / `TSM_OPS_TOKEN` | 已弃用的静态令牌：设置后仍可作为机器令牌使用（前者可读和改设置，后者可修改服务器），启动时会提示迁移到面板签发的 API 令牌 |
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
- 报告里的每一条根因、建议、安全风险和异常下面都有“详情 / 让 Agent 解释 / 追问 / 让 Agent 修复”。后三项在后台运行，不用离开报告页；状态会显示在这一条下面，“详情”抽屉里能看到 Agent 的最新回答、继续追问，并直接批准它提交的变更申请。
- 对话和自动任务分两条通道：定时任务运行时依然可以对话（最多同时 2 个对话，再多的消息排队，队列上限 10 条），互不阻塞；对话与自动分析各自计入每日 `daily_budget`。
- 对话中的 Agent 与自动分析使用同一套只读工具；对话里另外可以用 `propose_change` 提交变更申请（见「变更审批」）。批准并执行后，结果会回到原对话，Agent 会自行核对效果。

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

## 服务器管理（nginx / 防火墙 / SSH / Docker）

可选安装的运维助手让面板与外部 Agent 可以管理服务器。安装步骤见 `deploy/tsmonitor-helper.service` 文件头，配置见 `deploy/helper.example.toml`（所有领域默认关闭）。

| 领域 | 可以做的事 | 安全措施 |
| --- | --- | --- |
| Docker | 启动/停止/重启/强制终止/删除已有容器；按 compose 标签整体启停项目；拉取、删除、清理镜像；删除、清理卷 | 不提供 exec 与新建容器；套接字代理、TServerMonitor 自身和配置中列出的容器只能启动；删卷与清理卷是单独开关 |
| nginx | 检查配置、重新加载、启用/停用站点、在 `conf.d` / `sites-available` / `snippets` 中编辑或新建文件 | 写入前备份并要求读取时的 sha256（防止覆盖他人修改）；随后执行 `nginx -t`、重新加载，并可探测 `probe_url`，任一步失败都逐字节恢复原文件 |
| 防火墙 | ufw、firewalld 增删规则，ufw 启停；nftables 只能在独立的 `inet tsmonitor` 表中添加拒绝规则；iptables 只读 | 不能对所有来源封锁 SSH 端口、不能删除放行 SSH 的最后一条规则、未放行 SSH 时不能启用 ufw；每次修改都要在倒计时内确认，否则自动回滚 |
| SSH | 通过 `sshd_config.d/00-tsmonitor.conf` 修改一组固定选项；为登录用户增删 `authorized_keys` 公钥；查看会话 | 执行 `sshd -t` 并用 `sshd -T` 核对生效值；拒绝关闭所有登录方式、在没有可用公钥时关闭密码登录；修改需确认否则回滚；公钥文件以 `O_NOFOLLOW` 打开并校验属主，防符号链接与硬链接攻击 |

- **确认或回滚**：防火墙和 sshd 的修改会立即生效，页面顶部显示倒计时（默认 120 秒）。请在另一个终端**新建** SSH 连接确认能登录后再点“保留变更”，因为已建立的连接不受影响。不确认、助手崩溃或重启时都会自动回滚。外部 Agent 可以撤销但不能确认。
- **演练模式**：助手配置 `dry_run = true` 时只记录将要执行的命令；单次请求也可以先演练（nginx 与 sshd 会返回 diff）。
- **审计**：每次修改请求（包括被拒绝的）都记录在“运维记录”页；助手另在 journald 中记录自己的审计日志（`journalctl -u tsmonitor-helper`）。
- 分析脚本沙箱没有内核级隔离时，守护进程拒绝提交修改（可在 `[ops] allow_without_sandbox` 放开）。

## 对外接口

- REST + SSE：见 [`docs/api.md`](docs/api.md)。
- MCP（Streamable HTTP），两个入口：
  - `http://127.0.0.1:8787/mcp`：只读。诊断工具（`get_health_snapshot`、`list_alerts`、`get_latest_report`、`get_report`、`list_reports`、`list_findings`、`get_system_status`、`analyze_logs`、`get_access_stats`、`get_access_history`、`get_host_metrics`、`search_log_clusters`、`list_containers`、`get_container_logs`、`list_log_sources`、`get_log_rates`、`list_ports`、`get_db_metrics`、`list_package_updates`），面板数据（`list_conversations`、`get_conversation`、`list_tasks`、`list_prompts`、`list_notify_channels`、`list_package_jobs`、`get_package_job`、`get_ops_audit`），变更申请（`list_change_actions`、`list_change_requests`、`get_change_request`），以及服务器清单（`get_ops_capabilities`、`docker_inventory`、`docker_list_images/volumes/networks`、`nginx_list_sites`、`nginx_list_files`、`nginx_get_file`、`firewall_status`、`ssh_get_config`、`ssh_list_keys`、`ssh_list_sessions`、`list_ops_jobs`、`get_ops_job`、`list_pending_changes`）。敏感值已打码。
  - `http://127.0.0.1:8787/mcp/ops`：在只读工具之外再提供修改工具（`docker_container_action`、`docker_project_action`、`docker_image_pull`、`docker_image_remove`、`docker_prune`、`docker_volume_remove`、`nginx_test`、`nginx_reload`、`nginx_site_toggle`、`nginx_write_file`、`firewall_rule_add`、`firewall_rule_delete`、`firewall_toggle`、`ssh_set_options`、`ssh_key_add`、`ssh_key_remove`、`revert_change`）。另有 `request_change`，可申请面板上的其他操作（处理告警、触发分析、让内置 Agent 分析、定时任务、提示词、软件包更新、测试通知）。需要 `ops` 范围的 API 令牌；所有修改工具默认演练，真正修改（`dry_run: false`）必须填写 `reason`，并成为一条变更申请，按批准策略由人批准或自动放行；没有确认变更的工具。详见 [docs/mcp.md](docs/mcp.md)。
  - 通过反向代理访问时，把域名加入 `[server] mcp_allowed_hosts`。接入示例见 [`docs/mcp.md`](docs/mcp.md)。
- 访问分析：配置 `kind = "nginx_access"` 的日志源后，日志页显示请求量、状态码、P50/P95/P99 延迟（日志格式需包含 `$request_time`）、热门与慢接口、虚拟主机、UA 分类和可疑来源；支持 combined 格式和 JSON 访问日志。按分钟持久化，可查看 24 小时 / 7 天 / 30 天历史。5xx 比例、单地址请求洪泛、扫描敏感路径，以及路径或参数中的 SQL / 脚本 / 命令注入载荷（URL 解码后匹配，不看状态码和速率）会触发告警（阈值见 `[thresholds] access_*`）。
- systemd journal：默认把 warning 及以上级别的日志作为 `journal` 日志源；`[journal] units` 中的单元会完整跟读。没有 `/var/log/auth.log` 的主机会改用 journal 做 SSH 登录审计。
- nginx 体检：每次安全巡检读取 nginx 配置，给出版本暴露、gzip、TLS 协议、HTTP/2、keepalive、缺少 `$request_time` 等建议，并根据访问统计列出慢接口。
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

- 单机部署，不做多服务器集中管理；内置 Agent 不做任何自动修复，只给建议。
- 运维助手面向 Linux + systemd（ufw、firewalld、nftables、sshd、nginx 的实际命令行为请先用演练模式在目标主机上确认）；nftables 规则只在运行时生效（重启后需自行持久化）；firewalld 确认时会一并持久化其他未保存的运行时改动。
- Docker 拉取只支持公开镜像；compose 项目只按标签启停已有容器，不执行 `docker compose up/down`。
- 回滚窗口内整机重启、且坏规则已经持久化时，助手启动后才会回滚；请保持较短的确认窗口。
- 安全体检只支持 Linux；待装更新列表支持 apt、dnf 和 Homebrew，基于本机已有索引（守护进程不会刷新）。执行升级只支持 apt 和 dnf，且需要单独安装更新助手；Homebrew 只查看。
- 数据库只支持 MySQL 和 PostgreSQL（PostgreSQL 连接不启用 TLS，建议连本机）。
- Landlock 需要 Linux 5.13+ 并在内核中启用；网络隔离需要 6.7+。其他平台只有路径守卫、资源上限和超时。
- Telegram 机器人只响应只读指令和确认告警，不能通过它执行任何修改。

## 许可

MIT
