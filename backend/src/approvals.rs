//! Change requests: every change an agent asks for, from the built-in agent (`propose_change`)
//! or an external one on `/mcp/ops`, goes through here.
//!
//! * The catalog below is the closed set of changes an agent can ask for. Host changes run
//!   through the ops helper (which applies its own allow-list); panel changes reuse the same
//!   functions the dashboard calls.
//! * Each action has a policy: `approve` (a signed-in person approves it in the dashboard
//!   after re-entering the password) or `auto` (runs at once, still recorded). Operators change
//!   the policy in the dashboard; account, token and secret settings are never in the catalog.
//! * A request always carries the requester's reason. Host changes that support it are dry-run
//!   first, so the person approving sees the plan or diff.
//! * Approved changes of the built-in agent are reported back to its conversation, which then
//!   checks the result.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::model::{Event, now_ms};
use crate::settings::Invalid;
use crate::state::Shared;
use crate::store::Db;

/// Pending requests expire after this long.
pub const REQUEST_TTL_MS: i64 = 30 * 60_000;
/// How long a host change may run before the request is closed as still running.
const HOST_WAIT: Duration = Duration::from_secs(15 * 60);
const MAX_REASON: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Changes the server (through the ops helper or the package updater).
    Host,
    /// Changes TServerMonitor's own state (alerts, tasks, prompts, analyses).
    Panel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Approve,
    Auto,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Approve => "approve",
            Mode::Auto => "auto",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "approve" => Some(Mode::Approve),
            "auto" => Some(Mode::Auto),
            _ => None,
        }
    }
}

pub struct ActionDef {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    pub default: Mode,
    /// May the built-in agent propose it (`agent.ask` would let it start itself).
    pub agent: bool,
    /// Host actions that accept `dry_run`; their preview is a dry run.
    pub dry_run: bool,
    /// Argument hint for the built-in agent.
    pub args: &'static str,
}

const fn host(name: &'static str, label: &'static str, args: &'static str) -> ActionDef {
    ActionDef {
        name,
        label,
        kind: Kind::Host,
        default: Mode::Approve,
        agent: true,
        dry_run: true,
        args,
    }
}

const fn panel(
    name: &'static str,
    label: &'static str,
    default: Mode,
    args: &'static str,
) -> ActionDef {
    ActionDef {
        name,
        label,
        kind: Kind::Panel,
        default,
        agent: true,
        dry_run: false,
        args,
    }
}

pub const CATALOG: &[ActionDef] = &[
    host(
        "docker.container",
        "容器启停/删除",
        r#"{"id": "容器名", "action": "start|stop|restart|kill|remove"}"#,
    ),
    host(
        "docker.project",
        "compose 项目启停",
        r#"{"name": "项目名", "action": "start|stop|restart"}"#,
    ),
    host(
        "docker.image_pull",
        "拉取镜像",
        r#"{"reference": "nginx:1.27"}"#,
    ),
    host(
        "docker.image_remove",
        "删除镜像",
        r#"{"id": "镜像 id 或引用", "force": false}"#,
    ),
    host("docker.image_prune", "清理悬空镜像", "{}"),
    host("docker.volume_remove", "删除卷", r#"{"name": "卷名"}"#),
    host("docker.volume_prune", "清理未使用的卷", "{}"),
    ActionDef {
        default: Mode::Auto,
        dry_run: false,
        ..host("nginx.test", "检查 nginx 配置（nginx -t）", "{}")
    },
    host("nginx.reload", "重新加载 nginx", "{}"),
    host(
        "nginx.site",
        "启用/停用站点",
        r#"{"name": "站点名", "enabled": true}"#,
    ),
    host(
        "nginx.write",
        "修改 nginx 配置文件",
        r#"{"path": "相对路径，如 sites-available/shop", "content": "完整新内容（不能含 <redacted>）", "base_sha256": "get_nginx_file 返回的 sha256，新文件省略"}"#,
    ),
    host(
        "nginx.site_save",
        "创建/修改面板管理的 nginx 站点",
        r#"{"spec": "get_nginx_site（MCP 为 nginx_get_site）返回的 spec（name, domains, kind: proxy|static, proxy, static, listen, features, ssl, extra）", "base_sha256": "get_nginx_site 返回的 sha256，新站点省略", "overwrite": false}"#,
    ),
    host(
        "nginx.site_delete",
        "删除面板管理的 nginx 站点",
        r#"{"name": "站点名", "purge_certs": false}"#,
    ),
    host(
        "nginx.cert_issue",
        "为站点申请/续期证书（ACME）",
        r#"{"name": "站点名", "force": false}"#,
    ),
    host(
        "nginx.service",
        "启动/停止/重启 nginx",
        r#"{"action": "start|stop|restart"}"#,
    ),
    host(
        "nginx.install",
        "用 Docker 安装 nginx",
        r#"{"version": "镜像版本标签，如 1.27.3（get_ops_inventory nginx_versions）"}"#,
    ),
    host(
        "nginx.upgrade",
        "升级 nginx",
        r#"{"version": "Docker 方式：目标版本；系统包方式省略（升级到 apt 候选版本）"}"#,
    ),
    host("nginx.rollback", "回退 nginx 版本（Docker 方式）", "{}"),
    // private keys never pass through an agent
    ActionDef {
        agent: false,
        ..host(
            "nginx.cert_upload",
            "为站点上传证书",
            r#"{"name": "站点名", "cert_pem": "证书 PEM", "key_pem": "私钥 PEM"}"#,
        )
    },
    host(
        "firewall.add",
        "添加防火墙规则",
        r#"{"action": "allow|deny|reject|limit", "port": "443 或 8000-8100", "proto": "tcp|udp|any", "from": "来源地址或 CIDR，可省略"}"#,
    ),
    host(
        "firewall.delete",
        "删除防火墙规则",
        r#"{"spec": "firewall 状态里规则的 spec"}"#,
    ),
    host("firewall.toggle", "启用/停用防火墙", r#"{"enabled": true}"#),
    host(
        "ssh.set",
        "修改 sshd 设置",
        r#"{"options": {"PasswordAuthentication": "no"}}"#,
    ),
    host(
        "ssh.key_add",
        "添加 SSH 公钥",
        r#"{"user": "用户名", "key": "ssh-ed25519 AAAA... comment"}"#,
    ),
    host(
        "ssh.key_remove",
        "删除 SSH 公钥",
        r#"{"user": "用户名", "fingerprint": "SHA256:..."}"#,
    ),
    ActionDef {
        default: Mode::Auto,
        dry_run: false,
        ..host(
            "pending.revert",
            "撤销待确认的防火墙/SSH 变更",
            r#"{"id": "待确认变更 id"}"#,
        )
    },
    ActionDef {
        kind: Kind::Host,
        ..panel(
            "packages.job",
            "刷新索引或升级软件包",
            Mode::Approve,
            r#"{"op": "refresh|upgrade_security|upgrade_all|upgrade_packages", "packages": ["只在 upgrade_packages 时填写"]}"#,
        )
    },
    panel("packages.check", "检查软件包更新（只读）", Mode::Auto, "{}"),
    panel("alert.ack", "确认告警", Mode::Auto, r#"{"id": 1}"#),
    panel(
        "alert.silence",
        "静默告警",
        Mode::Auto,
        r#"{"id": 1, "minutes": 60}"#,
    ),
    panel("alert.close", "关闭告警", Mode::Auto, r#"{"id": 1}"#),
    panel(
        "analysis.trigger",
        "触发一次 AI 分析",
        Mode::Auto,
        r#"{"kind": "hourly|daily|incident|audit"}"#,
    ),
    ActionDef {
        agent: false,
        ..panel(
            "agent.ask",
            "让内置 Agent 分析一个问题",
            Mode::Auto,
            r#"{"message": "问题", "title": "可选标题"}"#,
        )
    },
    panel(
        "task.run",
        "立即运行定时任务",
        Mode::Auto,
        r#"{"id": "任务 id"}"#,
    ),
    panel(
        "task.create",
        "新建定时任务",
        Mode::Approve,
        r#"{"name": "名称", "enabled": true, "trigger": {"type": "interval", "every_mins": 60}, "prompt_id": "提示词 id", "route_kind": "hourly"}"#,
    ),
    panel(
        "task.update",
        "修改定时任务",
        Mode::Approve,
        r#"{"id": "任务 id", "...": "同 task.create，只填要改的字段"}"#,
    ),
    panel(
        "task.delete",
        "删除定时任务",
        Mode::Approve,
        r#"{"id": "任务 id"}"#,
    ),
    panel(
        "prompt.create",
        "新建提示词",
        Mode::Approve,
        r#"{"name": "名称", "description": "说明", "body": "正文"}"#,
    ),
    panel(
        "prompt.update",
        "修改提示词",
        Mode::Approve,
        r#"{"id": "提示词 id", "name": "…", "description": "…", "body": "…"}"#,
    ),
    panel(
        "prompt.delete",
        "删除提示词",
        Mode::Approve,
        r#"{"id": "提示词 id"}"#,
    ),
    panel(
        "channel.test",
        "发送测试通知",
        Mode::Auto,
        r#"{"id": "渠道 id"}"#,
    ),
];

pub fn find(name: &str) -> Option<&'static ActionDef> {
    CATALOG.iter().find(|a| a.name == name)
}

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    Invalid(msg.into()).into()
}

// ---------------------------------------------------------------- policy

#[derive(Debug, Clone, Serialize)]
pub struct PolicyView {
    pub action: &'static str,
    pub label: &'static str,
    pub kind: Kind,
    pub default: Mode,
    pub mode: Mode,
    pub agent: bool,
}

pub async fn policies(db: &Db) -> Result<Vec<PolicyView>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT action, mode FROM approval_policy")
        .fetch_all(db)
        .await?;
    Ok(CATALOG
        .iter()
        .map(|a| PolicyView {
            action: a.name,
            label: a.label,
            kind: a.kind,
            default: a.default,
            mode: rows
                .iter()
                .find(|(n, _)| n == a.name)
                .and_then(|(_, m)| Mode::parse(m))
                .unwrap_or(a.default),
            agent: a.agent,
        })
        .collect())
}

async fn mode_of(db: &Db, def: &ActionDef) -> Result<Mode> {
    let m: Option<String> = sqlx::query_scalar("SELECT mode FROM approval_policy WHERE action = ?")
        .bind(def.name)
        .fetch_optional(db)
        .await?;
    Ok(m.as_deref().and_then(Mode::parse).unwrap_or(def.default))
}

pub async fn set_policy(db: &Db, action: &str, mode: &str, by: &str) -> Result<()> {
    let def = find(action).ok_or_else(|| invalid(format!("未知的操作 {action}")))?;
    let mode = Mode::parse(mode).ok_or_else(|| invalid("mode 只能是 approve 或 auto"))?;
    if mode == def.default {
        sqlx::query("DELETE FROM approval_policy WHERE action = ?")
            .bind(def.name)
            .execute(db)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO approval_policy (action, mode, updated_at, updated_by) VALUES (?, ?, ?, ?)
             ON CONFLICT(action) DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        )
        .bind(def.name)
        .bind(mode.as_str())
        .bind(now_ms())
        .bind(by)
        .execute(db)
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- panel actions

fn parse<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T> {
    serde_json::from_value(if args.is_null() {
        json!({})
    } else {
        args.clone()
    })
    .map_err(|e| invalid(format!("参数不正确：{e}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdNum {
    id: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdStr {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Silence {
    id: i64,
    minutes: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trigger {
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    message: String,
    title: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

/// Splits `{"id": ..., rest}` for the update actions.
fn split_id(args: &Value) -> Result<(String, Value)> {
    let mut rest = args.as_object().cloned().unwrap_or_default();
    let id = rest
        .remove("id")
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| invalid("缺少 id"))?;
    Ok((id, Value::Object(rest)))
}

fn short(s: &str, n: usize) -> String {
    let t: String = s.trim().chars().take(n).collect();
    if s.trim().chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}

/// Checks the arguments and returns the human-readable summary.
pub fn validate(def: &ActionDef, args: &Value) -> Result<String> {
    if !args.is_object() && !args.is_null() {
        return Err(invalid("args 必须是对象"));
    }
    Ok(match def.name {
        "nginx.write" => {
            if args["content"]
                .as_str()
                .is_some_and(crate::ops::has_placeholder)
            {
                return Err(invalid(
                    "content 含有脱敏占位符（如 <redacted>），请只改需要的行并保留原值，或请管理员在面板上修改",
                ));
            }
            crate::ops::calls::summary(def.name, args)
        }
        "nginx.site_save" => {
            if args["spec"]["extra"]
                .as_str()
                .is_some_and(crate::ops::has_placeholder)
            {
                return Err(invalid(
                    "spec.extra 含有脱敏占位符（如 <redacted>），请保留原值，或请管理员在面板上修改",
                ));
            }
            crate::ops::calls::summary(def.name, args)
        }
        "packages.job" => {
            let r: crate::updater::Request = parse(args)?;
            let pk = if r.packages.is_empty() {
                String::new()
            } else {
                format!("：{}", short(&r.packages.join(" "), 80))
            };
            format!("{}{pk}", r.op.label())
        }
        _ if def.kind == Kind::Host => crate::ops::calls::summary(def.name, args),
        "packages.check" => {
            parse::<Empty>(args)?;
            "检查软件包更新".into()
        }
        "alert.ack" => format!("确认告警 #{}", parse::<IdNum>(args)?.id),
        "alert.close" => format!("关闭告警 #{}", parse::<IdNum>(args)?.id),
        "alert.silence" => {
            let s: Silence = parse(args)?;
            if !(0..=7 * 24 * 60).contains(&s.minutes) {
                return Err(invalid("静默时长需在 0 到 7 天之间"));
            }
            format!("静默告警 #{} {} 分钟", s.id, s.minutes)
        }
        "analysis.trigger" => {
            let t: Trigger = parse(args)?;
            let k = crate::model::ReportKind::parse(&t.kind)
                .ok_or_else(|| invalid("kind 只能是 hourly|daily|incident|audit"))?;
            format!("触发{}", k.label())
        }
        "agent.ask" => {
            let a: Ask = parse(args)?;
            if a.message.trim().is_empty() {
                return Err(invalid("message 不能为空"));
            }
            format!("让内置 Agent 分析：{}", short(&a.message, 40))
        }
        "task.run" => format!("立即运行任务 {}", parse::<IdStr>(args)?.id),
        "task.create" => {
            let t: crate::tasks::TaskInput = parse(args)?;
            format!("新建定时任务 {}", t.name.unwrap_or_default())
        }
        "task.update" => {
            let (id, rest) = split_id(args)?;
            parse::<crate::tasks::TaskInput>(&rest)?;
            format!("修改定时任务 {id}")
        }
        "task.delete" => format!("删除定时任务 {}", parse::<IdStr>(args)?.id),
        "prompt.create" => {
            let p: crate::agent::library::PromptInput = parse(args)?;
            format!("新建提示词 {}", p.name.unwrap_or_default())
        }
        "prompt.update" => {
            let (id, rest) = split_id(args)?;
            parse::<crate::agent::library::PromptInput>(&rest)?;
            format!("修改提示词 {id}")
        }
        "prompt.delete" => format!("删除提示词 {}", parse::<IdStr>(args)?.id),
        "channel.test" => format!("测试通知渠道 {}", parse::<IdStr>(args)?.id),
        other => return Err(invalid(format!("未知的操作 {other}"))),
    })
}

fn not_found(what: &str) -> anyhow::Error {
    invalid(format!("{what}不存在"))
}

async fn run_panel(state: &Shared, name: &str, args: &Value) -> Result<Value> {
    let alert =
        |a: Option<crate::model::Alert>| a.map(|a| json!(a)).ok_or_else(|| not_found("告警"));
    Ok(match name {
        "packages.check" => json!(crate::collect::packages::check(state).await),
        "packages.job" => {
            let id = crate::updater::start_job(state, parse(args)?).await?;
            json!({ "package_job_id": id })
        }
        "alert.ack" => alert(
            crate::alerts::act(state, parse::<IdNum>(args)?.id, crate::alerts::Action::Ack).await?,
        )?,
        "alert.close" => alert(
            crate::alerts::act(
                state,
                parse::<IdNum>(args)?.id,
                crate::alerts::Action::Close,
            )
            .await?,
        )?,
        "alert.silence" => {
            let s: Silence = parse(args)?;
            alert(
                crate::alerts::act(state, s.id, crate::alerts::Action::Silence(s.minutes)).await?,
            )?
        }
        "analysis.trigger" => {
            let t: Trigger = parse(args)?;
            let kind = crate::model::ReportKind::parse(&t.kind)
                .ok_or_else(|| invalid("未知的分析类型"))?;
            let agent = state.agent().context("agent not ready")?;
            let run = agent
                .trigger(kind, "approval")
                .map_err(|e| invalid(e.to_string()))?;
            json!({ "run_id": run })
        }
        "agent.ask" => {
            let a: Ask = parse(args)?;
            let agent = state.agent().context("agent not ready")?;
            let title: String = a
                .title
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .unwrap_or(crate::agent::prompt::NEW_CHAT_TITLE)
                .chars()
                .take(60)
                .collect();
            let id = format!("c_{}", uuid::Uuid::new_v4().simple());
            crate::store::create_conversation(&state.db, &id, &title, "chat", None).await?;
            let run = agent
                .send_message(&id, a.message.trim())
                .await
                .map_err(|e| invalid(e.to_string()))?;
            json!({ "conversation_id": id, "run_id": run })
        }
        "task.run" => {
            let id = parse::<IdStr>(args)?.id;
            let t = crate::tasks::get(&state.db, &id)
                .await?
                .ok_or_else(|| not_found("任务"))?;
            let run = crate::tasks::fire(state, &t, "approval").await?;
            json!({ "run_id": run, "deferred": run.is_none() })
        }
        "task.create" => json!({ "id": crate::tasks::create(&state.db, parse(args)?).await? }),
        "task.update" => {
            let (id, rest) = split_id(args)?;
            if !crate::tasks::update(&state.db, &id, parse(&rest)?).await? {
                return Err(not_found("任务"));
            }
            json!({ "id": id })
        }
        "task.delete" => {
            let id = parse::<IdStr>(args)?.id;
            if !crate::tasks::delete(&state.db, &id).await? {
                return Err(not_found("任务"));
            }
            json!({ "ok": true })
        }
        "prompt.create" => {
            json!({ "id": crate::agent::library::create(&state.db, parse(args)?).await? })
        }
        "prompt.update" => {
            let (id, rest) = split_id(args)?;
            if !crate::agent::library::update(&state.db, &id, parse(&rest)?).await? {
                return Err(not_found("提示词"));
            }
            json!({ "id": id })
        }
        "prompt.delete" => {
            let id = parse::<IdStr>(args)?.id;
            if !crate::agent::library::delete(&state.db, &id).await? {
                return Err(not_found("提示词"));
            }
            json!({ "ok": true })
        }
        "channel.test" => {
            state
                .notifier
                .test(state, &parse::<IdStr>(args)?.id)
                .await?;
            json!({ "ok": true })
        }
        other => return Err(invalid(format!("未知的操作 {other}"))),
    })
}

// ---------------------------------------------------------------- host actions

/// Keeps the tail of a job log for the model.
pub fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = s.len() - max;
    while !s.is_char_boundary(cut) {
        cut += 1;
    }
    format!("…{}", &s[cut..])
}

/// Compact job view for agents and the approval card.
pub fn job_view(job: &crate::ops::Job) -> Value {
    json!({
        "job_id": job.id,
        "status": job.status,
        "dry_run": job.dry_run,
        "error": job.error,
        "result": job.result,
        "log": tail(job.log.as_deref().unwrap_or(""), 6000),
        "note": if job.status == "running" { "still running; poll get_ops_job" } else { "" },
    })
}

/// Runs a helper call and waits for it. Errors are refusals before a job started.
pub async fn run_host(
    state: &Shared,
    call: &str,
    args: Value,
    dry_run: bool,
    via: crate::ops::Via,
    wait: Duration,
) -> Result<crate::ops::Job> {
    let summary = crate::ops::calls::summary(call, &args);
    let id = crate::ops::submit(
        state,
        crate::ops::Submit {
            call: call.into(),
            args,
            dry_run,
            summary,
            via,
        },
    )
    .await?;
    crate::ops::wait(state, id, wait)
        .await?
        .context("job vanished")
}

// ---------------------------------------------------------------- requests

/// Who asked.
#[derive(Debug, Clone)]
pub struct Origin {
    /// agent | mcp
    pub source: &'static str,
    pub actor: String,
    pub remote: Option<String>,
    pub conversation_id: Option<String>,
    pub run_id: Option<String>,
}

impl Origin {
    pub fn via(&self, approved_by: Option<&str>) -> crate::ops::Via {
        crate::ops::Via {
            via: self.source,
            remote: self.remote.clone(),
            actor: match approved_by {
                Some(by) if by != "auto" => format!("{}（批准人 {by}）", self.actor),
                _ => self.actor.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeRequest {
    pub id: i64,
    pub action: String,
    pub label: String,
    pub kind: Option<Kind>,
    pub summary: String,
    /// Redacted for display (file contents become size + hash, keys their fingerprint).
    pub args: Value,
    pub reason: String,
    pub source: String,
    pub actor: Option<String>,
    pub remote: Option<String>,
    pub conversation_id: Option<String>,
    pub run_id: Option<String>,
    pub mode: String,
    pub status: String,
    pub preview: Option<Value>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub job_id: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub note: Option<String>,
    pub finished_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    action: String,
    summary: String,
    args: String,
    reason: String,
    source: String,
    actor: Option<String>,
    remote: Option<String>,
    conversation_id: Option<String>,
    run_id: Option<String>,
    mode: String,
    status: String,
    preview: Option<String>,
    result: Option<String>,
    error: Option<String>,
    job_id: Option<i64>,
    created_at: i64,
    expires_at: i64,
    decided_at: Option<i64>,
    decided_by: Option<String>,
    note: Option<String>,
    finished_at: Option<i64>,
}

const COLS: &str = "id, action, summary, args, reason, source, actor, remote, conversation_id, run_id, mode, status, preview, result, error, job_id, created_at, expires_at, decided_at, decided_by, note, finished_at";

impl Row {
    fn raw_args(&self) -> Value {
        serde_json::from_str(&self.args).unwrap_or(Value::Null)
    }

    fn origin(&self) -> Origin {
        Origin {
            source: if self.source == "agent" {
                "agent"
            } else {
                "mcp"
            },
            actor: self.actor.clone().unwrap_or_default(),
            remote: self.remote.clone(),
            conversation_id: self.conversation_id.clone(),
            run_id: self.run_id.clone(),
        }
    }

    fn view(self) -> ChangeRequest {
        let def = find(&self.action);
        let parse = |s: Option<String>| s.and_then(|s| serde_json::from_str(&s).ok());
        ChangeRequest {
            id: self.id,
            label: def.map_or_else(|| self.action.clone(), |d| d.label.to_string()),
            kind: def.map(|d| d.kind),
            args: crate::ops::redact_args(&self.raw_args()),
            action: self.action,
            summary: self.summary,
            reason: self.reason,
            source: self.source,
            actor: self.actor,
            remote: self.remote,
            conversation_id: self.conversation_id,
            run_id: self.run_id,
            mode: self.mode,
            status: self.status,
            preview: parse(self.preview),
            result: parse(self.result),
            error: self.error,
            job_id: self.job_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            decided_at: self.decided_at,
            decided_by: self.decided_by,
            note: self.note,
            finished_at: self.finished_at,
        }
    }
}

async fn row(db: &Db, id: i64) -> Result<Option<Row>> {
    let sql = format!("SELECT {COLS} FROM change_requests WHERE id = ?");
    Ok(sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn get(db: &Db, id: i64) -> Result<Option<ChangeRequest>> {
    Ok(row(db, id).await?.map(Row::view))
}

/// Newest first. `status` = "open" for pending ones, a single status, or None for all.
pub async fn list(db: &Db, status: Option<&str>, limit: i64) -> Result<Vec<ChangeRequest>> {
    let status = match status {
        Some("open") => Some("pending"),
        s => s,
    };
    let sql = format!(
        "SELECT {COLS} FROM change_requests WHERE (?1 IS NULL OR status = ?1) ORDER BY id DESC LIMIT ?2"
    );
    Ok(sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
        .bind(status)
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await?
        .into_iter()
        .map(Row::view)
        .collect())
}

pub async fn for_conversations(db: &Db, ids: &[String]) -> Result<Vec<ChangeRequest>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let marks = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT {COLS} FROM change_requests WHERE conversation_id IN ({marks}) ORDER BY id"
    );
    let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
    for id in ids {
        q = q.bind(id);
    }
    Ok(q.fetch_all(db).await?.into_iter().map(Row::view).collect())
}

pub async fn pending_count(db: &Db) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM change_requests WHERE status = 'pending'")
            .fetch_one(db)
            .await?,
    )
}

fn emit(state: &Shared, id: i64, status: &str) {
    state.emit(Event::Approval {
        id,
        status: status.into(),
    });
}

/// Files a request. Auto-approved actions run before this returns; the others are dry-run
/// (when supported) and wait for a person.
pub async fn request(
    state: &Shared,
    action: &str,
    args: Value,
    reason: &str,
    origin: Origin,
) -> Result<ChangeRequest> {
    let def = find(action).ok_or_else(|| {
        invalid(format!(
            "未知的操作 {action}，可用操作见 list_change_actions"
        ))
    })?;
    if origin.source == "agent" && !def.agent {
        return Err(invalid(format!("内置 Agent 不能申请 {action}")));
    }
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(invalid("必须写明调用理由（reason）"));
    }
    if reason.chars().count() > MAX_REASON {
        return Err(invalid(format!("理由不能超过 {MAX_REASON} 个字符")));
    }
    let args = if args.is_null() { json!({}) } else { args };
    let summary = validate(def, &args)?;
    let mode = mode_of(&state.db, def).await?;

    let preview = if mode == Mode::Approve && def.dry_run {
        let job = run_host(
            state,
            def.name,
            args.clone(),
            true,
            origin.via(None),
            Duration::from_secs(60),
        )
        .await?;
        if job.status == "failed" {
            return Err(invalid(format!(
                "预演失败，未提交申请：{}",
                job.error.as_deref().unwrap_or("未知错误")
            )));
        }
        Some(job_view(&job))
    } else {
        None
    };

    let now = now_ms();
    let (status, decided_by, decided_at) = match mode {
        Mode::Auto => ("approved", Some("auto"), Some(now)),
        Mode::Approve => ("pending", None, None),
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO change_requests (action, summary, args, reason, source, actor, remote, conversation_id, run_id, mode, status, preview, created_at, expires_at, decided_at, decided_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(def.name)
    .bind(&summary)
    .bind(args.to_string())
    .bind(reason)
    .bind(origin.source)
    .bind(&origin.actor)
    .bind(&origin.remote)
    .bind(&origin.conversation_id)
    .bind(&origin.run_id)
    .bind(mode.as_str())
    .bind(status)
    .bind(preview.as_ref().map(Value::to_string))
    .bind(now)
    .bind(now + REQUEST_TTL_MS)
    .bind(decided_at)
    .bind(decided_by)
    .fetch_one(&state.db)
    .await?;
    if mode == Mode::Auto {
        // run inline (bounded like the old direct writes) so the caller gets the result
        execute(state, id, Duration::from_secs(120)).await?;
    } else {
        emit(state, id, "pending");
    }
    get(&state.db, id).await?.context("request just stored")
}

/// Approves a pending request and runs it in the background.
pub async fn approve(state: &Shared, id: i64, by: &str) -> Result<ChangeRequest> {
    let now = now_ms();
    let done = sqlx::query(
        "UPDATE change_requests SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending' AND expires_at > ?",
    )
    .bind(now)
    .bind(by)
    .bind(id)
    .bind(now)
    .execute(&state.db)
    .await?
    .rows_affected();
    if done == 0 {
        return Err(invalid("申请不存在、已处理或已过期"));
    }
    emit(state, id, "approved");
    let st = state.clone();
    tokio::spawn(async move {
        if let Err(e) = execute(&st, id, HOST_WAIT).await {
            tracing::warn!("change request {id}: {e:#}");
        }
    });
    get(&state.db, id).await?.context("request vanished")
}

pub async fn reject(
    state: &Shared,
    id: i64,
    by: &str,
    note: Option<&str>,
) -> Result<ChangeRequest> {
    let note = note
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| short(n, 500));
    let done = sqlx::query(
        "UPDATE change_requests SET status = 'rejected', decided_at = ?, decided_by = ?, note = ?, finished_at = ? WHERE id = ? AND status = 'pending'",
    )
    .bind(now_ms())
    .bind(by)
    .bind(&note)
    .bind(now_ms())
    .bind(id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if done == 0 {
        return Err(invalid("申请不存在或已处理"));
    }
    emit(state, id, "rejected");
    get(&state.db, id).await?.context("request vanished")
}

/// Runs an approved request and stores the outcome.
async fn execute(state: &Shared, id: i64, wait: Duration) -> Result<()> {
    let r = row(&state.db, id).await?.context("request not found")?;
    if r.status != "approved" {
        return Ok(());
    }
    let def = find(&r.action).context("action left the catalog")?;
    let args = r.raw_args();
    let origin = r.origin();
    let (status, result, error, job_id) = if def.kind == Kind::Host && def.name != "packages.job" {
        match run_host(
            state,
            def.name,
            args,
            false,
            origin.via(r.decided_by.as_deref()),
            wait,
        )
        .await
        {
            Ok(job) if job.status == "running" => {
                // a long job (image pull): keep the request open and close it when the job ends
                sqlx::query("UPDATE change_requests SET job_id = ? WHERE id = ?")
                    .bind(job.id)
                    .bind(id)
                    .execute(&state.db)
                    .await?;
                let (st, job_id) = (state.clone(), job.id);
                tokio::spawn(async move {
                    let job = crate::ops::wait(&st, job_id, HOST_WAIT).await;
                    let (status, view, error) = match &job {
                        Ok(Some(j)) if j.status == "running" => (
                            "failed",
                            Some(job_view(j)),
                            Some("执行超时，请在运维记录中查看任务状态".to_string()),
                        ),
                        Ok(Some(j)) => (
                            if j.status == "failed" {
                                "failed"
                            } else {
                                "executed"
                            },
                            Some(job_view(j)),
                            j.error.clone(),
                        ),
                        _ => ("failed", None, Some("任务记录丢失".to_string())),
                    };
                    if let Err(e) = finish(&st, &r, status, view, error, Some(job_id)).await {
                        tracing::warn!("change request {}: {e:#}", r.id);
                    }
                });
                return Ok(());
            }
            Ok(job) => {
                let ok = job.status != "failed";
                (
                    if ok { "executed" } else { "failed" },
                    Some(job_view(&job)),
                    job.error.clone(),
                    Some(job.id),
                )
            }
            Err(e) => ("failed", None, Some(user_error(&e)), None),
        }
    } else {
        match run_panel(state, def.name, &args).await {
            Ok(v) => ("executed", Some(v), None, None),
            Err(e) => ("failed", None, Some(user_error(&e)), None),
        }
    };
    finish(state, &r, status, result, error, job_id).await
}

async fn finish(
    state: &Shared,
    r: &Row,
    status: &str,
    result: Option<Value>,
    error: Option<String>,
    job_id: Option<i64>,
) -> Result<()> {
    let id = r.id;
    sqlx::query(
        "UPDATE change_requests SET status = ?, result = ?, error = ?, job_id = ?, finished_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(result.as_ref().map(Value::to_string))
    .bind(&error)
    .bind(job_id)
    .bind(now_ms())
    .bind(id)
    .execute(&state.db)
    .await?;
    emit(state, id, status);
    if r.mode == "approve" {
        report_back(state, r, status, error.as_deref()).await;
    }
    Ok(())
}

/// Error text safe to show: validation and helper refusals as is, the rest generic.
fn user_error(e: &anyhow::Error) -> String {
    if let Some(i) = e.downcast_ref::<Invalid>() {
        return i.0.clone();
    }
    if let Some(op) = e.downcast_ref::<crate::ops::proto::OpError>() {
        return op.message.clone();
    }
    tracing::warn!("change request failed: {e:#}");
    "执行失败（详见服务日志）".into()
}

/// Tells the built-in agent's conversation how its approved request went, so it can verify.
async fn report_back(state: &Shared, r: &Row, status: &str, error: Option<&str>) {
    let (Some(conv), "agent") = (r.conversation_id.as_deref(), r.source.as_str()) else {
        return;
    };
    let Some(agent) = state.agent().cloned() else {
        return;
    };
    let outcome = match status {
        "executed" => "已执行成功".to_string(),
        _ => format!("执行失败：{}", error.unwrap_or("未知错误")),
    };
    let text = format!(
        "【系统通知】变更申请 #{}（{}）已由 {} 批准，{outcome}。请用只读工具确认实际效果，简要说明是否达到预期；如果还需要其他变更，继续用 propose_change 提交申请。",
        r.id,
        r.summary,
        r.decided_by.as_deref().unwrap_or("管理员"),
    );
    if let Err(e) = agent.send_message(conv, &text).await {
        tracing::warn!("reporting change request {} to {conv}: {e}", r.id);
    }
}

/// Marks pending requests past their deadline as expired.
pub async fn expire(state: &Shared) -> Result<()> {
    let now = now_ms();
    let ids: Vec<i64> = sqlx::query_scalar(
        "UPDATE change_requests SET status = 'expired', finished_at = ? WHERE status = 'pending' AND expires_at <= ? RETURNING id",
    )
    .bind(now)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    for id in ids {
        emit(state, id, "expired");
    }
    Ok(())
}

/// Startup: requests left `approved` by a restart cannot be resumed safely.
pub async fn close_stale(db: &Db) -> Result<()> {
    sqlx::query(
        "UPDATE change_requests SET status = 'failed', error = '服务重启，执行结果未知，请检查后重新申请', finished_at = ? WHERE status = 'approved'",
    )
    .bind(now_ms())
    .execute(db)
    .await?;
    Ok(())
}

pub fn spawn(state: &Shared) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = close_stale(&state.db).await {
            tracing::warn!("closing stale change requests: {e:#}");
        }
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = state.shutdown_requested() => break,
            }
            if let Err(e) = expire(&state).await {
                tracing::warn!("expiring change requests: {e:#}");
            }
        }
    });
}

/// Waits up to `timeout` for a request to leave `pending`/`approved`.
pub async fn wait(state: &Shared, id: i64, timeout: Duration) -> Result<Option<ChangeRequest>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut rx = state.events.subscribe();
    loop {
        let r = get(&state.db, id).await?;
        match &r {
            Some(c) if matches!(c.status.as_str(), "pending" | "approved") => {}
            _ => return Ok(r),
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(r);
        }
        // wake on any approval event (or every few seconds in case one was missed)
        let _ = tokio::time::timeout(left.min(Duration::from_secs(5)), async {
            loop {
                match rx.recv().await {
                    Ok(Event::Approval { id: got, .. }) if got == id => break,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                }
            }
        })
        .await;
    }
}

/// Catalog for agents: name, label, policy and argument hint.
pub async fn catalog_view(db: &Db, for_agent: bool) -> Result<Vec<Value>> {
    Ok(policies(db)
        .await?
        .into_iter()
        .filter(|p| !for_agent || p.agent)
        .map(|p| {
            let def = find(p.action).expect("policy comes from the catalog");
            json!({
                "action": p.action,
                "label": p.label,
                "kind": p.kind,
                "needs_approval": p.mode == Mode::Approve,
                "args": def.args,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_consistent() {
        let mut names: Vec<_> = CATALOG.iter().map(|a| a.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CATALOG.len(), "duplicate action");
        // every helper write call is covered, except confirming (people only)
        for (call, _) in crate::ops::calls::WRITE_CALLS {
            if *call == "pending.confirm" {
                assert!(find(call).is_none());
            } else {
                assert!(find(call).is_some_and(|a| a.kind == Kind::Host), "{call}");
            }
        }
        // host changes need a person by default
        for a in CATALOG.iter().filter(|a| a.kind == Kind::Host) {
            assert!(
                a.default == Mode::Approve || matches!(a.name, "nginx.test" | "pending.revert"),
                "{}",
                a.name
            );
        }
        for a in CATALOG {
            serde_json::from_str::<Value>(a.args).unwrap_or_else(|e| panic!("{}: {e}", a.name));
        }
    }

    #[test]
    fn validation() {
        let d = |n| find(n).unwrap();
        assert!(
            validate(d("alert.ack"), &json!({ "id": 3 }))
                .unwrap()
                .contains("#3")
        );
        assert!(validate(d("alert.ack"), &json!({ "id": 3, "x": 1 })).is_err());
        assert!(validate(d("alert.silence"), &json!({ "id": 3, "minutes": 99999 })).is_err());
        assert!(validate(d("analysis.trigger"), &json!({ "kind": "weekly" })).is_err());
        assert!(
            validate(
                d("nginx.write"),
                &json!({ "path": "a", "content": "x <redacted> y" })
            )
            .is_err()
        );
        assert!(validate(d("packages.job"), &json!({ "op": "upgrade_all" })).is_ok());
        assert!(validate(d("task.update"), &json!({ "enabled": false })).is_err());
        assert!(validate(d("task.update"), &json!({ "id": "t1", "enabled": false })).is_ok());
        assert_eq!(
            validate(
                d("docker.container"),
                &json!({ "id": "web", "action": "restart" })
            )
            .unwrap(),
            "重启容器 web"
        );
    }

    fn origin(source: &'static str) -> Origin {
        Origin {
            source,
            actor: "token:ci".into(),
            remote: None,
            conversation_id: None,
            run_id: None,
        }
    }

    async fn state() -> Shared {
        let db = crate::store::open_memory().await;
        crate::state::AppState::new(std::sync::Arc::new(crate::config::Config::default()), db)
    }

    #[tokio::test]
    async fn policy_override_and_reset() {
        let s = state().await;
        let get_mode = |p: &[PolicyView], n: &str| p.iter().find(|x| x.action == n).unwrap().mode;
        assert_eq!(
            get_mode(&policies(&s.db).await.unwrap(), "task.delete"),
            Mode::Approve
        );
        set_policy(&s.db, "task.delete", "auto", "root")
            .await
            .unwrap();
        assert_eq!(
            get_mode(&policies(&s.db).await.unwrap(), "task.delete"),
            Mode::Auto
        );
        set_policy(&s.db, "task.delete", "approve", "root")
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM approval_policy")
            .fetch_one(&s.db)
            .await
            .unwrap();
        assert_eq!(n, 0, "back to default removes the override");
        assert!(set_policy(&s.db, "nope", "auto", "root").await.is_err());
        assert!(
            set_policy(&s.db, "task.delete", "maybe", "root")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn request_lifecycle() {
        let s = state().await;
        // reason is mandatory
        assert!(
            request(
                &s,
                "task.delete",
                json!({ "id": "t1" }),
                "  ",
                origin("mcp")
            )
            .await
            .is_err()
        );
        // the built-in agent cannot start conversations
        assert!(
            request(
                &s,
                "agent.ask",
                json!({ "message": "hi" }),
                "why",
                origin("agent")
            )
            .await
            .is_err()
        );

        let r = request(
            &s,
            "task.delete",
            json!({ "id": "t1" }),
            "清理",
            origin("mcp"),
        )
        .await
        .unwrap();
        assert_eq!(r.status, "pending");
        assert_eq!(r.reason, "清理");
        assert_eq!(pending_count(&s.db).await.unwrap(), 1);

        let rej = reject(&s, r.id, "root", Some("不需要")).await.unwrap();
        assert_eq!(rej.status, "rejected");
        assert!(
            approve(&s, r.id, "root").await.is_err(),
            "decided requests stay decided"
        );

        // approval runs it (the task does not exist, so it fails cleanly)
        let r2 = request(
            &s,
            "task.delete",
            json!({ "id": "t1" }),
            "清理",
            origin("mcp"),
        )
        .await
        .unwrap();
        approve(&s, r2.id, "root").await.unwrap();
        let done = wait(&s, r2.id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done.status, "failed");
        assert_eq!(done.decided_by.as_deref(), Some("root"));
        assert!(done.error.unwrap().contains("不存在"));

        // expiry
        let r3 = request(
            &s,
            "task.delete",
            json!({ "id": "t2" }),
            "清理",
            origin("mcp"),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE change_requests SET expires_at = 0 WHERE id = ?")
            .bind(r3.id)
            .execute(&s.db)
            .await
            .unwrap();
        assert!(approve(&s, r3.id, "root").await.is_err());
        expire(&s).await.unwrap();
        assert_eq!(get(&s.db, r3.id).await.unwrap().unwrap().status, "expired");
    }

    #[tokio::test]
    async fn auto_policy_runs_at_once() {
        let s = state().await;
        let r = request(
            &s,
            "alert.ack",
            json!({ "id": 42 }),
            "已知问题",
            origin("mcp"),
        )
        .await
        .unwrap();
        assert_eq!(r.mode, "auto");
        assert_eq!(r.decided_by.as_deref(), Some("auto"));
        // no such alert: recorded as failed, not left pending
        assert_eq!(r.status, "failed");
        assert_eq!(pending_count(&s.db).await.unwrap(), 0);
    }
}
