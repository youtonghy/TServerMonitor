//! Prompt library: built-in task prompts shipped in code (read-only) and user prompts in the
//! `prompts` table. A prompt is only the *task text*; the system prompt with the read-only and
//! untrusted-data rules is always prepended and cannot be replaced.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::model::now_ms;
use crate::settings::Invalid;
use crate::store::Db;

#[derive(Debug, Clone, Serialize)]
pub struct Prompt {
    pub id: String,
    pub name: String,
    pub description: String,
    pub body: String,
    pub builtin: bool,
    /// Suggested routing kind when a task uses this prompt.
    pub route_kind: String,
    pub updated_at: Option<i64>,
}

struct Builtin {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    route_kind: &'static str,
    body: &'static str,
}

pub const HOURLY: &str =
    "任务：小时巡检。快速判断过去一小时是否有异常趋势或需要关注的问题，结论简明。建议最多 3 条。";
pub const DAILY: &str = "任务：生成每日运维简报。回顾过去 24 小时（必要时对比 7 天）的资源趋势、错误与慢日志模式、容器稳定性、数据库表现和安全体检结果，输出系统运行瓶颈与按优先级排序的代码/配置/架构改良建议（5~10 条）。可调用 get_report_history 对比之前的结论。";
pub const INCIDENT: &str = "任务：异常事件分析（触发原因：{trigger}）。系统检测到日志或错误突增，已进入深度日志分析模式。请定位突增来源，找出主要错误模板和首次出现时间，结合资源与容器状态判断根因，并给出止血和根治建议。";
pub const AUDIT: &str = "任务：空闲窗口深度审计。对历史日志做回溯（可导出样本用脚本统计），并对安全基线（端口暴露、登录爆破、更新、内核与 SSH 配置）和性能隐患做系统性审计，输出审计结论与整改清单。";

const BUILTINS: &[Builtin] = &[
    Builtin {
        id: "builtin:linux_check",
        name: "Linux 系统健康检查",
        description: "CPU、内存、交换、磁盘与 I/O、负载、网络、监听端口与容器的全面体检",
        route_kind: "default",
        body: "任务：Linux 系统健康检查。依次检查并给出结论：\n1. CPU 使用率与负载（对比核数），是否有持续高位或周期性尖峰；\n2. 内存与交换分区使用，是否存在内存压力或 OOM 迹象；\n3. 各挂载点磁盘使用率和磁盘 I/O，是否有即将写满的分区；\n4. 网络吞吐是否异常；\n5. 监听端口中哪些对外暴露、是否有不必要的服务；\n6. 容器的重启、OOM、健康检查状态；\n7. 最近的错误日志模板。\n对每一项给出健康评分依据，发现的问题按优先级给出具体可执行的处理建议（命令或配置项）。",
    },
    Builtin {
        id: "builtin:security_check",
        name: "每日本机安全体检",
        description: "端口暴露、SSH 配置、登录爆破、待装安全更新、内核参数基线",
        route_kind: "security_check",
        body: "任务：每日本机安全体检。基于安全发现（list_findings）、监听端口（list_ports）和认证日志模板（search_log_clusters），检查：\n1. 对公网暴露的端口与对应进程，哪些应只监听内网或本机；\n2. SSH 配置（root 登录、密码登录、端口）；\n3. 过去 24 小时的登录失败与爆破来源，是否有成功的异常登录；\n4. 待安装的安全更新数量与是否需要重启；\n5. 内核与网络参数基线偏差；\n6. 容器是否以特权或宿主机网络运行（如可从数据判断）。\n与上一次体检对比新增与已修复的问题，输出风险清单（严重度、证据、整改命令）。",
    },
    Builtin {
        id: "builtin:log_scan",
        name: "日志扫描",
        description: "扫描新出现或增长最快的错误模板、慢日志与突增来源",
        route_kind: "log_scan",
        body: "任务：日志扫描（触发原因：{trigger}）。查看各日志源的错误率趋势（get_log_rates）和错误/慢日志模板（search_log_clusters），找出：\n1. 新出现的错误模板与首次出现时间；\n2. 计数增长最快的模板及其来源；\n3. 慢查询或慢请求的共同模式。\n必要时导出样本用脚本做聚合统计。对每个问题判断影响范围和可能根因，给出排查与修复建议。没有明显问题时简要说明即可。",
    },
    Builtin {
        id: "builtin:package_advice",
        name: "包更新建议",
        description: "评估待升级软件包的风险与升级顺序",
        route_kind: "package_advice",
        body: "任务：软件包更新评估。根据待升级软件包列表，区分安全更新与普通更新，指出涉及内核、OpenSSL、OpenSSH、glibc、数据库、Web 服务器、Docker 等关键组件的升级风险（是否需要重启服务或主机、是否可能有配置变更），给出建议的升级顺序、维护窗口与回滚注意事项。只给建议，不执行任何命令。",
    },
    Builtin {
        id: "builtin:hourly",
        name: "小时巡检（系统内置）",
        description: "每小时自动运行的快速巡检",
        route_kind: "hourly",
        body: HOURLY,
    },
    Builtin {
        id: "builtin:daily",
        name: "每日运维简报（系统内置）",
        description: "每天定时生成的运维简报",
        route_kind: "daily",
        body: DAILY,
    },
    Builtin {
        id: "builtin:incident",
        name: "异常事件分析（系统内置）",
        description: "日志或错误突增时自动运行",
        route_kind: "incident",
        body: INCIDENT,
    },
    Builtin {
        id: "builtin:audit",
        name: "深度审计（系统内置）",
        description: "夜间空闲窗口内的深度审计",
        route_kind: "audit",
        body: AUDIT,
    },
];

fn builtin(b: &Builtin) -> Prompt {
    Prompt {
        id: b.id.into(),
        name: b.name.into(),
        description: b.description.into(),
        body: b.body.into(),
        builtin: true,
        route_kind: b.route_kind.into(),
        updated_at: None,
    }
}

pub async fn list(db: &Db) -> Result<Vec<Prompt>> {
    let mut out: Vec<Prompt> = BUILTINS.iter().map(builtin).collect();
    let rows = sqlx::query_as::<_, (String, String, String, String, i64)>(
        "SELECT id, name, description, body, updated_at FROM prompts ORDER BY updated_at DESC",
    )
    .fetch_all(db)
    .await?;
    out.extend(
        rows.into_iter()
            .map(|(id, name, description, body, updated_at)| Prompt {
                id,
                name,
                description,
                body,
                builtin: false,
                route_kind: "default".into(),
                updated_at: Some(updated_at),
            }),
    );
    Ok(out)
}

pub async fn get(db: &Db, id: &str) -> Result<Option<Prompt>> {
    if let Some(b) = BUILTINS.iter().find(|b| b.id == id) {
        return Ok(Some(builtin(b)));
    }
    Ok(list(db).await?.into_iter().find(|p| p.id == id))
}

#[derive(Debug, Deserialize)]
pub struct PromptInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub body: Option<String>,
}

const MAX_BODY: usize = 8000;

fn check(name: &str, description: &str, body: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 64 {
        return Err(Invalid("名称不能为空，且不超过 64 个字符".into()).into());
    }
    if description.chars().count() > 200 {
        return Err(Invalid("描述不超过 200 个字符".into()).into());
    }
    if body.trim().is_empty() || body.chars().count() > MAX_BODY {
        return Err(Invalid(format!("提示词不能为空，且不超过 {MAX_BODY} 个字符")).into());
    }
    Ok(())
}

pub async fn create(db: &Db, inp: PromptInput) -> Result<String> {
    let (name, description, body) = (
        inp.name.unwrap_or_default(),
        inp.description.unwrap_or_default(),
        inp.body.unwrap_or_default(),
    );
    check(&name, &description, &body)?;
    let id = format!("u_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let now = now_ms();
    sqlx::query("INSERT INTO prompts (id, name, description, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(name.trim())
        .bind(description.trim())
        .bind(body.trim())
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn update(db: &Db, id: &str, inp: PromptInput) -> Result<bool> {
    if id.starts_with("builtin:") {
        return Err(Invalid("内置提示词只读，可以复制后修改".into()).into());
    }
    let Some(cur) = get(db, id).await? else {
        return Ok(false);
    };
    let name = inp.name.unwrap_or(cur.name);
    let description = inp.description.unwrap_or(cur.description);
    let body = inp.body.unwrap_or(cur.body);
    check(&name, &description, &body)?;
    sqlx::query(
        "UPDATE prompts SET name = ?, description = ?, body = ?, updated_at = ? WHERE id = ?",
    )
    .bind(name.trim())
    .bind(description.trim())
    .bind(body.trim())
    .bind(now_ms())
    .bind(id)
    .execute(db)
    .await?;
    Ok(true)
}

pub async fn delete(db: &Db, id: &str) -> Result<bool> {
    if id.starts_with("builtin:") {
        return Err(Invalid("内置提示词不能删除".into()).into());
    }
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM scheduled_tasks WHERE prompt_id = ?")
        .bind(id)
        .fetch_one(db)
        .await?;
    if used > 0 {
        return Err(Invalid("有自动任务正在使用这个提示词，请先修改或删除这些任务".into()).into());
    }
    Ok(sqlx::query("DELETE FROM prompts WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected()
        > 0)
}

/// System prompt for drafting a task prompt from a short description.
pub const GENERATOR_SYSTEM: &str = r#"你是 TServerMonitor 的提示词助手。用户会描述一个希望 AI 运维参谋定期执行的检查任务，你需要写出这个任务的“任务说明”。

要求：
- 以“任务：”开头，用简体中文，分条列出要检查的项目和判断标准，200~600 字。
- 只能要求参谋使用这些只读能力：主机指标、容器状态与日志、日志错误/慢日志模板与错误率、安全发现、监听端口、告警、数据库指标、历史报告，以及在隔离工作区内用 Python 做统计。
- 不要要求执行任何修改操作（重启、改配置、安装、删除），只能要求给出建议。
- 输出时只给任务说明正文，不要任何解释、标题或代码块。"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builtins_are_read_only_and_user_prompts_crud() {
        let db = crate::store::open_memory().await;
        let all = list(&db).await.unwrap();
        assert!(all.iter().any(|p| p.id == "builtin:linux_check"));
        assert!(
            update(
                &db,
                "builtin:daily",
                PromptInput {
                    name: Some("x".into()),
                    description: None,
                    body: None
                }
            )
            .await
            .is_err()
        );

        let id = create(
            &db,
            PromptInput {
                name: Some("磁盘".into()),
                description: None,
                body: Some("任务：看磁盘".into()),
            },
        )
        .await
        .unwrap();
        assert!(
            update(
                &db,
                &id,
                PromptInput {
                    name: None,
                    description: Some("d".into()),
                    body: None
                }
            )
            .await
            .unwrap()
        );
        assert_eq!(get(&db, &id).await.unwrap().unwrap().description, "d");
        assert!(
            create(
                &db,
                PromptInput {
                    name: Some("空".into()),
                    description: None,
                    body: Some("  ".into())
                }
            )
            .await
            .is_err()
        );
        // seeded tasks reference built-in prompts, which keep existing
        assert!(get(&db, "builtin:security_check").await.unwrap().is_some());
        assert!(delete(&db, &id).await.unwrap());
    }
}
