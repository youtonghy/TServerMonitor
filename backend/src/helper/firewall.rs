//! Firewall domain. ufw and firewalld: add / delete rules (and ufw enable / disable).
//! nftables: block rules in a dedicated `inet tsmonitor` table only. iptables: read-only.
//! Every change is confirm-or-revert and checked against the SSH lockout guard.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::config::{FirewallBackend, FirewallOp, HelperConfig};
use super::pending::RevertPlan;
use super::{Call, Ctx, Domain, Log, exec, fsutil, not_enabled, op_not_allowed};
use crate::ops::firewall::{self as fw, NewRule, Status};
use crate::ops::proto::{OpError, OpResult};

const T: Duration = Duration::from_secs(30);
const RAW_MAX: usize = 20_000;
const UFW_RULES: &[&str] = &["/etc/ufw/user.rules", "/etc/ufw/user6.rules"];

fn has(bin: &str) -> bool {
    crate::sandbox::which(bin).is_some()
}

pub async fn backend(cfg: &HelperConfig) -> Option<FirewallBackend> {
    if let Some(b) = cfg.firewall.backend {
        return Some(b);
    }
    if has("ufw") {
        return Some(FirewallBackend::Ufw);
    }
    if has("firewall-cmd")
        && exec::run(&exec::argv(&["firewall-cmd", "--state"]), T)
            .await
            .is_ok_and(|o| o.stdout.trim() == "running")
    {
        return Some(FirewallBackend::Firewalld);
    }
    if has("nft") {
        return Some(FirewallBackend::Nftables);
    }
    has("iptables").then_some(FirewallBackend::Iptables)
}

fn allow(ctx: &Ctx, op: FirewallOp) -> OpResult<()> {
    if ctx.cfg.firewall.allow.contains(&op) {
        Ok(())
    } else {
        Err(op_not_allowed("firewall", &op))
    }
}

async fn out(argv: &[&str]) -> OpResult<String> {
    let o = exec::run(&exec::argv(argv), T).await?;
    if !o.ok() {
        return Err(OpError::failed(format!(
            "{}：{}",
            argv.join(" "),
            o.message()
        )));
    }
    Ok(o.stdout)
}

fn truncate(mut s: String) -> String {
    if s.len() > RAW_MAX {
        let mut cut = RAW_MAX;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n…（已截断）");
    }
    s
}

async fn zone(ctx: &Ctx) -> OpResult<String> {
    if let Some(z) = &ctx.cfg.firewall.zone {
        return Ok(z.clone());
    }
    let z = out(&["firewall-cmd", "--get-default-zone"]).await?;
    crate::ops::validate::simple_name("zone", z.trim())
}

pub async fn status(ctx: &Ctx) -> OpResult<Status> {
    let b = backend(&ctx.cfg).await.ok_or_else(|| {
        OpError::new(
            crate::ops::proto::ErrorCode::Unsupported,
            "没有找到 ufw、firewalld、nftables 或 iptables",
        )
    })?;
    let ssh_ports = super::ssh::ports(ctx).await;
    let mut st = Status {
        ssh_ports,
        notes: vec![
            "Docker 发布的容器端口由 Docker 自己的 iptables 规则放行，不受 ufw/firewalld 入站规则限制".into(),
        ],
        ..Default::default()
    };
    match b {
        FirewallBackend::Ufw => {
            st.backend = "ufw".into();
            let s = out(&["ufw", "status", "verbose"]).await?;
            (st.active, st.default_incoming) = fw::parse_ufw_status(&s);
            st.rules = fw::parse_ufw_added(&out(&["ufw", "show", "added"]).await?);
            st.raw = truncate(s);
            st.writable = true;
        }
        FirewallBackend::Firewalld => {
            st.backend = "firewalld".into();
            let z = zone(ctx).await?;
            let s = out(&["firewall-cmd", &format!("--zone={z}"), "--list-all"]).await?;
            let (_, rules) = fw::parse_firewalld(&s);
            st.rules = rules;
            st.active = true;
            st.zone = Some(z);
            st.raw = truncate(s);
            st.writable = true;
            st.notes.push("变更先写入运行时配置，确认后才会持久化（--runtime-to-permanent，会一并持久化其他未保存的运行时改动）".into());
        }
        FirewallBackend::Nftables => {
            st.backend = "nftables".into();
            st.active = true;
            st.raw = truncate(out(&["nft", "list", "ruleset"]).await.unwrap_or_default());
            st.rules = exec::run(
                &exec::argv(&["nft", "-a", "list", "table", "inet", fw::NFT_TABLE]),
                T,
            )
            .await
            .ok()
            .filter(|o| o.ok())
            .map(|o| fw::parse_nft_table(&o.stdout))
            .unwrap_or_default();
            st.writable = true;
            st.notes.push(format!(
                "nftables 下面板只能在独立的 inet {} 表中添加拒绝规则，且仅在运行时生效（重启后需自行持久化）",
                fw::NFT_TABLE
            ));
        }
        FirewallBackend::Iptables => {
            st.backend = "iptables".into();
            st.active = true;
            st.raw = truncate(out(&["iptables", "-S"]).await?);
            st.notes
                .push("iptables 仅支持查看；规则顺序与持久化方式因发行版而异，请手动维护".into());
        }
    }
    Ok(st)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArgs {
    spec: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToggleArgs {
    enabled: bool,
}

async fn run_all(log: &Log, cmds: &[Vec<String>]) -> OpResult<()> {
    for argv in cmds {
        let o = exec::run_logged(log, argv, T).await?;
        if !o.ok() {
            return Err(OpError::failed(format!(
                "{} 失败：{}",
                argv[0],
                o.message()
            )));
        }
    }
    Ok(())
}

/// Revert plan and confirm steps for one change on the current backend.
async fn plan(ctx: &Ctx, backend: &str) -> OpResult<(RevertPlan, Vec<Vec<String>>)> {
    let st = &ctx.cfg.state_dir;
    Ok(match backend {
        "ufw" => {
            let mut restore = Vec::new();
            for p in UFW_RULES {
                restore.push(fsutil::backup(st, "firewall", std::path::Path::new(p))?);
            }
            (
                RevertPlan {
                    restore,
                    commands: vec![exec::argv(&["ufw", "reload"])],
                },
                vec![],
            )
        }
        "firewalld" => (
            RevertPlan {
                restore: vec![],
                commands: vec![exec::argv(&["firewall-cmd", "--reload"])],
            },
            vec![exec::argv(&["firewall-cmd", "--runtime-to-permanent"])],
        ),
        "nftables" => {
            let dump = exec::run(
                &exec::argv(&["nft", "list", "table", "inet", fw::NFT_TABLE]),
                T,
            )
            .await?;
            // revert = drop our table, then load the saved copy if there was one; the dump lives
            // with the other backups and is pruned with them
            let mut commands = vec![exec::argv(&[
                "nft",
                "delete",
                "table",
                "inet",
                fw::NFT_TABLE,
            ])];
            if dump.ok() {
                let dir = st.join("backups").join("firewall");
                std::fs::create_dir_all(&dir).map_err(|e| OpError::failed(e.to_string()))?;
                let f = dir.join(format!("nft-{}.nft", crate::model::now_ms()));
                std::fs::write(&f, &dump.stdout).map_err(|e| OpError::failed(e.to_string()))?;
                commands.push(vec![
                    "nft".into(),
                    "-f".into(),
                    f.to_string_lossy().into_owned(),
                ]);
            }
            (
                RevertPlan {
                    restore: vec![],
                    commands,
                },
                vec![],
            )
        }
        _ => return Err(OpError::invalid("此后端不支持修改")),
    })
}

pub async fn handle(ctx: &Ctx, op: &str, call: Call<'_>) -> OpResult<Value> {
    if !ctx.cfg.firewall.enabled {
        return Err(not_enabled("firewall"));
    }
    match op {
        "status" => Ok(json!(status(ctx).await?)),
        "add" => {
            let r: NewRule = call.args()?;
            allow(ctx, FirewallOp::AddRule)?;
            let rule = r.check()?;
            let _g = ctx.lock(Domain::Firewall).await?;
            let st = status(ctx).await?;
            if !st.writable {
                return Err(OpError::invalid(format!("{} 后端不支持修改", st.backend)));
            }
            fw::guard_add(&rule, &st.ssh_ports)?;
            let cmds = match st.backend.as_str() {
                "ufw" => vec![fw::ufw_add_argv(&rule)],
                "firewalld" => {
                    fw::firewalld_add_argv(st.zone.as_deref().unwrap_or("public"), &rule)?
                }
                _ => {
                    let mut c = fw::nft_ensure_table_argv();
                    c.extend(fw::nft_add_argv(&rule)?);
                    c
                }
            };
            change(
                ctx,
                &st.backend,
                format!("添加规则：{}", rule.summary()),
                cmds,
                &call,
            )
            .await
        }
        "delete" => {
            let a: DeleteArgs = call.args()?;
            allow(ctx, FirewallOp::DeleteRule)?;
            let _g = ctx.lock(Domain::Firewall).await?;
            let st = status(ctx).await?;
            let target = st
                .rules
                .iter()
                .find(|r| r.spec == a.spec && r.deletable)
                .ok_or_else(|| OpError::invalid("找不到这条规则（可能已被修改），请刷新后重试"))?;
            fw::guard_delete(target, &st.rules, &st.ssh_ports, st.active)?;
            let cmds = match st.backend.as_str() {
                "ufw" => vec![fw::ufw_delete_argv(&target.spec)],
                "firewalld" => vec![fw::firewalld_delete_argv(
                    st.zone.as_deref().unwrap_or("public"),
                    &target.spec,
                )?],
                "nftables" => vec![fw::nft_delete_argv(&target.spec)?],
                b => return Err(OpError::invalid(format!("{b} 后端不支持修改"))),
            };
            change(
                ctx,
                &st.backend,
                format!("删除规则：{}", target.spec),
                cmds,
                &call,
            )
            .await
        }
        "toggle" => {
            let a: ToggleArgs = call.args()?;
            allow(ctx, FirewallOp::Toggle)?;
            let _g = ctx.lock(Domain::Firewall).await?;
            let st = status(ctx).await?;
            if st.backend != "ufw" {
                return Err(OpError::invalid("只有 ufw 支持从面板启用或停用"));
            }
            if a.enabled == st.active {
                call.log.line("防火墙已经是目标状态");
                return Ok(json!({ "changed": false }));
            }
            if a.enabled && !fw::ssh_admitted(&st.rules, &st.ssh_ports) {
                return Err(OpError::invalid(format!(
                    "拒绝：启用前必须先有一条对任意来源放行 SSH 端口 {:?} 的规则",
                    st.ssh_ports
                )));
            }
            let (cmd, undo) = if a.enabled {
                (
                    exec::argv(&["ufw", "--force", "enable"]),
                    exec::argv(&["ufw", "--force", "disable"]),
                )
            } else {
                (
                    exec::argv(&["ufw", "--force", "disable"]),
                    exec::argv(&["ufw", "--force", "enable"]),
                )
            };
            let summary = if a.enabled {
                "启用 ufw"
            } else {
                "停用 ufw"
            }
            .to_string();
            call.log.line(format!("$ {}", cmd.join(" ")));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let log = call.log.clone();
            let view = ctx
                .pending
                .guarded(
                    "firewall",
                    summary,
                    call.actor.clone(),
                    RevertPlan {
                        restore: vec![],
                        commands: vec![undo],
                    },
                    vec![],
                    || async move { run_all(&log, &[cmd]).await },
                )
                .await?;
            Ok(json!({ "pending": view }))
        }
        _ => Err(OpError::invalid(format!("unknown call firewall.{op}"))),
    }
}

async fn change(
    ctx: &Ctx,
    backend: &str,
    summary: String,
    cmds: Vec<Vec<String>>,
    call: &Call<'_>,
) -> OpResult<Value> {
    if call.dry_run {
        for c in &cmds {
            call.log.line(format!("$ {}", c.join(" ")));
        }
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true, "commands": cmds }));
    }
    let (revert, on_confirm) = plan(ctx, backend).await?;
    let log = call.log.clone();
    let view = ctx
        .pending
        .guarded(
            "firewall",
            summary,
            call.actor.clone(),
            revert,
            on_confirm,
            || async move { run_all(&log, &cmds).await },
        )
        .await?;
    call.log.line(format!(
        "已生效。请确认 SSH 仍能新建连接，并在 {} 秒内确认，否则自动回滚",
        ctx.cfg.confirm_secs
    ));
    Ok(json!({ "pending": view }))
}
