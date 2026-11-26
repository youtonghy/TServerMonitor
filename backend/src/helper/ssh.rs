//! SSH domain: effective sshd config, options through a drop-in (confirm-or-revert), and
//! `authorized_keys` management. Key files are opened with `openat` + `O_NOFOLLOW` below the
//! user's home and must be owned by that user, so a symlink or hard link planted by the user
//! cannot redirect a root write.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{Read, Seek, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::config::SshOp;
use super::fsutil;
use super::pending::RevertPlan;
use super::{Call, Ctx, Domain, Log, exec, not_enabled, op_not_allowed};
use crate::ops::proto::{OpError, OpResult};
use crate::ops::ssh::{self as model, LoginUser};
use crate::ops::validate;

fn allow(ctx: &Ctx, op: SshOp) -> OpResult<()> {
    if ctx.cfg.ssh.allow.contains(&op) {
        Ok(())
    } else {
        Err(op_not_allowed("ssh", &op))
    }
}

pub async fn effective(ctx: &Ctx) -> Option<BTreeMap<String, Vec<String>>> {
    let out = exec::run(
        &exec::argv(&[&ctx.cfg.ssh.sshd_binary, "-T"]),
        Duration::from_secs(15),
    )
    .await
    .ok()?;
    out.ok().then(|| model::parse_effective(&out.stdout))
}

/// Ports sshd listens on, for the firewall guard. Falls back to the config file, then 22.
pub async fn ports(ctx: &Ctx) -> Vec<u16> {
    if let Some(e) = effective(ctx).await {
        return model::ports(&e);
    }
    std::fs::read_to_string(&ctx.cfg.ssh.sshd_config)
        .map(|t| model::ports_from_config(&t))
        .unwrap_or_else(|_| vec![22])
}

async fn service_unit() -> &'static str {
    if exec::unit_loaded("ssh.service").await {
        "ssh.service"
    } else {
        "sshd.service"
    }
}

fn users() -> Vec<LoginUser> {
    std::fs::read_to_string("/etc/passwd")
        .map(|p| model::login_users(&p))
        .unwrap_or_default()
}

// ---------------------------------------------------------------- safe key file access

fn c(s: &str) -> OpResult<CString> {
    CString::new(s).map_err(|_| OpError::invalid("路径包含 NUL"))
}

fn last_err(what: &str) -> OpError {
    OpError::failed(format!("{what}：{}", std::io::Error::last_os_error()))
}

fn fstat(fd: i32) -> OpResult<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open descriptor and st is a properly sized buffer.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(last_err("fstat"));
    }
    Ok(st)
}

/// Opens `~user/.ssh/authorized_keys`. `None` when it does not exist and `create` is false.
fn open_keys(u: &LoginUser, create: bool) -> OpResult<Option<std::fs::File>> {
    let home = c(&u.home)?;
    // SAFETY: plain libc calls on NUL-terminated paths; every fd is wrapped in OwnedFd at once.
    unsafe {
        let hfd = libc::open(
            home.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if hfd < 0 {
            return if create {
                Err(last_err("打开家目录"))
            } else {
                Ok(None)
            };
        }
        let hfd = OwnedFd::from_raw_fd(hfd);
        let ssh = c(".ssh")?;
        let dflags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut sfd = libc::openat(std::os::fd::AsRawFd::as_raw_fd(&hfd), ssh.as_ptr(), dflags);
        if sfd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            if !create {
                return Ok(None);
            }
            let h = std::os::fd::AsRawFd::as_raw_fd(&hfd);
            if libc::mkdirat(h, ssh.as_ptr(), 0o700) != 0 {
                return Err(last_err("创建 ~/.ssh"));
            }
            if libc::fchownat(h, ssh.as_ptr(), u.uid, u.gid, libc::AT_SYMLINK_NOFOLLOW) != 0 {
                return Err(last_err("设置 ~/.ssh 属主"));
            }
            sfd = libc::openat(h, ssh.as_ptr(), dflags);
        }
        if sfd < 0 {
            return Err(OpError::invalid(format!(
                "{}/.ssh 无法安全打开（不能是符号链接）",
                u.home
            )));
        }
        let sfd = OwnedFd::from_raw_fd(sfd);
        let sraw = std::os::fd::AsRawFd::as_raw_fd(&sfd);
        let st = fstat(sraw)?;
        if (st.st_uid != u.uid && st.st_uid != 0) || st.st_mode & 0o022 != 0 {
            return Err(OpError::invalid(format!(
                "{}/.ssh 的属主或权限不安全，拒绝操作",
                u.home
            )));
        }
        let name = c("authorized_keys")?;
        let flags = if create {
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let ffd = libc::openat(sraw, name.as_ptr(), flags, 0o600 as libc::c_uint);
        if ffd < 0 {
            let e = std::io::Error::last_os_error();
            if !create && e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(OpError::invalid(format!(
                "{}/.ssh/authorized_keys 无法安全打开：{e}",
                u.home
            )));
        }
        let f = std::fs::File::from_raw_fd(ffd);
        let st = fstat(ffd)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1 {
            return Err(OpError::invalid(
                "authorized_keys 不是普通文件或存在硬链接，拒绝操作",
            ));
        }
        if st.st_uid != u.uid {
            // just created by us (root): hand it to the user; anything else is suspicious
            if st.st_uid == 0 && st.st_size == 0 && create {
                if libc::fchown(ffd, u.uid, u.gid) != 0 {
                    return Err(last_err("设置 authorized_keys 属主"));
                }
            } else {
                return Err(OpError::invalid(
                    "authorized_keys 的属主不是该用户，拒绝操作",
                ));
            }
        }
        Ok(Some(f))
    }
}

fn read_keys_text(u: &LoginUser) -> OpResult<String> {
    let Some(mut f) = open_keys(u, false)? else {
        return Ok(String::new());
    };
    let mut s = String::new();
    Read::by_ref(&mut f)
        .take(1024 * 1024)
        .read_to_string(&mut s)
        .map_err(|e| OpError::failed(format!("读取公钥：{e}")))?;
    Ok(s)
}

fn all_keys() -> Vec<model::KeyEntry> {
    users()
        .iter()
        .flat_map(|u| {
            read_keys_text(u)
                .map(|t| model::parse_authorized_keys(&u.name, &t))
                .unwrap_or_default()
        })
        .collect()
}

fn key_users(keys: &[model::KeyEntry]) -> Vec<String> {
    let mut v: Vec<String> = keys
        .iter()
        .filter(|k| !k.restricted)
        .map(|k| k.user.clone())
        .collect();
    v.dedup();
    v
}

// ---------------------------------------------------------------- handlers

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetArgs {
    options: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyAddArgs {
    user: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRemoveArgs {
    user: String,
    fingerprint: String,
}

/// Effective values shown in the panel.
const SHOWN: &[&str] = &[
    "port",
    "listenaddress",
    "permitrootlogin",
    "passwordauthentication",
    "pubkeyauthentication",
    "kbdinteractiveauthentication",
    "permitemptypasswords",
    "maxauthtries",
    "logingracetime",
    "clientaliveinterval",
    "clientalivecountmax",
    "maxsessions",
    "x11forwarding",
    "allowtcpforwarding",
    "allowagentforwarding",
    "usedns",
    "allowusers",
    "allowgroups",
    "denyusers",
];

pub async fn handle(ctx: &Ctx, op: &str, call: Call<'_>) -> OpResult<Value> {
    let s = &ctx.cfg.ssh;
    if !s.enabled {
        return Err(not_enabled("ssh"));
    }
    match op {
        "config" => {
            let eff = effective(ctx).await;
            let main = std::fs::read_to_string(&s.sshd_config).unwrap_or_default();
            let managed = std::fs::read_to_string(&s.dropin)
                .map(|t| model::parse_dropin(&t))
                .unwrap_or_default();
            let shown: BTreeMap<&str, Vec<String>> = eff
                .as_ref()
                .map(|e| {
                    SHOWN
                        .iter()
                        .filter_map(|k| e.get(*k).map(|v| (*k, v.clone())))
                        .collect()
                })
                .unwrap_or_default();
            Ok(json!({
                "available": eff.is_some(),
                "effective": shown,
                "ports": eff.as_ref().map(model::ports).unwrap_or_else(|| model::ports_from_config(&main)),
                "managed": managed,
                "dropin": s.dropin,
                "includes_dropins": model::includes_dropins(&main),
                "unit": service_unit().await,
                "socket_activated": exec::unit_active("ssh.socket").await,
                "options": model::OPTIONS.iter().map(|(k, v)| json!({ "key": k, "values": v })).collect::<Vec<_>>(),
            }))
        }
        "keys" => Ok(json!({
            "users": users().iter().map(|u| u.name.clone()).collect::<Vec<_>>(),
            "keys": all_keys(),
        })),
        "set" => {
            let a: SetArgs = call.args()?;
            allow(ctx, SshOp::Options)?;
            let opts = model::check_options(&a.options)?;
            let _g = ctx.lock(Domain::Ssh).await?;
            set_options(ctx, opts, &call).await
        }
        "key_add" => {
            let a: KeyAddArgs = call.args()?;
            allow(ctx, SshOp::KeyAdd)?;
            validate::user_name(&a.user)?;
            let (line, fp) = model::check_new_key(&a.key)?;
            let u = users()
                .into_iter()
                .find(|u| u.name == a.user)
                .ok_or_else(|| OpError::invalid(format!("{} 不是可登录用户", a.user)))?;
            let _g = ctx.lock(Domain::Ssh).await?;
            let existing = model::parse_authorized_keys(&u.name, &read_keys_text(&u)?);
            if existing.iter().any(|k| k.fingerprint == fp) {
                call.log.line(format!("{} 已有这把公钥（{fp}）", u.name));
                return Ok(json!({ "changed": false, "fingerprint": fp }));
            }
            call.log.line(format!("为 {} 添加公钥 {fp}", u.name));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true, "fingerprint": fp }));
            }
            let mut f =
                open_keys(&u, true)?.ok_or_else(|| OpError::failed("无法打开 authorized_keys"))?;
            let len = f
                .seek(std::io::SeekFrom::End(0))
                .map_err(|e| OpError::failed(e.to_string()))?;
            let mut buf = Vec::new();
            if len > 0 {
                // make sure the new key starts on its own line
                let mut last = [0u8; 1];
                f.seek(std::io::SeekFrom::End(-1))
                    .map_err(|e| OpError::failed(e.to_string()))?;
                f.read_exact(&mut last)
                    .map_err(|e| OpError::failed(e.to_string()))?;
                if last[0] != b'\n' {
                    buf.push(b'\n');
                }
            }
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
            f.write_all(&buf)
                .and_then(|_| f.sync_all())
                .map_err(|e| OpError::failed(format!("写入公钥：{e}")))?;
            Ok(json!({ "changed": true, "fingerprint": fp }))
        }
        "key_remove" => {
            let a: KeyRemoveArgs = call.args()?;
            allow(ctx, SshOp::KeyRemove)?;
            validate::user_name(&a.user)?;
            if !a.fingerprint.starts_with("SHA256:") || a.fingerprint.len() > 80 {
                return Err(OpError::invalid("无效的公钥指纹"));
            }
            let u = users()
                .into_iter()
                .find(|u| u.name == a.user)
                .ok_or_else(|| OpError::invalid(format!("{} 不是可登录用户", a.user)))?;
            let _g = ctx.lock(Domain::Ssh).await?;
            let text = read_keys_text(&u)?;
            let (rest, n) = model::remove_key(&text, &a.fingerprint);
            if n == 0 {
                return Err(OpError::invalid("找不到这把公钥"));
            }
            // lockout guard: keys left after the removal must still allow a login
            if let Some(eff) = effective(ctx).await {
                let mut left: Vec<model::KeyEntry> = all_keys()
                    .into_iter()
                    .filter(|k| !(k.user == u.name && k.fingerprint == a.fingerprint))
                    .collect();
                left.retain(|k| !k.restricted);
                model::guard_auth(&eff, &key_users(&left)).map_err(|_| {
                    OpError::invalid(
                        "拒绝：密码登录已关闭，删除这把公钥后将没有任何用户能通过公钥登录",
                    )
                })?;
            }
            call.log.line(format!(
                "删除 {} 的公钥 {}（{n} 行）",
                u.name, a.fingerprint
            ));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let mut f =
                open_keys(&u, true)?.ok_or_else(|| OpError::failed("无法打开 authorized_keys"))?;
            f.set_len(0)
                .and_then(|_| f.seek(std::io::SeekFrom::Start(0)).map(|_| ()))
                .and_then(|_| f.write_all(rest.as_bytes()))
                .and_then(|_| f.sync_all())
                .map_err(|e| OpError::failed(format!("写入公钥：{e}")))?;
            Ok(json!({ "changed": true, "removed": n }))
        }
        _ => Err(OpError::invalid(format!("unknown call ssh.{op}"))),
    }
}

async fn sshd_check(ctx: &Ctx, log: &Log) -> OpResult<()> {
    let out = exec::run_logged(
        log,
        &exec::argv(&[&ctx.cfg.ssh.sshd_binary, "-t"]),
        Duration::from_secs(15),
    )
    .await?;
    if out.ok() {
        Ok(())
    } else {
        Err(OpError::failed(format!(
            "sshd -t 未通过：{}",
            out.message()
        )))
    }
}

async fn set_options(
    ctx: &Ctx,
    opts: BTreeMap<&'static str, String>,
    call: &Call<'_>,
) -> OpResult<Value> {
    let s = &ctx.cfg.ssh;
    let main = std::fs::read_to_string(&s.sshd_config)
        .map_err(|e| OpError::failed(format!("读取 {}：{e}", s.sshd_config.display())))?;
    if !model::includes_dropins(&main) {
        return Err(OpError::invalid(format!(
            "{} 没有在 Match 之前 Include sshd_config.d/*.conf，面板写入的设置不会生效；请先手动加上",
            s.sshd_config.display()
        )));
    }
    let new_ports: Option<Vec<u16>> = opts.get("Port").map(|p| vec![p.parse().unwrap_or(22)]);
    if new_ports.is_some() && exec::unit_active("ssh.socket").await {
        return Err(OpError::invalid(
            "sshd 由 ssh.socket 按需启动，端口在 socket 单元中配置；面板不修改这种情况下的端口",
        ));
    }
    if let Some(p) = &new_ports
        && ctx.cfg.firewall.enabled
    {
        let st = super::firewall::status(ctx).await?;
        if st.active && st.writable && !crate::ops::firewall::ssh_admitted(&st.rules, p) {
            return Err(OpError::invalid(format!(
                "拒绝：防火墙尚未放行新端口 {p:?}，请先在防火墙中添加放行规则"
            )));
        }
    }
    let mut merged: BTreeMap<&'static str, String> = std::fs::read_to_string(&s.dropin)
        .map(|t| model::parse_dropin(&t))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, v)| {
            model::OPTIONS
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(&k))
                .map(|(n, _)| (*n, v))
        })
        .collect();
    let summary = opts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    merged.extend(opts.clone());
    let content = model::dropin_content(&merged);
    call.log
        .line(format!("将写入 {}：{summary}", s.dropin.display()));
    if call.dry_run {
        let old = std::fs::read_to_string(&s.dropin).unwrap_or_default();
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({
            "dry_run": true,
            "diff": crate::ops::nginx::unified_diff(&s.dropin.to_string_lossy(), &old, &content),
        }));
    }
    let unit = service_unit().await;
    let reload = exec::argv(&["systemctl", "reload", unit]);
    let backup = fsutil::backup(&ctx.cfg.state_dir, "ssh", &s.dropin)?;
    let plan = RevertPlan {
        restore: vec![backup],
        commands: vec![reload.clone()],
    };
    let log = call.log.clone();
    let dropin = s.dropin.clone();
    let view = ctx
        .pending
        .guarded(
            "ssh",
            format!("sshd：{summary}"),
            call.actor.clone(),
            plan,
            vec![],
            || async move {
                if let Some(dir) = dropin.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| OpError::failed(e.to_string()))?;
                }
                fsutil::atomic_write(&dropin, content.as_bytes())?;
                sshd_check(ctx, &log).await?;
                let eff = effective(ctx)
                    .await
                    .ok_or_else(|| OpError::failed("sshd -T 不可用，无法确认生效配置"))?;
                for (k, v) in &opts {
                    let got = model::first(&eff, &k.to_ascii_lowercase()).unwrap_or("");
                    // sshd -T prints without-password for prohibit-password on some versions
                    let same = got.eq_ignore_ascii_case(v)
                        || (*k == "PermitRootLogin"
                            && v == "prohibit-password"
                            && got == "without-password");
                    if !same && *k != "Port" {
                        return Err(OpError::invalid(format!(
                            "{k} 被主配置中更早的设置覆盖（生效值 {got}），请先在 {} 中删除该项",
                            ctx.cfg.ssh.sshd_config.display()
                        )));
                    }
                }
                let keys = all_keys();
                model::guard_auth(&eff, &key_users(&keys))?;
                let out = exec::run_logged(&log, &reload, Duration::from_secs(30)).await?;
                if !out.ok() {
                    return Err(OpError::failed(format!(
                        "重新加载 sshd 失败：{}",
                        out.message()
                    )));
                }
                Ok(())
            },
        )
        .await?;
    call.log.line(format!(
        "已生效。请用新会话测试登录，并在 {} 秒内确认，否则自动回滚",
        ctx.cfg.confirm_secs
    ));
    Ok(json!({ "pending": view }))
}
