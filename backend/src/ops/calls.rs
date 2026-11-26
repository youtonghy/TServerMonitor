//! The closed set of write calls the daemon forwards to the helper, with a human-readable
//! summary for the job list and audit log. The helper validates again; this list only keeps
//! anything else (reads, unknown names) out of the write path.

use serde_json::Value;

use super::proto::{OpError, OpResult};

/// (call, may an MCP agent invoke it)
pub const WRITE_CALLS: &[(&str, bool)] = &[
    ("docker.container", true),
    ("docker.project", true),
    ("docker.image_pull", true),
    ("docker.image_remove", true),
    ("docker.image_prune", true),
    ("docker.volume_remove", true),
    ("docker.volume_prune", true),
    ("nginx.test", true),
    ("nginx.reload", true),
    ("nginx.site", true),
    ("nginx.write", true),
    ("firewall.add", true),
    ("firewall.delete", true),
    ("firewall.toggle", true),
    ("ssh.set", true),
    ("ssh.key_add", true),
    ("ssh.key_remove", true),
    // agents may undo a pending change, but only a person in the dashboard can keep it
    ("pending.revert", true),
    ("pending.confirm", false),
];

pub fn check(call: &str, from_mcp: bool) -> OpResult<()> {
    match WRITE_CALLS.iter().find(|(c, _)| *c == call) {
        Some((_, mcp_ok)) if !from_mcp || *mcp_ok => Ok(()),
        Some(_) => Err(OpError::not_allowed(
            "确认变更只能由人在面板上操作（确认前请先新开 SSH 会话测试登录）",
        )),
        None => Err(OpError::invalid(format!("不支持的操作 {call}"))),
    }
}

fn s<'a>(args: &'a Value, k: &str) -> &'a str {
    args[k].as_str().unwrap_or("?")
}

fn action(a: &str) -> &str {
    match a {
        "start" => "启动",
        "stop" => "停止",
        "restart" => "重启",
        "kill" => "强制终止",
        "remove" => "删除",
        other => other,
    }
}

pub fn summary(call: &str, args: &Value) -> String {
    match call {
        "docker.container" => format!("{}容器 {}", action(s(args, "action")), s(args, "id")),
        "docker.project" => format!(
            "{} compose 项目 {}",
            action(s(args, "action")),
            s(args, "name")
        ),
        "docker.image_pull" => format!("拉取镜像 {}", s(args, "reference")),
        "docker.image_remove" => format!("删除镜像 {}", s(args, "id")),
        "docker.image_prune" => "清理悬空镜像".into(),
        "docker.volume_remove" => format!("删除卷 {}", s(args, "name")),
        "docker.volume_prune" => "清理未使用的卷".into(),
        "nginx.test" => "检查 nginx 配置".into(),
        "nginx.reload" => "重新加载 nginx".into(),
        "nginx.site" => format!(
            "{}站点 {}",
            if args["enabled"].as_bool() == Some(true) {
                "启用"
            } else {
                "停用"
            },
            s(args, "name")
        ),
        "nginx.write" => format!("修改 nginx 配置 {}", s(args, "path")),
        "firewall.add" => format!(
            "添加防火墙规则 {} {}/{}{}",
            s(args, "action"),
            s(args, "port"),
            args["proto"].as_str().unwrap_or("any"),
            args["from"]
                .as_str()
                .map(|f| format!(" 来自 {f}"))
                .unwrap_or_default()
        ),
        "firewall.delete" => format!("删除防火墙规则 {}", s(args, "spec")),
        "firewall.toggle" => format!(
            "{}防火墙",
            if args["enabled"].as_bool() == Some(true) {
                "启用"
            } else {
                "停用"
            }
        ),
        "ssh.set" => {
            let opts = args["options"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?")))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("修改 sshd 设置 {opts}")
        }
        "ssh.key_add" => format!("为 {} 添加 SSH 公钥", s(args, "user")),
        "ssh.key_remove" => format!(
            "删除 {} 的 SSH 公钥 {}",
            s(args, "user"),
            s(args, "fingerprint")
        ),
        "pending.confirm" => "确认待定变更".into(),
        "pending.revert" => "撤销待定变更".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allowlist_and_summaries() {
        assert!(check("docker.container", true).is_ok());
        assert!(check("pending.confirm", false).is_ok());
        assert!(check("pending.confirm", true).is_err());
        assert!(check("docker.images", false).is_err());
        assert!(check("hello", false).is_err());
        assert_eq!(
            summary(
                "docker.container",
                &json!({ "id": "web", "action": "restart" })
            ),
            "重启容器 web"
        );
        assert!(
            summary(
                "firewall.add",
                &json!({ "action": "deny", "port": "22", "from": "1.2.3.4" })
            )
            .contains("来自 1.2.3.4")
        );
    }
}
