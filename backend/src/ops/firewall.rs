//! Firewall model shared by the helper and the daemon: parsers for `ufw`, `firewall-cmd` and
//! `nft` output, argv builders for the closed set of rule changes, and the SSH lockout guard.
//!
//! Rules are deleted by the exact `spec` the helper listed, never by number or free text, so a
//! delete can only remove something that is there.

use serde::{Deserialize, Serialize};

use super::proto::{OpError, OpResult};
use super::validate::{self, PortSpec, Proto};

pub const NFT_TABLE: &str = "tsmonitor";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Opaque identifier used for deletion (ufw: rule args; firewalld: `port:`/`service:`/`rich:`;
    /// nftables: `handle:N`).
    pub spec: String,
    /// allow | deny | reject | limit | drop
    pub action: String,
    pub port: Option<String>,
    pub proto: Option<String>,
    pub from: Option<String>,
    /// Whether the panel may delete it.
    pub deletable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Status {
    pub backend: String,
    pub active: bool,
    pub default_incoming: Option<String>,
    pub zone: Option<String>,
    pub rules: Vec<Rule>,
    /// Raw listing for reference (truncated).
    pub raw: String,
    pub ssh_ports: Vec<u16>,
    pub notes: Vec<String>,
    /// The backend supports writes from the panel.
    pub writable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    /// ufw rate limiting.
    Limit,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
            Action::Limit => "limit",
        }
    }
    fn blocks(self) -> bool {
        matches!(self, Action::Deny | Action::Reject)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRule {
    pub action: Action,
    pub port: String,
    #[serde(default = "any_proto")]
    pub proto: Proto,
    /// Source address or CIDR; any source when omitted.
    #[serde(default)]
    pub from: Option<String>,
}

fn any_proto() -> Proto {
    Proto::Any
}

/// A rule after validation, ready for argv building.
#[derive(Debug, Clone)]
pub struct Checked {
    pub action: Action,
    pub port: PortSpec,
    pub proto: Proto,
    pub from: Option<String>,
}

impl NewRule {
    pub fn check(&self) -> OpResult<Checked> {
        let port = PortSpec::parse(&self.port)?;
        if port.lo != port.hi && self.proto == Proto::Any {
            return Err(OpError::invalid("端口范围必须指定 tcp 或 udp"));
        }
        let from = self.from.as_deref().filter(|s| !s.trim().is_empty());
        Ok(Checked {
            action: self.action,
            port,
            proto: self.proto,
            from: from.map(validate::cidr).transpose()?,
        })
    }
}

impl Checked {
    pub fn summary(&self) -> String {
        format!(
            "{} {}{} 来自 {}",
            self.action.as_str(),
            self.port.display('-'),
            if self.proto == Proto::Any {
                String::new()
            } else {
                format!("/{}", self.proto.as_str())
            },
            self.from.as_deref().unwrap_or("任意地址")
        )
    }
}

/// Refuses rules that would block SSH for everyone.
pub fn guard_add(r: &Checked, ssh_ports: &[u16]) -> OpResult<()> {
    if r.action.blocks()
        && r.from.is_none()
        && r.proto != Proto::Udp
        && ssh_ports.iter().any(|p| r.port.contains(*p))
    {
        return Err(OpError::invalid(format!(
            "拒绝：这条规则会对所有来源封锁 SSH 端口 {ssh_ports:?}，可能导致无法登录服务器"
        )));
    }
    Ok(())
}

fn rule_covers(r: &Rule, port: u16) -> bool {
    if r.proto.as_deref() == Some("udp") {
        return false;
    }
    match &r.port {
        Some(p) => p
            .split(',')
            .filter_map(|x| PortSpec::parse(&x.replace('-', ":")).ok())
            .any(|s| s.contains(port)),
        None => false,
    }
}

fn opens(r: &Rule) -> bool {
    matches!(r.action.as_str(), "allow" | "limit" | "accept") && r.from.is_none()
}

/// Refuses deleting the last rule that admits SSH from anywhere.
pub fn guard_delete(
    target: &Rule,
    rules: &[Rule],
    ssh_ports: &[u16],
    active: bool,
) -> OpResult<()> {
    if !active || !opens(target) {
        return Ok(());
    }
    for &p in ssh_ports {
        if rule_covers(target, p)
            && !rules
                .iter()
                .any(|r| r.spec != target.spec && opens(r) && rule_covers(r, p))
        {
            return Err(OpError::invalid(format!(
                "拒绝：这是放行 SSH 端口 {p} 的最后一条规则，删除后可能无法登录服务器"
            )));
        }
    }
    Ok(())
}

/// True when some rule admits SSH from anywhere (required before enabling ufw).
pub fn ssh_admitted(rules: &[Rule], ssh_ports: &[u16]) -> bool {
    ssh_ports
        .iter()
        .all(|p| rules.iter().any(|r| opens(r) && rule_covers(r, *p)))
}

// ---------------------------------------------------------------- ufw

/// `ufw status verbose` header: (active, default incoming policy).
pub fn parse_ufw_status(text: &str) -> (bool, Option<String>) {
    let mut active = false;
    let mut default = None;
    for l in text.lines() {
        if let Some(s) = l.strip_prefix("Status:") {
            active = s.trim() == "active";
        } else if let Some(d) = l.strip_prefix("Default:") {
            default = d
                .split(',')
                .find(|x| x.contains("(incoming)"))
                .map(|x| x.replace("(incoming)", "").trim().to_string());
        }
    }
    (active, default)
}

/// Known ufw application profiles and the TCP port they open.
fn ufw_app_port(name: &str) -> Option<&'static str> {
    match name {
        "OpenSSH" => Some("22"),
        "Nginx HTTP" | "Apache" | "WWW" => Some("80"),
        "Nginx HTTPS" | "Apache Secure" | "WWW Secure" => Some("443"),
        "Nginx Full" | "Apache Full" | "WWW Full" => Some("80,443"),
        _ => None,
    }
}

/// One rule from `ufw show added` (`ufw allow from 10.0.0.0/8 to any port 22 proto tcp`).
pub fn parse_ufw_rule(spec: &str) -> Rule {
    let toks: Vec<&str> = spec.split_whitespace().collect();
    let action = toks.first().copied().unwrap_or("").to_string();
    let mut port = None;
    let mut proto = None;
    let mut from = None;
    let mut i = 1;
    let mut bare: Vec<&str> = Vec::new();
    while i < toks.len() {
        match toks[i] {
            "from" if i + 1 < toks.len() => {
                if toks[i + 1] != "any" {
                    from = Some(toks[i + 1].to_string());
                }
                i += 2;
            }
            "to" if i + 1 < toks.len() => i += 2,
            "port" if i + 1 < toks.len() => {
                port = Some(toks[i + 1].to_string());
                i += 2;
            }
            "proto" if i + 1 < toks.len() => {
                proto = Some(toks[i + 1].to_string());
                i += 2;
            }
            "in" | "out" | "log" | "log-all" => i += 1,
            "on" | "comment" | "app" if i + 1 < toks.len() => i += 2,
            t => {
                bare.push(t);
                i += 1;
            }
        }
    }
    if port.is_none() && !bare.is_empty() {
        let joined = bare.join(" ");
        if let Some((p, pr)) = joined.split_once('/') {
            port = Some(p.to_string());
            proto = Some(pr.to_string());
        } else if joined
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == ':')
        {
            port = Some(joined);
        } else {
            let app = joined.trim_matches(['\'', '"']);
            port = ufw_app_port(app).map(str::to_string);
            if port.is_some() {
                proto = Some("tcp".into());
            }
        }
    }
    Rule {
        spec: spec.to_string(),
        action,
        port: port.map(|p| p.replace(':', "-")),
        proto,
        from,
        deletable: true,
    }
}

/// `ufw show added` lines after the header.
pub fn parse_ufw_added(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("ufw "))
        .map(|s| parse_ufw_rule(s.trim()))
        .collect()
}

pub fn ufw_add_argv(r: &Checked) -> Vec<String> {
    let mut v = vec![
        "ufw".to_string(),
        "--force".into(),
        r.action.as_str().into(),
    ];
    let port = r.port.display(':');
    match (&r.from, r.proto) {
        (None, Proto::Any) => v.push(port),
        (None, p) => v.push(format!("{port}/{}", p.as_str())),
        (Some(src), p) => {
            v.extend([
                "from".into(),
                src.clone(),
                "to".into(),
                "any".into(),
                "port".into(),
                port,
            ]);
            if p != Proto::Any {
                v.extend(["proto".into(), p.as_str().into()]);
            }
        }
    }
    v
}

/// Splits on whitespace, keeping `'quoted words'` (ufw app profiles) as one argument.
fn ufw_tokens(spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in spec.chars() {
        match c {
            '\'' | '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn ufw_delete_argv(spec: &str) -> Vec<String> {
    let mut v = vec!["ufw".to_string(), "--force".into(), "delete".into()];
    v.extend(ufw_tokens(spec));
    v
}

// ---------------------------------------------------------------- firewalld

/// `firewall-cmd --zone=Z --list-all`.
pub fn parse_firewalld(text: &str) -> (Option<String>, Vec<Rule>) {
    let mut zone = None;
    let mut rules = Vec::new();
    let mut in_rich = false;
    for (i, l) in text.lines().enumerate() {
        if i == 0 {
            zone = l.split_whitespace().next().map(str::to_string);
            continue;
        }
        let t = l.trim();
        if in_rich && l.starts_with(['\t', ' ']) && t.starts_with("rule ") {
            rules.push(parse_rich(t));
            continue;
        }
        in_rich = false;
        if let Some(v) = t.strip_prefix("services:") {
            for s in v.split_whitespace() {
                let port = match s {
                    "ssh" => Some("22"),
                    "http" => Some("80"),
                    "https" => Some("443"),
                    _ => None,
                };
                rules.push(Rule {
                    spec: format!("service:{s}"),
                    action: "allow".into(),
                    port: port.map(str::to_string),
                    proto: port.map(|_| "tcp".into()),
                    from: None,
                    deletable: true,
                });
            }
        } else if let Some(v) = t.strip_prefix("ports:") {
            for p in v.split_whitespace() {
                let (port, proto) = p.split_once('/').unwrap_or((p, "tcp"));
                rules.push(Rule {
                    spec: format!("port:{p}"),
                    action: "allow".into(),
                    port: Some(port.to_string()),
                    proto: Some(proto.to_string()),
                    from: None,
                    deletable: true,
                });
            }
        } else if t.starts_with("rich rules:") {
            in_rich = true;
            if let Some(rest) = t.strip_prefix("rich rules:").map(str::trim)
                && rest.starts_with("rule ")
            {
                rules.push(parse_rich(rest));
            }
        }
    }
    (zone, rules)
}

fn quoted(t: &str, key: &str) -> Option<String> {
    let i = t.find(&format!("{key}=\""))? + key.len() + 2;
    let rest = &t[i..];
    Some(rest[..rest.find('"')?].to_string())
}

fn parse_rich(t: &str) -> Rule {
    let action = ["accept", "reject", "drop"]
        .iter()
        .find(|a| t.split_whitespace().any(|w| w == **a))
        .map(|a| if *a == "accept" { "allow" } else { a })
        .unwrap_or("rich")
        .to_string();
    Rule {
        spec: format!("rich:{t}"),
        action,
        port: quoted(t, "port").map(|p| p.replace(':', "-")),
        proto: quoted(t, "protocol"),
        from: t
            .find("source address=")
            .and_then(|i| quoted(&t[i..], "address")),
        deletable: true,
    }
}

fn protos(p: Proto) -> Vec<&'static str> {
    match p {
        Proto::Any => vec!["tcp", "udp"],
        Proto::Tcp => vec!["tcp"],
        Proto::Udp => vec!["udp"],
    }
}

/// Runtime-only changes; confirm makes them permanent, revert reloads the permanent config.
pub fn firewalld_add_argv(zone: &str, r: &Checked) -> OpResult<Vec<Vec<String>>> {
    let port = r.port.display('-');
    let z = format!("--zone={zone}");
    let mut out = Vec::new();
    for p in protos(r.proto) {
        let argv = match (r.action, &r.from) {
            (Action::Allow, None) => vec![
                "firewall-cmd".into(),
                z.clone(),
                format!("--add-port={port}/{p}"),
            ],
            (Action::Limit, _) => {
                return Err(OpError::invalid("firewalld 不支持 limit，请用 allow"));
            }
            (a, from) => {
                let fam = from
                    .as_deref()
                    .map(|f| if f.contains(':') { "ipv6" } else { "ipv4" });
                let verdict = match a {
                    Action::Allow => "accept",
                    Action::Deny => "drop",
                    _ => "reject",
                };
                let mut rule = String::from("rule");
                if let Some(f) = fam {
                    rule.push_str(&format!(" family=\"{f}\""));
                }
                if let Some(src) = from {
                    rule.push_str(&format!(" source address=\"{src}\""));
                }
                rule.push_str(&format!(" port port=\"{port}\" protocol=\"{p}\" {verdict}"));
                vec![
                    "firewall-cmd".into(),
                    z.clone(),
                    format!("--add-rich-rule={rule}"),
                ]
            }
        };
        out.push(argv);
    }
    Ok(out)
}

pub fn firewalld_delete_argv(zone: &str, spec: &str) -> OpResult<Vec<String>> {
    let z = format!("--zone={zone}");
    let arg = if let Some(s) = spec.strip_prefix("service:") {
        format!("--remove-service={s}")
    } else if let Some(p) = spec.strip_prefix("port:") {
        format!("--remove-port={p}")
    } else if let Some(r) = spec.strip_prefix("rich:") {
        format!("--remove-rich-rule={r}")
    } else {
        return Err(OpError::invalid("无效的规则标识"));
    };
    Ok(vec!["firewall-cmd".into(), z, arg])
}

// ---------------------------------------------------------------- nftables

/// `nft -a list table inet tsmonitor`: only rules in our own table are listed and deletable.
pub fn parse_nft_table(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            let (body, handle) = t.rsplit_once("# handle ")?;
            let body = body.trim();
            if body.starts_with("type ") || body.ends_with('{') || body.is_empty() {
                return None;
            }
            let w: Vec<&str> = body.split_whitespace().collect();
            let after = |k: &str| w.iter().position(|x| *x == k).and_then(|i| w.get(i + 1));
            let proto = w
                .iter()
                .position(|x| *x == "dport")
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| w.get(i))
                .map(|s| s.to_string());
            Some(Rule {
                spec: format!("handle:{}", handle.trim()),
                action: w.last().map_or("drop", |v| v).to_string(),
                port: after("dport").map(|s| s.replace(':', "-")),
                proto,
                from: after("saddr").map(|s| s.to_string()),
                deletable: true,
            })
        })
        .collect()
}

/// Block-only rules in `table inet tsmonitor` (a separate table cannot open what another drops).
pub fn nft_add_argv(r: &Checked) -> OpResult<Vec<Vec<String>>> {
    if !r.action.blocks() {
        return Err(OpError::invalid(
            "nftables 后端只支持在 tsmonitor 表中添加拒绝规则；放行规则请在主规则集中手动维护",
        ));
    }
    let verdict = if r.action == Action::Reject {
        "reject"
    } else {
        "drop"
    };
    let mut out = Vec::new();
    for p in protos(r.proto) {
        let mut v: Vec<String> = ["nft", "add", "rule", "inet", NFT_TABLE, "input"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(src) = &r.from {
            v.extend([
                if src.contains(':') { "ip6" } else { "ip" }.into(),
                "saddr".into(),
                src.clone(),
            ]);
        }
        v.extend([
            p.to_string(),
            "dport".into(),
            r.port.display('-'),
            verdict.into(),
        ]);
        out.push(v);
    }
    Ok(out)
}

pub fn nft_ensure_table_argv() -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        s(&["nft", "add", "table", "inet", NFT_TABLE]),
        s(&[
            "nft", "add", "chain", "inet", NFT_TABLE, "input", "{", "type", "filter", "hook",
            "input", "priority", "-10", ";", "policy", "accept", ";", "}",
        ]),
    ]
}

pub fn nft_delete_argv(spec: &str) -> OpResult<Vec<String>> {
    let h: u64 = spec
        .strip_prefix("handle:")
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| OpError::invalid("无效的规则标识"))?;
    Ok([
        "nft", "delete", "rule", "inet", NFT_TABLE, "input", "handle",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([h.to_string()])
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UFW_STATUS: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n";
    const UFW_ADDED: &str = "Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw allow from 10.0.0.0/8 to any port 8080 proto tcp\nufw limit 2222/tcp\nufw allow 'Nginx Full'\nufw deny from 203.0.113.7\nufw allow proto tcp from any to any port 6000:6010\n";

    #[test]
    fn ufw_parsing() {
        assert_eq!(parse_ufw_status(UFW_STATUS), (true, Some("deny".into())));
        let r = parse_ufw_added(UFW_ADDED);
        assert_eq!(r.len(), 6);
        assert_eq!(
            (r[0].port.as_deref(), r[0].proto.as_deref()),
            (Some("22"), Some("tcp"))
        );
        assert_eq!(r[1].from.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(r[1].port.as_deref(), Some("8080"));
        assert_eq!(r[2].action, "limit");
        assert_eq!(r[3].port.as_deref(), Some("80,443"));
        assert_eq!((r[4].action.as_str(), r[4].port.as_deref()), ("deny", None));
        assert_eq!(r[5].port.as_deref(), Some("6000-6010"));
        assert_eq!(
            ufw_delete_argv(&r[1].spec)[..3],
            ["ufw", "--force", "delete"]
        );
        assert_eq!(ufw_delete_argv(&r[3].spec)[3..], ["allow", "Nginx Full"]);
    }

    #[test]
    fn ufw_argv_and_ssh_guards() {
        let rule = |a, p: &str, pr, f: Option<&str>| {
            NewRule {
                action: a,
                port: p.into(),
                proto: pr,
                from: f.map(str::to_string),
            }
            .check()
            .unwrap()
        };
        assert_eq!(
            ufw_add_argv(&rule(Action::Allow, "80", Proto::Any, None)),
            ["ufw", "--force", "allow", "80"]
        );
        assert_eq!(
            ufw_add_argv(&rule(
                Action::Deny,
                "8000-8100",
                Proto::Tcp,
                Some("10.0.0.0/8")
            )),
            [
                "ufw",
                "--force",
                "deny",
                "from",
                "10.0.0.0/8",
                "to",
                "any",
                "port",
                "8000:8100",
                "proto",
                "tcp"
            ]
        );
        let ssh = [22];
        assert!(guard_add(&rule(Action::Deny, "22", Proto::Tcp, None), &ssh).is_err());
        assert!(guard_add(&rule(Action::Deny, "1-1000", Proto::Tcp, None), &ssh).is_err());
        assert!(
            guard_add(
                &rule(Action::Deny, "22", Proto::Tcp, Some("203.0.113.7")),
                &ssh
            )
            .is_ok()
        );
        assert!(guard_add(&rule(Action::Allow, "22", Proto::Tcp, None), &ssh).is_ok());
        assert!(
            NewRule {
                action: Action::Allow,
                port: "1:2".into(),
                proto: Proto::Any,
                from: None
            }
            .check()
            .is_err()
        );
        assert!(
            NewRule {
                action: Action::Allow,
                port: "22".into(),
                proto: Proto::Tcp,
                from: Some("evil;".into())
            }
            .check()
            .is_err()
        );

        let rules = parse_ufw_added(UFW_ADDED);
        // the only rule admitting 22 from anywhere
        assert!(guard_delete(&rules[0], &rules, &ssh, true).is_err());
        assert!(guard_delete(&rules[0], &rules, &ssh, false).is_ok());
        assert!(guard_delete(&rules[1], &rules, &ssh, true).is_ok());
        // with OpenSSH also present, deleting 22/tcp is fine
        let mut more = rules.clone();
        more.push(parse_ufw_rule("allow OpenSSH"));
        assert!(guard_delete(&more[0], &more, &ssh, true).is_ok());
        assert!(ssh_admitted(&rules, &ssh));
        assert!(!ssh_admitted(&rules[1..], &ssh));
    }

    #[test]
    fn firewalld_parsing_and_argv() {
        let text = "public (active)\n  target: default\n  interfaces: eth0\n  services: dhcpv6-client ssh\n  ports: 8080/tcp 53/udp\n  forward: yes\n  rich rules: \n\trule family=\"ipv4\" source address=\"203.0.113.7\" port port=\"22\" protocol=\"tcp\" reject\n";
        let (zone, rules) = parse_firewalld(text);
        assert_eq!(zone.as_deref(), Some("public"));
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[1].spec, "service:ssh");
        assert_eq!(rules[1].port.as_deref(), Some("22"));
        assert_eq!(rules[3].proto.as_deref(), Some("udp"));
        assert_eq!(rules[4].action, "reject");
        assert_eq!(rules[4].from.as_deref(), Some("203.0.113.7"));
        assert!(guard_delete(&rules[1], &rules, &[22], true).is_err());

        let r = NewRule {
            action: Action::Deny,
            port: "3306".into(),
            proto: Proto::Tcp,
            from: Some("10.0.0.0/8".into()),
        }
        .check()
        .unwrap();
        let a = firewalld_add_argv("public", &r).unwrap();
        assert_eq!(
            a[0][2],
            "--add-rich-rule=rule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"3306\" protocol=\"tcp\" drop"
        );
        let r = NewRule {
            action: Action::Allow,
            port: "80".into(),
            proto: Proto::Any,
            from: None,
        }
        .check()
        .unwrap();
        let a = firewalld_add_argv("public", &r).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[1][2], "--add-port=80/udp");
        assert_eq!(
            firewalld_delete_argv("public", &rules[2].spec).unwrap()[2],
            "--remove-port=8080/tcp"
        );
        assert!(firewalld_delete_argv("public", "--panic-on").is_err());
    }

    #[test]
    fn nft_parsing_and_argv() {
        let text = "table inet tsmonitor { # handle 7\n\tchain input { # handle 1\n\t\ttype filter hook input priority -10; policy accept;\n\t\tip saddr 203.0.113.7 tcp dport 22 drop # handle 4\n\t\ttcp dport 3306 reject # handle 5\n\t}\n}\n";
        let r = parse_nft_table(text);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].spec, "handle:4");
        assert_eq!(r[0].from.as_deref(), Some("203.0.113.7"));
        assert_eq!(
            (
                r[1].port.as_deref(),
                r[1].proto.as_deref(),
                r[1].action.as_str()
            ),
            (Some("3306"), Some("tcp"), "reject")
        );
        let allow = NewRule {
            action: Action::Allow,
            port: "80".into(),
            proto: Proto::Tcp,
            from: None,
        }
        .check()
        .unwrap();
        assert!(nft_add_argv(&allow).is_err());
        assert_eq!(nft_delete_argv("handle:4").unwrap().last().unwrap(), "4");
        assert!(nft_delete_argv("handle:4; flush ruleset").is_err());
    }
}
