//! SSH model shared by the helper and the daemon: effective sshd config (`sshd -T`), the closed
//! set of options the panel may change, `authorized_keys` parsing and fingerprints, login users
//! from `/etc/passwd`, active sessions from `who`, and the lockout guards.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NOPAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::proto::{OpError, OpResult};

/// `sshd -T` output: lowercase keys, every value kept (e.g. several `port` lines).
pub fn parse_effective(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
        m.entry(k.to_ascii_lowercase())
            .or_default()
            .push(v.trim().to_string());
    }
    m
}

pub fn first<'a>(eff: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    eff.get(key).and_then(|v| v.first()).map(String::as_str)
}

pub fn ports(eff: &BTreeMap<String, Vec<String>>) -> Vec<u16> {
    let mut p: Vec<u16> = eff
        .get("port")
        .into_iter()
        .flatten()
        .filter_map(|v| v.parse().ok())
        .collect();
    if p.is_empty() {
        p.push(22);
    }
    p.sort_unstable();
    p.dedup();
    p
}

/// Ports from a plain `sshd_config` (fallback when `sshd -T` is unavailable).
pub fn ports_from_config(text: &str) -> Vec<u16> {
    let mut p = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if t.to_ascii_lowercase().starts_with("match ") {
            break;
        }
        let mut w = t.split_whitespace();
        if w.next().is_some_and(|k| k.eq_ignore_ascii_case("port"))
            && let Some(v) = w.next().and_then(|v| v.parse().ok())
        {
            p.push(v);
        }
    }
    if p.is_empty() {
        p.push(22);
    }
    p
}

/// Options the panel may set, with their allowed values.
pub const OPTIONS: &[(&str, &[&str])] = &[
    ("PermitRootLogin", &["no", "prohibit-password", "yes"]),
    ("PasswordAuthentication", &["yes", "no"]),
    ("PubkeyAuthentication", &["yes", "no"]),
    ("KbdInteractiveAuthentication", &["yes", "no"]),
    ("PermitEmptyPasswords", &["no"]),
    ("X11Forwarding", &["yes", "no"]),
    ("AllowTcpForwarding", &["yes", "no", "local", "remote"]),
    ("AllowAgentForwarding", &["yes", "no"]),
    ("UseDNS", &["yes", "no"]),
    // numeric options are checked below
    ("MaxAuthTries", &[]),
    ("LoginGraceTime", &[]),
    ("ClientAliveInterval", &[]),
    ("ClientAliveCountMax", &[]),
    ("MaxSessions", &[]),
    ("Port", &[]),
];

fn numeric_range(key: &str) -> Option<(u32, u32)> {
    Some(match key {
        "MaxAuthTries" => (1, 10),
        "LoginGraceTime" => (10, 600),
        "ClientAliveInterval" => (0, 3600),
        "ClientAliveCountMax" => (0, 10),
        "MaxSessions" => (1, 100),
        "Port" => (1, 65535),
        _ => return None,
    })
}

/// Canonicalises a requested option set (case-insensitive keys) and validates every value.
pub fn check_options(input: &BTreeMap<String, String>) -> OpResult<BTreeMap<&'static str, String>> {
    if input.is_empty() {
        return Err(OpError::invalid("没有要修改的选项"));
    }
    let mut out = BTreeMap::new();
    for (k, v) in input {
        let (key, allowed) = OPTIONS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .ok_or_else(|| OpError::invalid(format!("不支持通过面板修改 {k}")))?;
        let v = v.trim();
        let ok = match numeric_range(key) {
            Some((lo, hi)) => v.parse::<u32>().is_ok_and(|n| (lo..=hi).contains(&n)),
            None => allowed.contains(&v),
        };
        if !ok {
            return Err(OpError::invalid(format!("{key} 的值 {v:?} 无效")));
        }
        out.insert(*key, v.to_string());
    }
    Ok(out)
}

pub fn dropin_content(opts: &BTreeMap<&'static str, String>) -> String {
    let mut s = String::from(
        "# Managed by TServerMonitor (tsmonitor helper). Changes here are overwritten from the dashboard.\n",
    );
    for (k, v) in opts {
        s.push_str(&format!("{k} {v}\n"));
    }
    s
}

/// Options currently set in our drop-in.
pub fn parse_dropin(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                return None;
            }
            let (k, v) = t.split_once(char::is_whitespace)?;
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// True when the main config includes `sshd_config.d/*.conf` (before any `Match`).
pub fn includes_dropins(main: &str) -> bool {
    for l in main.lines() {
        let t = l.trim().to_ascii_lowercase();
        if t.starts_with("match ") {
            return false;
        }
        if t.starts_with("include ") && t.contains("sshd_config.d") {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------- keys

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub user: String,
    pub kind: String,
    pub fingerprint: String,
    pub comment: String,
    /// The line has options such as `from=` or `command=` (shown, never edited).
    pub restricted: bool,
}

fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", B64_NOPAD.encode(Sha256::digest(blob)))
}

/// Parses `type base64 [comment]`, checking the embedded type name.
fn parse_key(kind: &str, b64: &str) -> Option<Vec<u8>> {
    let blob = B64.decode(b64).ok()?;
    let n = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    (blob.get(4..4 + n)? == kind.as_bytes()).then_some(blob)
}

/// Finds the key type token in a line that may start with options.
fn split_key_line(line: &str) -> Option<(bool, &str, &str, String)> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let i = toks.iter().position(|t| KEY_TYPES.contains(t))?;
    let b64 = toks.get(i + 1)?;
    Some((i > 0, toks[i], b64, toks[i + 2..].join(" ")))
}

pub fn parse_authorized_keys(user: &str, text: &str) -> Vec<KeyEntry> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let (restricted, kind, b64, comment) = split_key_line(l)?;
            let blob = parse_key(kind, b64)?;
            Some(KeyEntry {
                user: user.to_string(),
                kind: kind.to_string(),
                fingerprint: fingerprint(&blob),
                comment,
                restricted,
            })
        })
        .collect()
}

/// Validates a public key to add: a single line, a known type, no options. Returns the
/// canonical line and its fingerprint.
pub fn check_new_key(line: &str) -> OpResult<(String, String)> {
    let line = line.trim();
    if line.contains('\n') || line.len() > 16 * 1024 {
        return Err(OpError::invalid("只能添加一行公钥"));
    }
    let (restricted, kind, b64, comment) =
        split_key_line(line).ok_or_else(|| OpError::invalid("无法识别的公钥格式"))?;
    if restricted {
        return Err(OpError::invalid(
            "面板添加的公钥不能带 from= / command= 等选项",
        ));
    }
    let blob = parse_key(kind, b64).ok_or_else(|| OpError::invalid("公钥内容无效"))?;
    let comment: String = comment
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let canon = if comment.is_empty() {
        format!("{kind} {b64}")
    } else {
        format!("{kind} {b64} {comment}")
    };
    Ok((canon, fingerprint(&blob)))
}

/// Removes lines whose key has `fp`. Returns the new text and how many were removed.
pub fn remove_key(text: &str, fp: &str) -> (String, usize) {
    let mut removed = 0;
    let mut out = String::new();
    for l in text.lines() {
        let hit = split_key_line(l)
            .and_then(|(_, k, b, _)| parse_key(k, b))
            .is_some_and(|blob| fingerprint(&blob) == fp);
        if hit {
            removed += 1;
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    (out, removed)
}

// ---------------------------------------------------------------- users and sessions

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// Accounts that can log in: root and uid 1000..65533 with a real shell.
pub fn login_users(passwd: &str) -> Vec<LoginUser> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            let uid: u32 = f[2].parse().ok()?;
            let shell = f[6];
            let real_shell =
                !(shell.ends_with("nologin") || shell.ends_with("false") || shell.is_empty());
            ((uid == 0 || (1000..65534).contains(&uid)) && real_shell).then(|| LoginUser {
                name: f[0].to_string(),
                uid,
                gid: f[3].parse().unwrap_or(uid),
                home: f[5].to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub user: String,
    pub tty: String,
    pub since: String,
    pub from: Option<String>,
}

/// `who` output: `deploy   pts/0        2026-11-26 09:12 (203.0.113.7)`.
pub fn parse_who(text: &str) -> Vec<Session> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            if w.len() < 4 {
                return None;
            }
            let from = w
                .iter()
                .find(|x| x.starts_with('(') && x.ends_with(')'))
                .map(|x| x.trim_matches(['(', ')']).to_string());
            Some(Session {
                user: w[0].to_string(),
                tty: w[1].to_string(),
                since: format!("{} {}", w[2], w[3]),
                from,
            })
        })
        .collect()
}

/// Refuses an effective configuration that leaves no way to log in. `key_users` are login users
/// with at least one usable key.
pub fn guard_auth(eff: &BTreeMap<String, Vec<String>>, key_users: &[String]) -> OpResult<()> {
    let yes = |k: &str| first(eff, k).is_some_and(|v| v == "yes");
    let password = yes("passwordauthentication") || yes("kbdinteractiveauthentication");
    let pubkey = first(eff, "pubkeyauthentication").is_none_or(|v| v == "yes");
    if !password && !pubkey {
        return Err(OpError::invalid(
            "拒绝：密码与公钥登录都会被关闭，没有任何登录方式",
        ));
    }
    if !password {
        let root_ok = first(eff, "permitrootlogin").is_some_and(|v| v != "no");
        let usable = key_users.iter().any(|u| u != "root" || root_ok);
        if !usable {
            return Err(OpError::invalid(
                "拒绝：关闭密码登录前，至少要有一个可登录用户配置了 authorized_keys 公钥",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // a real ed25519 public key (no private part anywhere)
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl deploy@laptop";

    #[test]
    fn effective_config_and_options() {
        let eff = parse_effective(
            "port 22\nport 2222\npermitrootlogin without-password\npasswordauthentication yes\n",
        );
        assert_eq!(ports(&eff), [22, 2222]);
        assert_eq!(
            ports_from_config("Port 2200\nMatch User x\nPort 1\n"),
            [2200]
        );
        let mut req = BTreeMap::new();
        req.insert("passwordauthentication".into(), "no".into());
        req.insert("MaxAuthTries".into(), "3".into());
        let o = check_options(&req).unwrap();
        assert_eq!(
            o.get("PasswordAuthentication").map(String::as_str),
            Some("no")
        );
        assert!(dropin_content(&o).contains("MaxAuthTries 3\n"));
        req.insert("MaxAuthTries".into(), "99".into());
        assert!(check_options(&req).is_err());
        let mut bad = BTreeMap::new();
        bad.insert("AuthorizedKeysCommand".into(), "/bin/sh".into());
        assert!(check_options(&bad).is_err());
        let mut inj = BTreeMap::new();
        inj.insert(
            "PermitRootLogin".into(),
            "yes\nAuthorizedKeysFile /tmp/k".into(),
        );
        assert!(check_options(&inj).is_err());
        assert!(includes_dropins(
            "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
        ));
        assert!(!includes_dropins(
            "Port 22\nMatch all\nInclude /etc/ssh/sshd_config.d/*.conf\n"
        ));
    }

    #[test]
    fn keys() {
        let text = format!("# comment\n{KEY}\nfrom=\"10.0.0.0/8\" {KEY}\nssh-rsa notbase64 x\n");
        let k = parse_authorized_keys("deploy", &text);
        assert_eq!(k.len(), 2);
        assert!(k[0].fingerprint.starts_with("SHA256:"));
        assert!(!k[0].restricted && k[1].restricted);
        let (canon, fp) = check_new_key(KEY).unwrap();
        assert_eq!(fp, k[0].fingerprint);
        assert_eq!(canon, KEY);
        assert!(check_new_key(&format!("command=\"/bin/sh\" {KEY}")).is_err());
        assert!(check_new_key("ssh-ed25519 AAAA").is_err());
        assert!(check_new_key(&format!("{KEY}\n{KEY}")).is_err());
        // type name inside the blob must match
        assert!(
            check_new_key(
                "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
            )
            .is_err()
        );
        let (rest, n) = remove_key(&text, &fp);
        assert_eq!(n, 2);
        assert!(rest.contains("# comment") && rest.contains("notbase64"));
    }

    #[test]
    fn users_sessions_and_guard() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\nsvc:x:1001:1001::/srv:/bin/false\n";
        let u: Vec<_> = login_users(passwd).into_iter().map(|u| u.name).collect();
        assert_eq!(u, ["root", "deploy"]);
        let s = parse_who(
            "deploy   pts/0        2026-11-26 09:12 (203.0.113.7)\nroot     tty1         2026-11-25 20:00\n",
        );
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].from.as_deref(), Some("203.0.113.7"));
        assert!(s[1].from.is_none());

        let eff = |t: &str| parse_effective(t);
        let none = eff(
            "passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication no\n",
        );
        assert!(guard_auth(&none, &["deploy".into()]).is_err());
        let keys_only = eff(
            "passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\n",
        );
        assert!(guard_auth(&keys_only, &[]).is_err());
        assert!(guard_auth(&keys_only, &["root".into()]).is_err());
        assert!(guard_auth(&keys_only, &["deploy".into()]).is_ok());
        assert!(guard_auth(&eff("passwordauthentication yes\n"), &[]).is_ok());
    }
}
