//! Alert notifications against a fake Telegram API and a webhook receiver:
//! severity gating, per-fingerprint de-duplication, escalation and HMAC signatures.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tsmonitor::alerts::{self, AlertInput};
use tsmonitor::config::{Config, Severity, WebhookConfig};
use tsmonitor::{notify, state, store};

#[derive(Default)]
struct Seen {
    telegram: Vec<Value>,
    webhook: Vec<(Option<String>, String)>,
}

type Shared = Arc<Mutex<Seen>>;

async fn telegram(State(s): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    s.lock().unwrap().telegram.push(body);
    Json(json!({ "ok": true }))
}

async fn webhook(State(s): State<Shared>, headers: HeaderMap, body: String) -> &'static str {
    let sig = headers
        .get("x-tsm-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    s.lock().unwrap().webhook.push((sig, body));
    "ok"
}

#[tokio::test]
async fn telegram_and_webhook_delivery() {
    let seen: Shared = Arc::default();
    let app = Router::new()
        .route("/botTEST-TOKEN/sendMessage", post(telegram))
        .route("/hook", post(webhook))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // SAFETY: unique variable names for this test.
    unsafe {
        std::env::set_var("TSM_TEST_TG_TOKEN", "TEST-TOKEN");
        std::env::set_var("TSM_TEST_HOOK_SECRET", "hook-secret");
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.notify.telegram.enabled = true;
    cfg.notify.telegram.chat_id = "42".into();
    cfg.notify.telegram.token_env = "TSM_TEST_TG_TOKEN".into();
    cfg.notify.telegram.api_base = base.clone();
    cfg.notify.telegram.min_severity = Severity::Critical;
    cfg.notify.webhooks = vec![WebhookConfig {
        url: format!("{base}/hook"),
        secret_env: Some("TSM_TEST_HOOK_SECRET".into()),
        events: vec!["alert".into()],
    }];
    let st = state::AppState::new(Arc::new(cfg), store::open(dir.path()).await.unwrap());

    let input = |sev| AlertInput {
        severity: sev,
        source: "test",
        fingerprint: "fp-1",
        title: "磁盘 <满了>",
        summary: "used 99%",
        suggestion: None,
    };
    // warning: webhook only, not telegram
    let a = alerts::raise(&st, input(Severity::Warning)).await.unwrap();
    assert!(a.notified);
    assert!(seen.lock().unwrap().telegram.is_empty());
    // repeated within cooldown: no new notification at all
    alerts::raise(&st, input(Severity::Warning)).await.unwrap();
    assert_eq!(seen.lock().unwrap().webhook.len(), 1);
    // escalation to critical: notified again, now also on telegram
    let a = alerts::raise(&st, input(Severity::Critical)).await.unwrap();
    assert_eq!(a.count, 3);
    assert_eq!(a.severity, "critical");
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.telegram.len(), 1);
        assert_eq!(s.telegram[0]["chat_id"], "42");
        let text = s.telegram[0]["text"].as_str().unwrap();
        assert!(text.contains("&lt;满了&gt;"), "{text}");
        assert_eq!(s.webhook.len(), 2);
        for (sig, body) in &s.webhook {
            let expected = format!("sha256={}", notify::sign(b"hook-secret", body.as_bytes()));
            assert_eq!(sig.as_deref(), Some(expected.as_str()));
            let v: Value = serde_json::from_str(body).unwrap();
            assert_eq!(v["event"], "alert");
        }
    }
    // resolve then raise again: a fresh alert is pushed
    alerts::resolve(&st, "fp-1").await;
    alerts::raise(&st, input(Severity::Critical)).await.unwrap();
    assert_eq!(seen.lock().unwrap().telegram.len(), 2);
    let open = alerts::list(&st.db, true, 10).await.unwrap();
    assert_eq!(open.len(), 1);
}

/// Minimal SMTP server: accepts one message per connection and records the DATA payload.
async fn fake_smtp() -> (u16, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mails: Arc<Mutex<Vec<String>>> = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let m = mails.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let m = m.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                w.write_all(b"220 fake ESMTP\r\n").await.unwrap();
                let mut data: Option<String> = None;
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(buf) = data.as_mut() {
                        if line == "." {
                            m.lock().unwrap().push(data.take().unwrap());
                            w.write_all(b"250 queued\r\n").await.unwrap();
                        } else {
                            buf.push_str(&line);
                            buf.push('\n');
                        }
                        continue;
                    }
                    let cmd = line.to_ascii_uppercase();
                    let reply: &[u8] = if cmd.starts_with("EHLO") {
                        b"250-fake\r\n250 8BITMIME\r\n"
                    } else if cmd.starts_with("DATA") {
                        data = Some(String::new());
                        b"354 go\r\n"
                    } else if cmd.starts_with("QUIT") {
                        w.write_all(b"221 bye\r\n").await.unwrap();
                        return;
                    } else {
                        b"250 ok\r\n"
                    };
                    w.write_all(reply).await.unwrap();
                }
            });
        }
    });
    (port, mails)
}

/// Dashboard-configured email channel, silence and acknowledgement gating.
#[tokio::test]
async fn email_channel_with_silence_and_ack() {
    let (port, mails) = fake_smtp().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.thresholds.alert_cooldown_mins = 0;
    let st = state::AppState::new(Arc::new(cfg), store::open(dir.path()).await.unwrap());
    st.settings.set_file_key_allowed(true);
    let id = tsmonitor::channels::create(
        &st.settings,
        &st.db,
        tsmonitor::channels::ChannelInput {
            kind: Some(tsmonitor::channels::Kind::Email),
            name: Some("ops".into()),
            enabled: None,
            min_severity: Some(Severity::Warning),
            events: Some(vec!["alert".into()]),
            config: Some(json!({ "host": "127.0.0.1", "port": port, "security": "none", "from": "mon@example.com", "to": ["ops@example.com"] })),
            secret: None,
        },
    )
    .await
    .unwrap();

    st.notifier.test(&st, &id).await.unwrap();
    assert!(mails.lock().unwrap()[0].contains("TServerMonitor"));

    let input = |fp| AlertInput {
        severity: Severity::Critical,
        source: "test",
        fingerprint: fp,
        title: "CPU 过高",
        summary: "cpu 99%",
        suggestion: None,
    };
    let a = alerts::raise(&st, input("fp-mail")).await.unwrap();
    assert!(a.notified);
    assert_eq!(mails.lock().unwrap().len(), 2);
    assert!(mails.lock().unwrap()[1].contains("Subject:"));

    // silenced: repeats are recorded but not sent, and the silence survives a re-open
    alerts::act(&st, a.id, alerts::Action::Silence(60))
        .await
        .unwrap()
        .unwrap();
    alerts::raise(&st, input("fp-mail")).await.unwrap();
    alerts::resolve(&st, "fp-mail").await;
    let again = alerts::raise(&st, input("fp-mail")).await.unwrap();
    assert!(!again.notified);
    assert!(again.silenced_until.is_some());
    assert_eq!(mails.lock().unwrap().len(), 2);

    // acknowledged: cooldown repeats stay quiet
    let b = alerts::raise(&st, input("fp-ack")).await.unwrap();
    assert_eq!(mails.lock().unwrap().len(), 3);
    alerts::act(&st, b.id, alerts::Action::Ack)
        .await
        .unwrap()
        .unwrap();
    alerts::raise(&st, input("fp-ack")).await.unwrap();
    assert_eq!(mails.lock().unwrap().len(), 3);
}

/// The bot answers commands only from the configured chat and remembers the update offset.
#[tokio::test]
async fn telegram_bot_answers_configured_chat_only() {
    #[derive(Default)]
    struct Bot {
        sent: Vec<Value>,
        offsets: Vec<i64>,
    }
    type B = Arc<Mutex<Bot>>;
    async fn updates(State(b): State<B>, Json(body): Json<Value>) -> Json<Value> {
        let offset = body["offset"].as_i64().unwrap_or(0);
        b.lock().unwrap().offsets.push(offset);
        let all = json!([
            { "update_id": 10, "message": { "chat": { "id": 42 }, "from": { "id": 7 }, "text": "/alerts" } },
            { "update_id": 11, "message": { "chat": { "id": 99 }, "from": { "id": 7 }, "text": "/status" } },
            { "update_id": 12, "message": { "chat": { "id": 42 }, "from": { "id": 8 }, "text": "/ack 1" } },
        ]);
        let pending: Vec<Value> = all
            .as_array()
            .unwrap()
            .iter()
            .filter(|u| u["update_id"].as_i64().unwrap() >= offset)
            .cloned()
            .collect();
        Json(json!({ "ok": true, "result": pending }))
    }
    async fn send(State(b): State<B>, Json(body): Json<Value>) -> Json<Value> {
        b.lock().unwrap().sent.push(body);
        Json(json!({ "ok": true }))
    }
    let bot: B = Arc::default();
    let app = Router::new()
        .route("/botBOT/getUpdates", post(updates))
        .route("/botBOT/sendMessage", post(send))
        .with_state(bot.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    let st = state::AppState::new(Arc::new(cfg), store::open(dir.path()).await.unwrap());
    st.settings.set_file_key_allowed(true);
    tsmonitor::channels::create(
        &st.settings,
        &st.db,
        tsmonitor::channels::ChannelInput {
            kind: Some(tsmonitor::channels::Kind::Telegram),
            name: Some("bot".into()),
            enabled: None,
            min_severity: None,
            events: None,
            // user 8 is not allowed to issue commands
            config: Some(json!({ "chat_id": "42", "api_base": base, "bot_enabled": true, "allowed_user_ids": [7] })),
            secret: Some("BOT".into()),
        },
    )
    .await
    .unwrap();
    let ch = tsmonitor::channels::all(&st).await.pop().unwrap();
    let tsmonitor::channels::Target::Telegram {
        cfg: tg,
        token: Some(token),
    } = ch.target.clone()
    else {
        panic!("telegram channel with token");
    };
    let http = reqwest::Client::new();
    tsmonitor::telegram_bot::poll_once(&st, &http, &ch, &tg, &token)
        .await
        .unwrap();
    {
        let b = bot.lock().unwrap();
        assert_eq!(b.sent.len(), 1, "{:?}", b.sent);
        assert_eq!(b.sent[0]["chat_id"], "42");
        assert!(
            b.sent[0]["text"]
                .as_str()
                .unwrap()
                .contains("没有未处理的告警")
        );
    }
    tsmonitor::telegram_bot::poll_once(&st, &http, &ch, &tg, &token)
        .await
        .unwrap();
    let b = bot.lock().unwrap();
    assert_eq!(b.offsets, vec![0, 13]);
    assert_eq!(b.sent.len(), 1, "already handled updates are not replayed");
}
