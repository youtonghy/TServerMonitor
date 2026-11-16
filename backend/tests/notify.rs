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
