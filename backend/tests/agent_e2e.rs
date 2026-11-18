//! End-to-end: Rust agent -> Node sidecar (Vercel AI SDK) -> fake model server speaking
//! `/responses` or `/messages` -> tool call executed in Rust -> structured diagnosis stored.
//! Needs Node 20+ and a built sidecar (`pnpm -C agent-sidecar build`); skips otherwise.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tsmonitor::config::{ApiFormat, AuthStyle, Config, ModelProfile};
use tsmonitor::model::ReportKind;
use tsmonitor::{agent, sandbox, settings, state, store};

type Log = Arc<Mutex<Vec<Value>>>;

fn diagnosis() -> Value {
    json!({
        "health_score": 82,
        "summary": "整体平稳，CPU 有短时尖峰。",
        "dimensions": { "cpu": 75, "memory": 90, "disk": 88, "logs": 80, "security": 70, "containers": 95, "database": 100 },
        "root_causes": [{ "title": "定时任务导致 CPU 尖峰", "evidence": "整点 CPU 达 92%", "confidence": "medium" }],
        "security_risks": [{ "title": "SSH 允许密码登录", "severity": "medium", "detail": "PasswordAuthentication yes", "recommendation": "改为密钥登录" }],
        "recommendations": [{ "title": "错峰执行定时任务", "category": "config", "priority": "high", "detail": "把 crontab 中整点任务分散", "expected_impact": "降低峰值 CPU" }],
        "anomalies": []
    })
}

fn has_tool_result_responses(body: &Value) -> bool {
    body["input"]
        .as_array()
        .is_some_and(|items| items.iter().any(|i| i["type"] == "function_call_output"))
}

fn has_tool_result_messages(body: &Value) -> bool {
    body["messages"].as_array().is_some_and(|msgs| {
        msgs.iter().any(|m| {
            m["content"]
                .as_array()
                .is_some_and(|c| c.iter().any(|b| b["type"] == "tool_result"))
        })
    })
}

async fn responses(State(log): State<Log>, Json(body): Json<Value>) -> Json<Value> {
    log.lock().unwrap().push(body.clone());
    let usage = json!({ "input_tokens": 10, "output_tokens": 5, "total_tokens": 15 });
    if !has_tool_result_responses(&body) {
        return Json(json!({
            "id": "resp_1", "object": "response", "created_at": 1, "status": "completed", "model": "fake",
            "output": [{ "type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "get_host_metrics", "arguments": "{\"range\":\"1h\"}", "status": "completed" }],
            "usage": usage,
        }));
    }
    Json(json!({
        "id": "resp_2", "object": "response", "created_at": 2, "status": "completed", "model": "fake",
        "output": [{ "type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                     "content": [{ "type": "output_text", "text": diagnosis().to_string(), "annotations": [] }] }],
        "usage": usage,
    }))
}

/// Anthropic-style SSE for streamed (chat) requests: a tool call first, then text in two deltas.
fn messages_stream(body: &Value) -> axum::response::Response {
    let ev = |name: &str, data: Value| format!("event: {name}\ndata: {data}\n\n");
    let usage = json!({ "input_tokens": 10, "output_tokens": 5 });
    let mut out = ev(
        "message_start",
        json!({ "type": "message_start", "message": { "id": "msg_s", "type": "message", "role": "assistant", "model": "fake", "content": [], "stop_reason": null, "stop_sequence": null, "usage": usage } }),
    );
    let stop = if !has_tool_result_messages(body) {
        out += &ev(
            "content_block_start",
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "tool_use", "id": "toolu_s1", "name": "get_host_metrics", "input": {} } }),
        );
        out += &ev(
            "content_block_delta",
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "input_json_delta", "partial_json": "{\"range\":\"1h\"}" } }),
        );
        "tool_use"
    } else {
        out += &ev(
            "content_block_start",
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
        );
        for part in ["主机运行", "正常。"] {
            out += &ev(
                "content_block_delta",
                json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": part } }),
            );
        }
        "end_turn"
    };
    out += &ev(
        "content_block_stop",
        json!({ "type": "content_block_stop", "index": 0 }),
    );
    out += &ev(
        "message_delta",
        json!({ "type": "message_delta", "delta": { "stop_reason": stop, "stop_sequence": null }, "usage": { "output_tokens": 5 } }),
    );
    out += &ev("message_stop", json!({ "type": "message_stop" }));
    axum::response::Response::builder()
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from(out))
        .unwrap()
}

async fn messages(State(log): State<Log>, Json(body): Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    log.lock().unwrap().push(body.clone());
    if body["stream"] == true {
        if body.to_string().contains("请慢慢想") {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        return messages_stream(&body);
    }
    messages_json(&body).into_response()
}

fn messages_json(body: &Value) -> Json<Value> {
    let usage = json!({ "input_tokens": 10, "output_tokens": 5 });
    if !has_tool_result_messages(body) {
        return Json(json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "fake",
            "content": [{ "type": "tool_use", "id": "toolu_1", "name": "get_host_metrics", "input": { "range": "1h" } }],
            "stop_reason": "tool_use", "stop_sequence": null, "usage": usage,
        }));
    }
    // structured output may be requested through a synthetic "json" tool or natively
    let json_tool = body["tools"]
        .as_array()
        .and_then(|t| t.iter().find(|t| t["name"] == "json"))
        .is_some();
    let content = if json_tool {
        json!([{ "type": "tool_use", "id": "toolu_2", "name": "json", "input": diagnosis() }])
    } else {
        json!([{ "type": "text", "text": diagnosis().to_string() }])
    };
    let stop = if json_tool { "tool_use" } else { "end_turn" };
    Json(
        json!({ "id": "msg_2", "type": "message", "role": "assistant", "model": "fake", "content": content, "stop_reason": stop, "stop_sequence": null, "usage": usage }),
    )
}

async fn fake_server() -> (String, Log) {
    let log: Log = Arc::default();
    let app = Router::new()
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        .with_state(log.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/v1"), log)
}

fn sidecar_path() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../agent-sidecar/dist/sidecar.mjs");
    let node_ok = std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    (p.is_file() && node_ok).then_some(p)
}

async fn run_once(format: ApiFormat) -> (Value, Vec<Value>) {
    let (base_url, log) = fake_server().await;
    let dir = tempfile::tempdir().unwrap();
    let key_env = format!(
        "TSM_TEST_KEY_{}",
        if format == ApiFormat::Responses {
            "R"
        } else {
            "M"
        }
    );
    // SAFETY: each test uses its own variable name.
    unsafe { std::env::set_var(&key_env, "test-key") };
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.ai.sidecar_path = sidecar_path();
    cfg.ai.timeout_secs = 60;
    cfg.ai.profiles = BTreeMap::from([(
        "default".to_string(),
        ModelProfile {
            api_format: format,
            base_url,
            model: "fake-model".into(),
            api_key_env: key_env,
            auth: AuthStyle::ApiKey,
        },
    )]);
    let cfg = Arc::new(cfg);
    let db = store::open(dir.path()).await.unwrap();
    let state = state::AppState::new(cfg.clone(), db);
    let sb = Arc::new(sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap());
    let mgr = agent::AgentManager::init(&state, sb).await;
    state.set_agent(mgr.clone());
    let status = mgr.status().await;
    assert!(status.enabled, "AI should be enabled: {:?}", status.reason);

    let run_id = mgr.trigger(ReportKind::Daily, "test").unwrap();
    let mut run = None;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some((r, steps)) = store::get_run(&state.db, &run_id).await.unwrap()
            && r.status != "running"
        {
            run = Some((r, steps));
            break;
        }
    }
    let (r, steps) = run.expect("run finished in time");
    assert_eq!(
        r.status,
        "succeeded",
        "run error: {:?}; requests: {:#?}",
        r.error,
        log.lock().unwrap()
    );
    assert!(
        steps
            .iter()
            .any(|s| s.kind == "tool_call" && s.tool.as_deref() == Some("get_host_metrics")),
        "{steps:?}"
    );
    assert!(steps.iter().any(|s| s.kind == "tool_result"));
    let report = store::get_report(&state.db, r.report_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.summary.generated_by, "ai");
    assert_eq!(report.summary.model.as_deref(), Some("fake-model"));
    let requests = log.lock().unwrap().clone();
    (report.body, requests)
}

#[tokio::test]
async fn responses_format_end_to_end() {
    if sidecar_path().is_none() {
        eprintln!("node or built sidecar missing, skipping");
        return;
    }
    let (body, requests) = run_once(ApiFormat::Responses).await;
    assert_eq!(body["health_score"], 82.0);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["model"], "fake-model");
    // the key must never appear in request bodies
    assert!(!requests.iter().any(|r| r.to_string().contains("test-key")));
}

#[tokio::test]
async fn messages_format_end_to_end() {
    if sidecar_path().is_none() {
        eprintln!("node or built sidecar missing, skipping");
        return;
    }
    let (body, requests) = run_once(ApiFormat::Messages).await;
    assert_eq!(body["recommendations"][0]["priority"], "high");
    assert!(requests.len() >= 2);
    assert!(
        requests[0]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "run_python")
    );
}

#[tokio::test]
async fn missing_key_falls_back_to_rules() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.ai.sidecar_path = sidecar_path();
    cfg.ai.profiles = BTreeMap::from([(
        "default".to_string(),
        ModelProfile {
            api_format: ApiFormat::Messages,
            base_url: "http://127.0.0.1:9".into(),
            model: "m".into(),
            api_key_env: "TSM_TEST_KEY_DEFINITELY_UNSET".into(),
            auth: AuthStyle::ApiKey,
        },
    )]);
    let cfg = Arc::new(cfg);
    let state = state::AppState::new(cfg.clone(), store::open(dir.path()).await.unwrap());
    let sb = Arc::new(sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap());
    let mgr = agent::AgentManager::init(&state, sb).await;
    state.set_agent(mgr.clone());
    let st = mgr.status().await;
    assert!(!st.enabled);
    assert!(
        st.reason.unwrap().contains("TSM_TEST_KEY_DEFINITELY_UNSET") || sidecar_path().is_none()
    );

    let run_id = mgr.trigger(ReportKind::Daily, "test").unwrap();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Some((r, _)) = store::get_run(&state.db, &run_id).await.unwrap()
            && r.status != "running"
        {
            assert_eq!(r.status, "fallback");
            let report = store::get_report(&state.db, r.report_id, None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(report.summary.generated_by, "rules");
            return;
        }
    }
    panic!("fallback run did not finish");
}

#[tokio::test]
async fn broken_sidecar_falls_back() {
    if std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("crash.mjs");
    std::fs::write(&script, "process.stdout.write(JSON.stringify({type:'ready'})+'\\n'); process.stdin.once('data', () => process.exit(3));").unwrap();
    // SAFETY: unique variable name for this test.
    unsafe { std::env::set_var("TSM_TEST_KEY_CRASH", "k") };
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.ai.sidecar_path = Some(script);
    cfg.ai.profiles = BTreeMap::from([(
        "default".to_string(),
        ModelProfile {
            api_format: ApiFormat::Responses,
            base_url: "http://127.0.0.1:9".into(),
            model: "m".into(),
            api_key_env: "TSM_TEST_KEY_CRASH".into(),
            auth: AuthStyle::ApiKey,
        },
    )]);
    let cfg = Arc::new(cfg);
    let state = state::AppState::new(cfg.clone(), store::open(dir.path()).await.unwrap());
    let sb = Arc::new(sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap());
    let mgr = agent::AgentManager::init(&state, sb).await;
    state.set_agent(mgr.clone());
    let run_id = mgr.trigger(ReportKind::Incident, "test").unwrap();
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Some((r, steps)) = store::get_run(&state.db, &run_id).await.unwrap()
            && r.status != "running"
        {
            assert_eq!(r.status, "fallback", "{r:?}");
            assert!(r.error.unwrap_or_default().contains("exited"));
            assert!(steps.iter().any(|s| s.kind == "error"));
            return;
        }
    }
    panic!("run did not finish");
}

/// Provider added at runtime (encrypted key in the DB) + routed reasoning effort reach the model.
#[tokio::test]
async fn db_provider_with_effort_end_to_end() {
    if sidecar_path().is_none() {
        eprintln!("node or built sidecar missing, skipping");
        return;
    }
    let (base_url, log) = fake_server().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.ai.sidecar_path = sidecar_path();
    cfg.ai.timeout_secs = 60;
    let cfg = Arc::new(cfg);
    let state = state::AppState::new(cfg.clone(), store::open(dir.path()).await.unwrap());
    state.settings.set_file_key_allowed(true);
    let sb = Arc::new(sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap());
    let mgr = agent::AgentManager::init(&state, sb).await;
    state.set_agent(mgr.clone());
    assert!(!mgr.status().await.enabled, "no provider yet");

    let id = settings::create_provider(
        &state.settings,
        &state.db,
        settings::ProviderInput {
            name: Some("ui".into()),
            api_format: Some(ApiFormat::Responses),
            base_url: Some(base_url),
            auth: None,
            default_model: Some("db-model".into()),
            api_key: Some("db-secret-key".into()),
        },
    )
    .await
    .unwrap();
    settings::replace_routes(
        &state.settings,
        &state.db,
        &[settings::Route {
            kind: "default".into(),
            provider: id,
            model: String::new(),
            effort: "high".into(),
        }],
    )
    .await
    .unwrap();
    let st = mgr.status().await;
    assert!(st.enabled, "{:?}", st.reason);

    let run_id = mgr.trigger(ReportKind::Daily, "test").unwrap();
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some((r, _)) = store::get_run(&state.db, &run_id).await.unwrap()
            && r.status != "running"
        {
            let requests = log.lock().unwrap().clone();
            assert_eq!(r.status, "succeeded", "{:?} {requests:#?}", r.error);
            assert_eq!(requests[0]["model"], "db-model");
            assert_eq!(
                requests[0]["reasoning"]["effort"], "high",
                "{:#?}",
                requests[0]
            );
            assert!(
                !requests
                    .iter()
                    .any(|r| r.to_string().contains("db-secret-key"))
            );
            return;
        }
    }
    panic!("run did not finish");
}

/// Conversation turn streams over SSE, runs tools, keeps history, and runs alongside a scheduled
/// analysis (separate lanes).
#[tokio::test]
async fn chat_streams_and_runs_alongside_background() {
    if sidecar_path().is_none() {
        eprintln!("node or built sidecar missing, skipping");
        return;
    }
    let (base_url, log) = fake_server().await;
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: unique variable name for this test.
    unsafe { std::env::set_var("TSM_TEST_KEY_CHAT", "chat-key") };
    let mut cfg = Config::default();
    cfg.storage.data_dir = dir.path().to_path_buf();
    cfg.ai.sidecar_path = sidecar_path();
    cfg.ai.timeout_secs = 60;
    cfg.ai.profiles = BTreeMap::from([(
        "default".to_string(),
        ModelProfile {
            api_format: ApiFormat::Messages,
            base_url,
            model: "fake-model".into(),
            api_key_env: "TSM_TEST_KEY_CHAT".into(),
            auth: AuthStyle::ApiKey,
        },
    )]);
    let cfg = Arc::new(cfg);
    let state = state::AppState::new(cfg.clone(), store::open(dir.path()).await.unwrap());
    let sb = Arc::new(sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap());
    let mgr = agent::AgentManager::init(&state, sb).await;
    state.set_agent(mgr.clone());
    let mut events = state.events.subscribe();

    store::create_conversation(&state.db, "c_test", "新对话", "chat", None)
        .await
        .unwrap();
    let background = mgr.trigger(ReportKind::Daily, "test").unwrap();
    let first = mgr.send_message("c_test", "主机怎么样？").await.unwrap();
    // one run per conversation at a time
    assert!(matches!(
        mgr.send_message("c_test", "再说一次").await,
        Err(agent::TriggerError::Busy(_))
    ));

    let wait = |id: String| {
        let db = state.db.clone();
        async move {
            for _ in 0..300 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Some((r, steps)) = store::get_run(&db, &id).await.unwrap()
                    && r.status != "running"
                {
                    return (r, steps);
                }
            }
            panic!("run {id} did not finish");
        }
    };
    let (r, steps) = wait(first.clone()).await;
    assert_eq!(
        r.status,
        "succeeded",
        "{:?} {:#?}",
        r.error,
        log.lock().unwrap()
    );
    assert_eq!(r.conversation_id.as_deref(), Some("c_test"));
    assert_eq!(steps[0].kind, "user");
    assert!(steps.iter().any(|s| s.kind == "tool_call"));
    assert_eq!(
        steps
            .iter()
            .rev()
            .find(|s| s.kind == "message")
            .unwrap()
            .text
            .as_deref(),
        Some("主机运行正常。")
    );
    let (b, _) = wait(background).await;
    assert_eq!(b.status, "succeeded", "{:?}", b.error);

    let mut deltas = String::new();
    while let Ok(ev) = events.try_recv() {
        if ev.name() == "agent_delta" {
            deltas.push_str(ev.data()["text"].as_str().unwrap());
        }
    }
    assert_eq!(deltas, "主机运行正常。");

    // the title follows the first message; the second turn sees the first answer
    let conv = store::get_conversation(&state.db, "c_test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conv.title, "主机怎么样？");
    let second = mgr.send_message("c_test", "那磁盘呢？").await.unwrap();
    let (r2, _) = wait(second).await;

    // a stuck request is cancelled without killing the shared sidecar
    let slow = mgr.send_message("c_test", "请慢慢想").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(mgr.cancel(&slow).await);
    let started = std::time::Instant::now();
    let (r3, _) = wait(slow).await;
    assert_eq!(r3.status, "cancelled");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(r2.status, "succeeded", "{:?}", r2.error);
    let requests = log.lock().unwrap().clone();
    let last = requests.iter().rev().find(|r| r["stream"] == true).unwrap();
    let msgs = last["messages"].as_array().unwrap();
    assert_eq!(msgs[0]["role"], "user");
    assert!(last.to_string().contains("主机运行正常。"));
    assert!(last.to_string().contains("那磁盘呢？"));
    assert!(!requests.iter().any(|r| r.to_string().contains("chat-key")));
}
