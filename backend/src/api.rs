//! HTTP API, SSE stream, MCP endpoint and the embedded dashboard. See `docs/api.md`.
//!
//! Reads (and the legacy manual trigger) use the optional bearer token. Everything that changes
//! settings or starts interactive work sits in the admin group, which additionally requires the
//! token to be configured at all and rejects cross-origin browser requests.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::model::{ContainerInfo, Health, ReportKind, Snapshot, now_ms};
use crate::state::Shared;
use crate::{alerts, store};

#[derive(rust_embed::Embed)]
#[folder = "../web/dist/"]
#[allow_missing = true]
struct WebAsset;

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<crate::ops::proto::OpError> for ApiError {
    fn from(e: crate::ops::proto::OpError) -> Self {
        use crate::ops::proto::ErrorCode as C;
        let status = match e.code {
            C::Unauthorized | C::NotAllowed => StatusCode::FORBIDDEN,
            C::Invalid => StatusCode::BAD_REQUEST,
            C::Busy | C::Conflict => StatusCode::CONFLICT,
            C::Unsupported => StatusCode::SERVICE_UNAVAILABLE,
            C::Failed => StatusCode::BAD_GATEWAY,
        };
        ApiError(status, e.message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(inv) = e.downcast_ref::<crate::settings::Invalid>() {
            return ApiError(StatusCode::BAD_REQUEST, inv.0.clone());
        }
        let e = match e.downcast::<crate::ops::proto::OpError>() {
            Ok(op) => return op.into(),
            Err(e) => e,
        };
        tracing::error!("api error: {e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ---------------------------------------------------------------- auth

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

async fn auth(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let Some(expected) = crate::config::secret(&state.cfg.server.token_env) else {
        return next.run(req).await;
    };
    let header_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    // EventSource cannot send headers, so the stream also accepts ?token=
    let query_token = (req.uri().path() == "/api/v1/stream")
        .then(|| {
            Query::<TokenQuery>::try_from_uri(req.uri())
                .ok()
                .and_then(|q| q.0.token)
        })
        .flatten();
    match header_token.or(query_token) {
        Some(t) if ct_eq(t.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => ApiError(StatusCode::UNAUTHORIZED, "unauthorized".into()).into_response(),
    }
}

/// Admin routes: a token must be configured, and browsers must not call cross-origin.
async fn require_admin(State(state): State<Shared>, req: Request, next: Next) -> Response {
    if crate::config::secret(&state.cfg.server.token_env).is_none() {
        return ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "写操作需要先设置访问令牌（环境变量 {}）",
                state.cfg.server.token_env
            ),
        )
        .into_response();
    }
    if !same_origin(req.headers()) {
        return ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into())
            .into_response();
    }
    next.run(req).await
}

/// Client address for the audit log: the TCP peer, or the first X-Forwarded-For hop when the
/// peer is a local reverse proxy.
#[derive(Clone)]
pub struct RemoteAddr(pub Option<String>);

pub fn remote_of(req: &Request) -> Option<String> {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    let fwd = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    match (peer, fwd) {
        (Some(p), Some(f)) if p.is_loopback() => Some(f),
        (Some(p), _) => Some(p.to_string()),
        (None, f) => f,
    }
}

/// Management routes (web and `/mcp/ops`): the separate ops token must be configured and sent
/// in `X-TSM-Ops-Token`; browsers must not call cross-origin. The regular API token is still
/// checked by [`auth`] in front of this.
pub async fn require_ops(State(state): State<Shared>, mut req: Request, next: Next) -> Response {
    let Some(expected) = crate::config::secret(&state.cfg.server.ops_token_env) else {
        return ApiError(
            StatusCode::FORBIDDEN,
            format!(
                "管理操作需要先设置运维令牌（环境变量 {}）",
                state.cfg.server.ops_token_env
            ),
        )
        .into_response();
    };
    if !same_origin(req.headers()) {
        return ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into())
            .into_response();
    }
    let given = req
        .headers()
        .get("x-tsm-ops-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !ct_eq(given.as_bytes(), expected.as_bytes()) {
        return ApiError(
            StatusCode::FORBIDDEN,
            "运维令牌无效或缺失（X-TSM-Ops-Token）".into(),
        )
        .into_response();
    }
    let remote = remote_of(&req);
    req.extensions_mut().insert(RemoteAddr(remote));
    next.run(req).await
}

/// True when there is no Origin header (non-browser client) or it matches Host.
fn same_origin(h: &HeaderMap) -> bool {
    let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = h.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/'));
    origin_host.is_some() && origin_host == host
}

fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

// ---------------------------------------------------------------- snapshot

pub async fn snapshot(state: &Shared) -> anyhow::Result<Snapshot> {
    let findings = store::list_findings(&state.db, false).await?;
    let alerts_open = alerts::open_counts(&state.db).await?;
    let latest = store::list_reports(&state.db, None, 1)
        .await?
        .into_iter()
        .next();
    let ai = match state.agent() {
        Some(a) => a.status().await,
        None => Default::default(),
    };
    let (host, dims, containers) = {
        let live = state.read();
        let c = &live.containers;
        let summary = crate::model::ContainerSummary {
            total: c.len(),
            running: c.iter().filter(|c| c.state == "running").count(),
            unhealthy: c
                .iter()
                .filter(|c| c.health.as_deref() == Some("unhealthy"))
                .count(),
            restart_loops: c.iter().filter(|c| c.restart_loop).count(),
            oom: c.iter().filter(|c| c.oom_killed).count(),
        };
        (
            live.host.clone(),
            crate::rules::dimensions(&live, &findings),
            summary,
        )
    };
    // a fresh AI diagnosis wins over the rule score
    let mut health = Health {
        score: crate::rules::overall(&dims),
        dimensions: dims,
        source: "rules",
    };
    if let Some(r) = latest
        .as_ref()
        .filter(|r| r.generated_by == "ai" && now_ms() - r.created_at < 90 * 60_000)
        && let Some(full) = store::get_report(&state.db, Some(r.id), None).await?
        && let Ok(d) = serde_json::from_value::<crate::model::Diagnosis>(full.body)
    {
        health = Health {
            score: d.health_score,
            dimensions: d.dimensions,
            source: "ai",
        };
    }
    Ok(Snapshot {
        generated_at: now_ms(),
        host,
        health,
        mode: state.mode(),
        containers,
        alerts_open,
        ai,
        latest_report: latest,
    })
}

async fn get_snapshot(State(state): State<Shared>) -> ApiResult<Snapshot> {
    Ok(Json(snapshot(&state).await?))
}

async fn get_status(State(state): State<Shared>) -> ApiResult<Value> {
    let ai = match state.agent() {
        Some(a) => a.status().await,
        None => Default::default(),
    };
    let collectors = state.read().collectors.clone();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "started_at": state.started_at,
        "mode": state.mode(),
        "ai": ai,
        "collectors": collectors,
    })))
}

#[derive(Deserialize)]
struct RangeQuery {
    range: Option<String>,
}

async fn get_metrics(State(state): State<Shared>, Query(q): Query<RangeQuery>) -> ApiResult<Value> {
    let range = q.range.unwrap_or_else(|| "1h".into());
    let span = store::range_ms(&range).ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "range must be 1h|6h|24h|7d|30d".into(),
        )
    })?;
    let (step, points) = store::query_metrics(&state.db, span, now_ms()).await?;
    Ok(Json(json!({ "step_secs": step, "points": points })))
}

async fn get_containers(State(state): State<Shared>) -> ApiResult<Vec<ContainerInfo>> {
    let live = state.read();
    let list = live
        .containers
        .iter()
        .map(|c| {
            let mut c = c.clone();
            c.history = Some(
                live.container_history
                    .get(&c.id)
                    .map(|h| h.iter().cloned().collect())
                    .unwrap_or_default(),
            );
            c
        })
        .collect();
    Ok(Json(list))
}

#[derive(Deserialize)]
struct TailQuery {
    tail: Option<usize>,
}

async fn get_container_logs(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Query(q): Query<TailQuery>,
) -> ApiResult<Value> {
    // only containers we discovered can be queried
    let known = state
        .read()
        .containers
        .iter()
        .any(|c| c.id == id || c.name == id);
    if !known {
        return Err(not_found("container"));
    }
    let docker = crate::collect::docker::connect().map_err(|e| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("docker unavailable: {e}"),
        )
    })?;
    let lines =
        crate::collect::docker::container_logs(&docker, &id, q.tail.unwrap_or(200).min(2000))
            .await
            .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("docker logs failed: {e}")))?;
    Ok(Json(json!({ "lines": lines })))
}

async fn get_log_sources(State(state): State<Shared>) -> ApiResult<Value> {
    Ok(Json(json!(
        state
            .read()
            .log_sources
            .values()
            .cloned()
            .collect::<Vec<_>>()
    )))
}

async fn get_log_rates(
    State(state): State<Shared>,
    Query(q): Query<RangeQuery>,
) -> ApiResult<Value> {
    let range = q.range.unwrap_or_else(|| "24h".into());
    let span = store::range_ms(&range)
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "bad range".into()))?;
    let (step, series) = store::query_log_rates(&state.db, span, now_ms()).await?;
    let series: Vec<Value> = series
        .into_iter()
        .map(|s| json!({ "source": s.source, "points": s.points.iter().map(|(ts, l, e)| json!({ "ts": ts, "lines": l, "errors": e })).collect::<Vec<_>>() }))
        .collect();
    Ok(Json(json!({ "step_secs": step, "series": series })))
}

#[derive(Deserialize)]
struct ClusterQ {
    source: Option<String>,
    level: Option<String>,
    limit: Option<i64>,
}

async fn get_log_clusters(
    State(state): State<Shared>,
    Query(q): Query<ClusterQ>,
) -> ApiResult<Vec<crate::model::LogCluster>> {
    let nonempty = |s: &Option<String>| s.as_deref().filter(|s| !s.is_empty()).map(str::to_string);
    let (source, level) = (nonempty(&q.source), nonempty(&q.level));
    let cq = store::ClusterQuery {
        source: source.as_deref(),
        level: level.as_deref(),
        limit: q.limit.unwrap_or(100),
        ..Default::default()
    };
    Ok(Json(store::query_clusters(&state.db, &cq).await?))
}

#[derive(Deserialize)]
struct DaysQuery {
    days: Option<i64>,
}

async fn get_daily_errors(
    State(state): State<Shared>,
    Query(q): Query<DaysQuery>,
) -> ApiResult<Value> {
    let rows = store::daily_errors(&state.db, q.days.unwrap_or(365).clamp(1, 730)).await?;
    Ok(Json(json!(
        rows.into_iter()
            .map(|(date, count)| json!({ "date": date, "count": count }))
            .collect::<Vec<_>>()
    )))
}

#[derive(Deserialize)]
struct FindingsQ {
    include_resolved: Option<bool>,
}

#[derive(Deserialize)]
struct AccessQ {
    window: Option<i64>,
}

async fn get_packages(State(state): State<Shared>) -> ApiResult<Value> {
    let socket = &state.cfg.packages.updater_socket;
    let mut v =
        serde_json::to_value(crate::collect::packages::last()).map_err(anyhow::Error::from)?;
    v["updater"] = json!({
        "available": crate::updater::helper_available(socket),
        "socket": socket,
    });
    Ok(Json(v))
}

async fn get_package_jobs(State(state): State<Shared>) -> ApiResult<Vec<crate::updater::Job>> {
    Ok(Json(crate::updater::list_jobs(&state.db).await?))
}

async fn get_package_job(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::updater::Job> {
    crate::updater::get_job(&state.db, id)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("job"))
}

async fn post_package_job(
    State(state): State<Shared>,
    Json(req): Json<crate::updater::Request>,
) -> Result<Response, ApiError> {
    let id = crate::updater::start_job(&state, req).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))).into_response())
}

async fn post_packages_check(
    State(state): State<Shared>,
) -> ApiResult<crate::collect::packages::PackageReport> {
    Ok(Json(crate::collect::packages::check(&state).await))
}

/// Dashboard view of real-time access statistics (client addresses unmasked).
async fn get_access(State(state): State<Shared>, Query(q): Query<AccessQ>) -> ApiResult<Value> {
    let sources: Vec<&str> = state
        .cfg
        .logs
        .iter()
        .filter(|l| l.kind == crate::config::LogKind::NginxAccess)
        .map(|l| l.name.as_str())
        .collect();
    let stats =
        crate::collect::pipeline()
            .access
            .stats(q.window.unwrap_or(15), now_ms(), 20, false);
    Ok(Json(json!({ "sources": sources, "stats": stats })))
}

#[derive(Deserialize)]
struct RangeQ {
    range: Option<String>,
}

/// Persisted access history (client addresses unmasked for the dashboard).
async fn get_access_history(
    State(state): State<Shared>,
    Query(q): Query<RangeQ>,
) -> ApiResult<crate::collect::access::AccessStats> {
    let range = q.range.unwrap_or_else(|| "24h".into());
    crate::collect::access_history::history(&state.db, &range, now_ms(), 20, false)
        .await?
        .map(Json)
        .ok_or_else(|| bad_request("range must be 1h, 6h, 24h, 7d or 30d"))
}

async fn get_findings(
    State(state): State<Shared>,
    Query(q): Query<FindingsQ>,
) -> ApiResult<Vec<crate::model::Finding>> {
    Ok(Json(
        store::list_findings(&state.db, q.include_resolved.unwrap_or(false)).await?,
    ))
}

async fn get_ports(State(state): State<Shared>) -> ApiResult<Value> {
    Ok(Json(json!(state.read().ports)))
}

async fn get_db(State(state): State<Shared>) -> ApiResult<Value> {
    Ok(Json(json!(state.read().dbs)))
}

#[derive(Deserialize)]
struct AlertsQ {
    status: Option<String>,
    limit: Option<i64>,
}

async fn get_alerts(
    State(state): State<Shared>,
    Query(q): Query<AlertsQ>,
) -> ApiResult<Vec<crate::model::Alert>> {
    let open_only = q.status.as_deref() != Some("all");
    Ok(Json(
        alerts::list(&state.db, open_only, q.limit.unwrap_or(100)).await?,
    ))
}

#[derive(Deserialize)]
struct ReportsQ {
    kind: Option<String>,
    limit: Option<i64>,
}

fn kind_filter(kind: &Option<String>) -> Result<Option<&str>, ApiError> {
    match kind.as_deref().filter(|k| !k.is_empty()) {
        None => Ok(None),
        Some(k) => ReportKind::parse(k)
            .map(|k| Some(k.as_str()))
            .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "unknown report kind".into())),
    }
}

async fn get_reports(
    State(state): State<Shared>,
    Query(q): Query<ReportsQ>,
) -> ApiResult<Vec<crate::model::ReportSummary>> {
    Ok(Json(
        store::list_reports(&state.db, kind_filter(&q.kind)?, q.limit.unwrap_or(50)).await?,
    ))
}

async fn get_report_latest(
    State(state): State<Shared>,
    Query(q): Query<ReportsQ>,
) -> ApiResult<crate::model::Report> {
    store::get_report(&state.db, None, kind_filter(&q.kind)?)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("report"))
}

async fn get_report(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::model::Report> {
    store::get_report(&state.db, Some(id), None)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("report"))
}

#[derive(Deserialize)]
struct LimitQ {
    limit: Option<i64>,
}

async fn get_runs(
    State(state): State<Shared>,
    Query(q): Query<LimitQ>,
) -> ApiResult<Vec<crate::model::AgentRun>> {
    Ok(Json(
        store::list_runs(&state.db, q.limit.unwrap_or(50)).await?,
    ))
}

async fn get_run(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    let (run, steps) = store::get_run(&state.db, &id)
        .await?
        .ok_or_else(|| not_found("run"))?;
    let mut v = serde_json::to_value(run).map_err(anyhow::Error::from)?;
    v["steps"] = json!(steps);
    Ok(Json(v))
}

#[derive(Deserialize)]
struct TriggerBody {
    kind: String,
}

async fn post_trigger(
    State(state): State<Shared>,
    Json(body): Json<TriggerBody>,
) -> Result<Response, ApiError> {
    let kind = ReportKind::parse(&body.kind).ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "kind must be hourly|daily|incident|audit".into(),
        )
    })?;
    let agent = state
        .agent()
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "agent not ready".into()))?;
    match agent.trigger(kind, "manual") {
        Ok(run_id) => Ok((StatusCode::ACCEPTED, Json(json!({ "run_id": run_id }))).into_response()),
        Err(e) => Err(trigger_error(e)),
    }
}

fn trigger_error(e: crate::agent::TriggerError) -> ApiError {
    match e {
        crate::agent::TriggerError::Busy(id) => ApiError(
            StatusCode::CONFLICT,
            format!("analysis {id} is already running"),
        ),
        crate::agent::TriggerError::NotFound => not_found("conversation"),
    }
}

fn agent_of(state: &Shared) -> Result<&std::sync::Arc<crate::agent::AgentManager>, ApiError> {
    state
        .agent()
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "agent not ready".into()))
}

// ---------------------------------------------------------------- conversations

#[derive(Deserialize)]
struct ConversationsQ {
    kind: Option<String>,
    limit: Option<i64>,
}

async fn get_conversations(
    State(state): State<Shared>,
    Query(q): Query<ConversationsQ>,
) -> ApiResult<Vec<crate::model::Conversation>> {
    Ok(Json(
        store::list_conversations(&state.db, q.kind.as_deref(), q.limit.unwrap_or(100)).await?,
    ))
}

async fn get_conversation(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    let conv = store::get_conversation(&state.db, &id)
        .await?
        .ok_or_else(|| not_found("conversation"))?;
    let runs: Vec<Value> = store::conversation_runs(&state.db, &id)
        .await?
        .into_iter()
        .map(|(run, steps)| {
            let mut v = serde_json::to_value(run).unwrap_or(Value::Null);
            v["steps"] = json!(steps);
            v
        })
        .collect();
    let mut v = serde_json::to_value(conv).map_err(anyhow::Error::from)?;
    v["runs"] = json!(runs);
    Ok(Json(v))
}

const MAX_MESSAGE_CHARS: usize = 8000;

fn clean_message(text: &str) -> Result<String, ApiError> {
    let t = text.trim();
    if t.is_empty() {
        return Err(bad_request("消息不能为空"));
    }
    if t.chars().count() > MAX_MESSAGE_CHARS {
        return Err(bad_request(format!(
            "消息不能超过 {MAX_MESSAGE_CHARS} 个字符"
        )));
    }
    Ok(t.to_string())
}

/// Accepts exactly one of `report_id`, `alert_id`, `run_id` or `text` (a note such as a package list).
fn clean_context(ctx: &Value) -> Result<Value, ApiError> {
    let obj = ctx
        .as_object()
        .ok_or_else(|| bad_request("context 必须是对象"))?;
    let ok = obj.len() == 1
        && (obj.get("report_id").is_some_and(Value::is_i64)
            || obj.get("alert_id").is_some_and(Value::is_i64)
            || obj
                .get("run_id")
                .and_then(Value::as_str)
                .is_some_and(|s| s.len() < 100)
            || obj
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|s| s.chars().count() <= 20_000));
    if !ok {
        return Err(bad_request(
            "context 只能包含 report_id、alert_id、run_id 或 text 之一",
        ));
    }
    Ok(ctx.clone())
}

#[derive(Deserialize)]
struct NewConversation {
    title: Option<String>,
    context: Option<Value>,
    /// First message; when present the reply starts immediately.
    message: Option<String>,
}

async fn post_conversation(
    State(state): State<Shared>,
    Json(b): Json<NewConversation>,
) -> Result<Response, ApiError> {
    let agent = agent_of(&state)?;
    let context = b.context.as_ref().map(clean_context).transpose()?;
    let message = b.message.as_deref().map(clean_message).transpose()?;
    let title: String = b
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or(crate::agent::prompt::NEW_CHAT_TITLE)
        .chars()
        .take(60)
        .collect();
    let id = format!("c_{}", uuid::Uuid::new_v4().simple());
    store::create_conversation(&state.db, &id, &title, "chat", context.as_ref()).await?;
    let run_id = match message {
        Some(m) => Some(agent.send_message(&id, &m).await.map_err(trigger_error)?),
        None => None,
    };
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "run_id": run_id })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct MessageBody {
    text: String,
}

async fn post_message(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(b): Json<MessageBody>,
) -> Result<Response, ApiError> {
    let text = clean_message(&b.text)?;
    let run_id = agent_of(&state)?
        .send_message(&id, &text)
        .await
        .map_err(trigger_error)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "run_id": run_id }))).into_response())
}

async fn delete_conversation(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    if store::get_conversation(&state.db, &id).await?.is_none() {
        return Err(not_found("conversation"));
    }
    if !store::delete_conversation(&state.db, &id).await? {
        return Err(bad_request(
            "只能删除手动发起的对话，定时任务记录会随保留策略清理",
        ));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- prompts & tasks

async fn get_prompts(State(state): State<Shared>) -> ApiResult<Vec<crate::agent::library::Prompt>> {
    Ok(Json(crate::agent::library::list(&state.db).await?))
}

async fn post_prompt(
    State(state): State<Shared>,
    Json(b): Json<crate::agent::library::PromptInput>,
) -> ApiResult<Value> {
    let id = crate::agent::library::create(&state.db, b).await?;
    Ok(Json(json!({ "id": id })))
}

async fn patch_prompt(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(b): Json<crate::agent::library::PromptInput>,
) -> ApiResult<Value> {
    if !crate::agent::library::update(&state.db, &id, b).await? {
        return Err(not_found("prompt"));
    }
    Ok(Json(json!({ "id": id })))
}

async fn delete_prompt(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    if !crate::agent::library::delete(&state.db, &id).await? {
        return Err(not_found("prompt"));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct GenerateBody {
    description: String,
}

async fn post_generate_prompt(
    State(state): State<Shared>,
    Json(b): Json<GenerateBody>,
) -> ApiResult<Value> {
    let description = clean_message(&b.description)?;
    let title: String = format!(
        "生成提示词：{}",
        description.chars().take(24).collect::<String>()
    );
    let spec = crate::agent::ChatSpec {
        route: "prompt_gen".into(),
        system: Some(crate::agent::library::GENERATOR_SYSTEM.into()),
        tools: false,
    };
    match agent_of(&state)?
        .complete("prompt_gen", &title, spec, &description)
        .await
    {
        Ok(body) => Ok(Json(json!({ "body": body.trim() }))),
        Err(e) => Err(ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
    }
}

async fn get_tasks(State(state): State<Shared>) -> ApiResult<Value> {
    Ok(Json(json!({
        "tasks": crate::tasks::list(&state.db).await?,
        "system": crate::tasks::system_jobs(&state),
    })))
}

async fn post_task(
    State(state): State<Shared>,
    Json(b): Json<crate::tasks::TaskInput>,
) -> ApiResult<Value> {
    let id = crate::tasks::create(&state.db, b).await?;
    Ok(Json(json!({ "id": id })))
}

async fn patch_task(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(b): Json<crate::tasks::TaskInput>,
) -> ApiResult<Value> {
    if !crate::tasks::update(&state.db, &id, b).await? {
        return Err(not_found("task"));
    }
    Ok(Json(json!({ "id": id })))
}

async fn delete_task(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    if !crate::tasks::delete(&state.db, &id).await? {
        return Err(not_found("task"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn post_run_task(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    let task = crate::tasks::get(&state.db, &id)
        .await?
        .ok_or_else(|| not_found("task"))?;
    let run_id = crate::tasks::fire(&state, &task, "manual").await?;
    Ok(Json(
        json!({ "run_id": run_id, "deferred": run_id.is_none() }),
    ))
}

// ---------------------------------------------------------------- alerts & channels

#[derive(Deserialize, Default)]
struct SilenceBody {
    minutes: i64,
}

async fn alert_action(
    state: &Shared,
    id: i64,
    action: alerts::Action,
) -> ApiResult<crate::model::Alert> {
    alerts::act(state, id, action)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("alert"))
}

async fn post_alert_ack(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::model::Alert> {
    alert_action(&state, id, alerts::Action::Ack).await
}

async fn post_alert_close(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::model::Alert> {
    alert_action(&state, id, alerts::Action::Close).await
}

async fn post_alert_silence(
    State(state): State<Shared>,
    Path(id): Path<i64>,
    Json(b): Json<SilenceBody>,
) -> ApiResult<crate::model::Alert> {
    if !(0..=7 * 24 * 60).contains(&b.minutes) {
        return Err(bad_request("静默时长需在 0 到 7 天之间"));
    }
    alert_action(&state, id, alerts::Action::Silence(b.minutes)).await
}

async fn get_channels(State(state): State<Shared>) -> ApiResult<Value> {
    let list: Vec<crate::channels::ChannelView> = crate::channels::all(&state)
        .await
        .iter()
        .map(Into::into)
        .collect();
    Ok(Json(json!({
        "channels": list,
        "key_storage": state.settings.key_storage(),
    })))
}

async fn post_channel(
    State(state): State<Shared>,
    Json(b): Json<crate::channels::ChannelInput>,
) -> ApiResult<Value> {
    let id = crate::channels::create(&state.settings, &state.db, b).await?;
    Ok(Json(json!({ "id": id })))
}

async fn patch_channel(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(b): Json<crate::channels::ChannelInput>,
) -> ApiResult<Value> {
    if id.starts_with("config:") {
        return Err(bad_request("配置文件中的渠道只读，请修改 config.toml"));
    }
    if !crate::channels::update(&state.settings, &state.db, &id, b).await? {
        return Err(not_found("channel"));
    }
    Ok(Json(json!({ "id": id })))
}

async fn delete_channel(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    if id.starts_with("config:") {
        return Err(bad_request("配置文件中的渠道只读，请修改 config.toml"));
    }
    if !crate::channels::delete(&state.db, &id).await? {
        return Err(not_found("channel"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn post_channel_test(
    State(state): State<Shared>,
    Path(id): Path<String>,
) -> ApiResult<Value> {
    match state.notifier.test(&state, &id).await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) if e.downcast_ref::<crate::settings::Invalid>().is_some() => Err(e.into()),
        Err(e) => Err(ApiError(
            StatusCode::BAD_GATEWAY,
            format!("发送失败：{e:#}"),
        )),
    }
}

async fn post_cancel(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    if !agent_of(&state)?.cancel(&id).await {
        return Err(not_found("running run"));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- settings

fn emit_settings(state: &Shared) {
    state.emit(crate::model::Event::Settings {
        generation: state.settings.generation(),
    });
}

async fn get_providers(State(state): State<Shared>) -> ApiResult<Value> {
    let snap = state.settings.snapshot();
    Ok(Json(json!({
        "providers": snap.providers,
        "key_storage": state.settings.key_storage(),
    })))
}

async fn post_provider(
    State(state): State<Shared>,
    Json(body): Json<crate::settings::ProviderInput>,
) -> ApiResult<Value> {
    let id = crate::settings::create_provider(&state.settings, &state.db, body).await?;
    emit_settings(&state);
    Ok(Json(json!({ "id": id })))
}

async fn patch_provider(
    State(state): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<crate::settings::ProviderInput>,
) -> ApiResult<Value> {
    if state.cfg.ai.profiles.contains_key(&id) {
        return Err(bad_request(
            "配置文件中的 Provider 只读，请修改 config.toml",
        ));
    }
    if !crate::settings::update_provider(&state.settings, &state.db, &id, body).await? {
        return Err(not_found("provider"));
    }
    emit_settings(&state);
    Ok(Json(json!({ "id": id })))
}

async fn delete_provider(State(state): State<Shared>, Path(id): Path<String>) -> ApiResult<Value> {
    if state.cfg.ai.profiles.contains_key(&id) {
        return Err(bad_request(
            "配置文件中的 Provider 只读，请修改 config.toml",
        ));
    }
    if !crate::settings::delete_provider(&state.settings, &state.db, &id).await? {
        return Err(not_found("provider"));
    }
    emit_settings(&state);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ModelsBody {
    /// Saved provider whose stored key (and, unless overridden, URL/format) is used.
    provider_id: Option<String>,
    api_format: Option<crate::config::ApiFormat>,
    base_url: Option<String>,
    auth: Option<crate::config::AuthStyle>,
    api_key: Option<String>,
}

async fn post_models(State(state): State<Shared>, Json(b): Json<ModelsBody>) -> ApiResult<Value> {
    let saved = match &b.provider_id {
        Some(id) => Some(
            state
                .settings
                .snapshot()
                .providers
                .iter()
                .find(|p| &p.id == id)
                .cloned()
                .ok_or_else(|| not_found("provider"))?,
        ),
        None => None,
    };
    let format = b
        .api_format
        .or(saved.as_ref().map(|p| p.api_format))
        .ok_or_else(|| bad_request("缺少 api_format"))?;
    let base_url = b
        .base_url
        .clone()
        .or(saved.as_ref().map(|p| p.base_url.clone()))
        .ok_or_else(|| bad_request("缺少 base_url"))?;
    let auth = b
        .auth
        .or(saved.as_ref().map(|p| p.auth))
        .unwrap_or_default();
    let key = match b
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        Some(k) => Some(k.to_string()),
        // the stored key only goes to the URL it was saved for
        None => match &saved {
            Some(p)
                if p.base_url.trim_end_matches('/') == base_url.trim().trim_end_matches('/') =>
            {
                state.settings.provider_key(&state.db, &p.id).await?
            }
            _ => None,
        },
    };
    let models = crate::settings::fetch_models(format, &base_url, auth, key.as_deref()).await?;
    Ok(Json(json!({ "models": models })))
}

async fn get_routing(State(state): State<Shared>) -> ApiResult<Value> {
    let snap = state.settings.snapshot();
    let kinds: Vec<Value> = crate::settings::TASK_KINDS
        .iter()
        .map(|(k, label)| {
            json!({
                "kind": k,
                "label": label,
                "resolved": state.settings.resolve(k),
            })
        })
        .collect();
    Ok(Json(json!({
        "kinds": kinds,
        "efforts": crate::settings::EFFORTS,
        "routes": snap.routes.values().collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct RoutingBody {
    routes: Vec<crate::settings::Route>,
}

async fn put_routing(State(state): State<Shared>, Json(b): Json<RoutingBody>) -> ApiResult<Value> {
    crate::settings::replace_routes(&state.settings, &state.db, &b.routes).await?;
    emit_settings(&state);
    get_routing(State(state)).await
}

async fn stream(
    State(state): State<Shared>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.events.subscribe();
    let s = BroadcastStream::new(rx).filter_map(|ev| {
        // lagging subscribers just skip missed events
        let ev = ev.ok()?;
        Some(Ok(SseEvent::default()
            .event(ev.name())
            .data(ev.data().to_string())))
    });
    Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

// ---------------------------------------------------------------- ops (helper-mediated management)

async fn get_ops_caps(State(state): State<Shared>) -> ApiResult<crate::ops::Capabilities> {
    Ok(Json(crate::ops::capabilities(&state).await))
}

#[derive(Deserialize)]
struct OpsJobsQ {
    domain: Option<String>,
    limit: Option<i64>,
}

async fn get_ops_jobs(
    State(state): State<Shared>,
    Query(q): Query<OpsJobsQ>,
) -> ApiResult<Vec<crate::ops::Job>> {
    Ok(Json(
        crate::ops::list_jobs(&state.db, q.domain.as_deref(), q.limit.unwrap_or(30)).await?,
    ))
}

async fn get_ops_job(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::ops::Job> {
    crate::ops::get_job(&state.db, id)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("job"))
}

async fn get_ops_audit(
    State(state): State<Shared>,
    Query(q): Query<LimitQ>,
) -> ApiResult<Vec<crate::ops::AuditEntry>> {
    Ok(Json(
        crate::ops::list_audit(&state.db, q.limit.unwrap_or(100)).await?,
    ))
}

async fn get_ops_pending(State(state): State<Shared>) -> ApiResult<Value> {
    Ok(Json(crate::ops::pending(&state).await))
}

/// `GET /api/v1/ops/read/{call}?path=...`: helper read with local fallback.
async fn get_ops_read(
    State(state): State<Shared>,
    Path(call): Path<String>,
    Query(q): Query<std::collections::BTreeMap<String, String>>,
) -> ApiResult<Value> {
    let args = json!(q);
    Ok(Json(crate::ops::read(&state, &call, args).await?))
}

async fn get_ssh_sessions() -> ApiResult<Value> {
    Ok(Json(json!(crate::ops::sessions().await)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpsRun {
    call: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    dry_run: bool,
}

/// Starts a change and waits briefly for it; long jobs come back with `status = running` and
/// continue over the `ops_job` SSE event.
async fn post_ops_run(
    State(state): State<Shared>,
    axum::Extension(remote): axum::Extension<RemoteAddr>,
    Json(r): Json<OpsRun>,
) -> ApiResult<crate::ops::Job> {
    let summary = crate::ops::calls::summary(&r.call, &r.args);
    let id = crate::ops::submit(
        &state,
        crate::ops::Submit {
            call: r.call,
            args: r.args,
            dry_run: r.dry_run,
            summary,
            via: crate::ops::Via {
                via: "web",
                remote: remote.0,
            },
        },
    )
    .await?;
    crate::ops::wait(&state, id, Duration::from_secs(20))
        .await?
        .map(Json)
        .ok_or_else(|| not_found("job"))
}

// ---------------------------------------------------------------- static dashboard

async fn static_handler(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path == "mcp" || path.starts_with("mcp/") {
        return ApiError(StatusCode::NOT_FOUND, "not found".into()).into_response();
    }
    let (file, name) = match WebAsset::get(path).filter(|_| !path.is_empty()) {
        Some(f) => (f, path.to_string()),
        None => match WebAsset::get("index.html") {
            Some(f) => (f, "index.html".into()),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    "dashboard not built: run `pnpm -C web build` and rebuild tsmonitor",
                )
                    .into_response();
            }
        },
    };
    let etag = format!("\"{}\"", hex::encode(file.metadata.sha256_hash()));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let mime = mime_guess::from_path(&name).first_or_octet_stream();
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        file.data.into_owned(),
    )
        .into_response()
}

pub fn router(state: Shared) -> Router {
    let api = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/snapshot", get(get_snapshot))
        .route("/api/v1/metrics", get(get_metrics))
        .route("/api/v1/containers", get(get_containers))
        .route("/api/v1/containers/{id}/logs", get(get_container_logs))
        .route("/api/v1/logs/sources", get(get_log_sources))
        .route("/api/v1/logs/rates", get(get_log_rates))
        .route("/api/v1/logs/clusters", get(get_log_clusters))
        .route("/api/v1/logs/daily-errors", get(get_daily_errors))
        .route("/api/v1/findings", get(get_findings))
        .route("/api/v1/access", get(get_access))
        .route("/api/v1/access/history", get(get_access_history))
        .route("/api/v1/packages", get(get_packages))
        .route("/api/v1/packages/jobs", get(get_package_jobs))
        .route("/api/v1/packages/jobs/{id}", get(get_package_job))
        .route("/api/v1/ports", get(get_ports))
        .route("/api/v1/db", get(get_db))
        .route("/api/v1/alerts", get(get_alerts))
        .route("/api/v1/reports", get(get_reports))
        .route("/api/v1/reports/latest", get(get_report_latest))
        .route("/api/v1/reports/{id}", get(get_report))
        .route("/api/v1/agent/runs", get(get_runs))
        .route("/api/v1/agent/runs/{id}", get(get_run))
        .route("/api/v1/agent/trigger", post(post_trigger))
        .route("/api/v1/stream", get(stream))
        .route("/api/v1/settings/providers", get(get_providers))
        .route("/api/v1/settings/routing", get(get_routing))
        .route("/api/v1/conversations", get(get_conversations))
        .route("/api/v1/conversations/{id}", get(get_conversation))
        .route("/api/v1/prompts", get(get_prompts))
        .route("/api/v1/settings/notify", get(get_channels))
        .route("/api/v1/tasks", get(get_tasks))
        .route("/api/v1/ops/capabilities", get(get_ops_caps))
        .route("/api/v1/ops/jobs", get(get_ops_jobs))
        .route("/api/v1/ops/jobs/{id}", get(get_ops_job))
        .route("/api/v1/ops/audit", get(get_ops_audit))
        .route("/api/v1/ops/pending", get(get_ops_pending))
        .route("/api/v1/ops/read/{call}", get(get_ops_read))
        .route("/api/v1/ssh/sessions", get(get_ssh_sessions))
        .nest_service("/mcp", crate::mcp::service(state.clone(), false));
    let ops = Router::new()
        .route("/api/v1/ops/run", post(post_ops_run))
        .nest_service("/mcp/ops", crate::mcp::service(state.clone(), true))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_ops,
        ));
    let admin = Router::new()
        .route("/api/v1/settings/providers", post(post_provider))
        .route(
            "/api/v1/settings/providers/{id}",
            patch(patch_provider).delete(delete_provider),
        )
        .route("/api/v1/settings/models", post(post_models))
        .route("/api/v1/settings/routing", axum::routing::put(put_routing))
        .route("/api/v1/conversations", post(post_conversation))
        .route(
            "/api/v1/conversations/{id}",
            axum::routing::delete(delete_conversation),
        )
        .route("/api/v1/conversations/{id}/messages", post(post_message))
        .route("/api/v1/agent/runs/{id}/cancel", post(post_cancel))
        .route("/api/v1/prompts", post(post_prompt))
        .route("/api/v1/prompts/generate", post(post_generate_prompt))
        .route(
            "/api/v1/prompts/{id}",
            patch(patch_prompt).delete(delete_prompt),
        )
        .route("/api/v1/tasks", post(post_task))
        .route("/api/v1/tasks/{id}", patch(patch_task).delete(delete_task))
        .route("/api/v1/tasks/{id}/run", post(post_run_task))
        .route("/api/v1/packages/check", post(post_packages_check))
        .route("/api/v1/packages/jobs", post(post_package_job))
        .route("/api/v1/alerts/{id}/ack", post(post_alert_ack))
        .route("/api/v1/alerts/{id}/silence", post(post_alert_silence))
        .route("/api/v1/alerts/{id}/close", post(post_alert_close))
        .route("/api/v1/settings/notify", post(post_channel))
        .route(
            "/api/v1/settings/notify/{id}",
            patch(patch_channel).delete(delete_channel),
        )
        .route("/api/v1/settings/notify/{id}/test", post(post_channel_test))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ));
    api.merge(admin)
        .merge(ops)
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .fallback(static_handler)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_check() {
        let mut h = HeaderMap::new();
        assert!(same_origin(&h));
        h.insert(header::HOST, "127.0.0.1:8787".parse().unwrap());
        h.insert(header::ORIGIN, "http://127.0.0.1:8787".parse().unwrap());
        assert!(same_origin(&h));
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!same_origin(&h));
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    async fn serve(token_env: &str) -> String {
        let mut cfg = crate::config::Config::default();
        cfg.server.token_env = token_env.into();
        let state = crate::state::AppState::new(
            std::sync::Arc::new(cfg),
            crate::store::open_memory().await,
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn admin_routes_need_configured_token() {
        let base = serve("TSM_TEST_API_TOKEN_UNSET").await;
        let c = reqwest::Client::new();
        // reads stay open when no token is configured
        let r = c
            .get(format!("{base}/api/v1/settings/providers"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let r = c
            .post(format!("{base}/api/v1/settings/providers"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }

    #[tokio::test]
    async fn admin_routes_check_token_and_origin() {
        // SAFETY: unique variable name for this test.
        unsafe { std::env::set_var("TSM_TEST_API_TOKEN_SET", "t0k") };
        let base = serve("TSM_TEST_API_TOKEN_SET").await;
        let c = reqwest::Client::new();
        let url = format!("{base}/api/v1/settings/providers");
        let r = c.post(&url).json(&json!({})).send().await.unwrap();
        assert_eq!(r.status(), 401);
        let r = c
            .post(&url)
            .bearer_auth("t0k")
            .header("origin", "https://evil.example")
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        // authorized: reaches validation
        let r = c
            .post(&url)
            .bearer_auth("t0k")
            .json(&json!({ "name": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    /// JSON-RPC over MCP Streamable HTTP; the reply may come as SSE.
    async fn mcp_call(
        c: &reqwest::Client,
        url: &str,
        session: Option<&str>,
        body: Value,
    ) -> (Option<String>, Value) {
        let mut req = c
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await.unwrap();
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let text = resp.text().await.unwrap();
        let json = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|l| l.starts_with('{'))
            .map(str::to_string)
            .unwrap_or(text);
        (sid, serde_json::from_str(&json).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn mcp_lists_shared_tools_without_workspace_tools() {
        let mut cfg = crate::config::Config::default();
        cfg.server.token_env = "TSM_TEST_API_TOKEN_UNSET".into();
        let dir = tempfile::tempdir().unwrap();
        cfg.storage.data_dir = dir.path().to_path_buf();
        let cfg = std::sync::Arc::new(cfg);
        let state = crate::state::AppState::new(cfg.clone(), crate::store::open_memory().await);
        let sb = std::sync::Arc::new(
            crate::sandbox::Sandbox::init(dir.path(), cfg.sandbox.clone()).unwrap(),
        );
        state.set_agent(crate::agent::AgentManager::init(&state, sb).await);
        crate::collect::pipeline().access.record(
            r#"203.0.113.9 - - [x] "GET /health HTTP/1.1" 200 2 "-" "-""#,
            now_ms(),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
        let c = reqwest::Client::new();

        let (sid, init) = mcp_call(&c, &url, None, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } } })).await;
        assert!(init["result"].is_object(), "{init}");
        let sid = sid.expect("session id");
        let _ = mcp_call(
            &c,
            &url,
            Some(&sid),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
        let (_, list) = mcp_call(
            &c,
            &url,
            Some(&sid),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        )
        .await;
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for n in [
            "get_health_snapshot",
            "list_alerts",
            "get_latest_report",
            "get_report",
            "list_findings",
        ]
        .iter()
        .chain(crate::agent::tools::MCP_SHARED)
        {
            assert!(names.contains(n), "{n} missing from {names:?}");
        }
        for n in ["run_python", "write_script", "export_log_sample"] {
            assert!(!names.contains(&n), "{n} must not be exposed");
        }
        let (_, call) = mcp_call(&c, &url, Some(&sid), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "get_access_stats", "arguments": { "window_mins": 5 } } })).await;
        let text = call["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("203.0.113.x"), "{call}");
        assert!(!text.contains("203.0.113.9"));
    }

    async fn mcp_tools(c: &reqwest::Client, url: &str, ops: Option<&str>) -> (u16, Vec<String>) {
        let mut req = c
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } } }));
        if let Some(t) = ops {
            req = req.header("x-tsm-ops-token", t);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let Some(sid) = r
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            return (status, vec![]);
        };
        let send = |body: Value| {
            let mut q = c
                .post(url)
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", &sid)
                .json(&body);
            if let Some(t) = ops {
                q = q.header("x-tsm-ops-token", t);
            }
            q.send()
        };
        let _ = send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await
            .unwrap();
        let text = send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let body = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|l| l.starts_with('{'))
            .map(str::to_string)
            .unwrap_or(text);
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let names = v["result"]["tools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|t| t["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        (status, names)
    }

    #[tokio::test]
    async fn ops_routes_and_mcp_ops_need_the_ops_token() {
        // SAFETY: unique variable names for this test.
        unsafe { std::env::set_var("TSM_TEST_OPS_TOKEN_A", "ops-token-0123456789") };
        let mut cfg = crate::config::Config::default();
        cfg.server.token_env = "TSM_TEST_API_TOKEN_UNSET".into();
        cfg.server.ops_token_env = "TSM_TEST_OPS_TOKEN_A".into();
        cfg.ops.helper_socket = "/nonexistent/helper.sock".into();
        let state = crate::state::AppState::new(
            std::sync::Arc::new(cfg),
            crate::store::open_memory().await,
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
        let c = reqwest::Client::new();
        let run = |tok: Option<&'static str>, body: Value| {
            let mut r = c.post(format!("{base}/api/v1/ops/run")).json(&body);
            if let Some(t) = tok {
                r = r.header("x-tsm-ops-token", t);
            }
            r.send()
        };
        let body =
            json!({ "call": "docker.container", "args": { "id": "web", "action": "restart" } });
        assert_eq!(run(None, body.clone()).await.unwrap().status(), 403);
        assert_eq!(
            run(Some("wrong-token-xxxxxxxx"), body.clone())
                .await
                .unwrap()
                .status(),
            403
        );
        // valid token but no helper: refused with the reason, and audited
        let r = run(Some("ops-token-0123456789"), body.clone())
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(r.text().await.unwrap().contains("运维助手"));
        let audit: Value = c
            .get(format!("{base}/api/v1/ops/audit"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(audit[0]["outcome"], "refused");
        // reads are not writes
        let r = run(
            Some("ops-token-0123456789"),
            json!({ "call": "docker.images" }),
        )
        .await
        .unwrap();
        assert_eq!(r.status(), 400);
        let caps: Value = c
            .get(format!("{base}/api/v1/ops/capabilities"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(caps["available"], false);
        assert_eq!(caps["write_ready"], false);

        // MCP: write tools never appear on /mcp, only on /mcp/ops behind the token
        let (_, read) = mcp_tools(&c, &format!("{base}/mcp"), None).await;
        assert!(read.contains(&"firewall_status".to_string()), "{read:?}");
        for w in [
            "docker_container_action",
            "nginx_write_file",
            "firewall_rule_add",
            "ssh_set_options",
            "revert_change",
        ] {
            assert!(!read.contains(&w.to_string()), "{w} exposed on /mcp");
        }
        assert!(!read.iter().any(|n| n == "confirm_change"));
        let (status, none) = mcp_tools(&c, &format!("{base}/mcp/ops"), None).await;
        assert_eq!(status, 403);
        assert!(none.is_empty());
        let (_, ops) =
            mcp_tools(&c, &format!("{base}/mcp/ops"), Some("ops-token-0123456789")).await;
        assert!(ops.contains(&"nginx_write_file".to_string()), "{ops:?}");
        assert!(ops.contains(&"firewall_status".to_string()));
        assert!(!ops.iter().any(|n| n.contains("confirm")));
    }

    #[tokio::test]
    async fn mcp_requires_api_token_when_configured() {
        unsafe { std::env::set_var("TSM_TEST_API_TOKEN_MCP", "api-token-x") };
        let base = serve("TSM_TEST_API_TOKEN_MCP").await;
        let r = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header("accept", "application/json, text/event-stream")
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn ops_end_to_end_through_a_real_helper() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nginx-root");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        std::fs::write(
            root.join("conf.d/app.conf"),
            "server { listen 80; server_name app; }",
        )
        .unwrap();
        let bin = dir.path().join("fake-nginx");
        std::fs::write(&bin, "#!/bin/sh\necho 'syntax is ok' >&2\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let me = unsafe { libc::getuid() };
        let mut hcfg: crate::helper::HelperConfig =
            toml::from_str(&format!("allowed_uids = [{me}]")).unwrap();
        hcfg.nginx.enabled = true;
        hcfg.nginx.root = root.clone();
        hcfg.nginx.binary = bin.to_string_lossy().into_owned();
        hcfg.nginx.allow = vec![
            crate::helper::config::NginxOp::Site,
            crate::helper::config::NginxOp::Test,
        ];
        let (socket, _hdir) = crate::helper::tests::spawn_helper(hcfg).await;

        unsafe { std::env::set_var("TSM_TEST_OPS_TOKEN_E2E", "ops-token-e2e-0123456") };
        let mut cfg = crate::config::Config::default();
        cfg.server.token_env = "TSM_TEST_API_TOKEN_UNSET".into();
        cfg.server.ops_token_env = "TSM_TEST_OPS_TOKEN_E2E".into();
        cfg.ops.helper_socket = socket;
        cfg.ops.secret_env = "TSM_TEST_HELPER_SECRET".into();
        cfg.ops.allow_without_sandbox = true;
        let state = crate::state::AppState::new(
            std::sync::Arc::new(cfg),
            crate::store::open_memory().await,
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
        let c = reqwest::Client::new();

        let caps: Value = c
            .get(format!("{base}/api/v1/ops/capabilities"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(caps["available"], true, "{caps}");
        assert_eq!(caps["write_ready"], true, "{caps}");
        let sites: Value = c
            .get(format!("{base}/api/v1/ops/read/nginx.sites"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(sites["source"], "helper");
        assert_eq!(sites["data"]["sites"][0]["enabled"], true);

        let job: Value = c
            .post(format!("{base}/api/v1/ops/run"))
            .header("x-tsm-ops-token", "ops-token-e2e-0123456")
            .json(&json!({ "call": "nginx.site", "args": { "name": "app", "enabled": false } }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(job["status"], "succeeded", "{job}");
        assert!(
            job["log"].as_str().unwrap().contains("nginx -t")
                || job["log"].as_str().unwrap().contains("fake-nginx"),
            "{job}"
        );
        assert!(root.join("conf.d/app.conf.disabled").exists());

        // an operation the helper does not allow
        let r = c
            .post(format!("{base}/api/v1/ops/run"))
            .header("x-tsm-ops-token", "ops-token-e2e-0123456")
            .json(&json!({ "call": "nginx.reload" }))
            .send()
            .await
            .unwrap();
        let job: Value = r.json().await.unwrap();
        assert_eq!(job["status"], "failed");
        assert!(job["error"].as_str().unwrap().contains("未允许"), "{job}");

        let audit: Value = c
            .get(format!("{base}/api/v1/ops/audit"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let outcomes: Vec<&str> = audit
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["outcome"].as_str())
            .collect();
        assert_eq!(outcomes, ["failed", "succeeded"]);
        assert_eq!(audit[1]["via"], "web");
    }
}
