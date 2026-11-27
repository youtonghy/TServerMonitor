//! HTTP API, SSE stream, MCP endpoint and the embedded dashboard. See `docs/api.md`.
//!
//! Reads (and the legacy manual trigger) use the optional bearer token. Everything that changes
//! settings or starts interactive work sits in the admin group, which additionally requires the
//! token to be configured at all and rejects cross-origin browser requests. Server management
//! (`/api/v1/ops/run`, `/mcp/ops`) sits in the ops group, which also requires the separate ops
//! token in `X-TSM-Ops-Token`; the change itself runs in the root ops helper.

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

/// Error with a machine-readable `code` (login_required, setup_required, sudo_required, ...).
pub struct Coded(StatusCode, &'static str, String);

impl IntoResponse for Coded {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.2, "code": self.1 }))).into_response()
    }
}

impl From<ApiError> for Coded {
    fn from(e: ApiError) -> Self {
        Coded(e.0, "error", e.1)
    }
}

impl From<anyhow::Error> for Coded {
    fn from(e: anyhow::Error) -> Self {
        ApiError::from(e).into()
    }
}

/// Client address for the audit log: the TCP peer, or the first X-Forwarded-For hop when the
/// peer is a local reverse proxy.
#[derive(Clone)]
pub struct RemoteAddr(pub Option<String>);

/// Whether the TCP peer is on this host (a local reverse proxy may then set forwarded headers).
#[derive(Clone, Copy)]
pub struct PeerLoopback(pub bool);

fn peer_ip(req: &Request) -> Option<std::net::IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip())
}

pub fn remote_of(req: &Request) -> Option<String> {
    let peer = peer_ip(req);
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

/// Runs for every API request: resolves the caller (session cookie, API token or the deprecated
/// environment tokens) and refuses cross-origin writes from browsers.
async fn identify(State(state): State<Shared>, mut req: Request, next: Next) -> Response {
    let principal = crate::auth::identify(&state, req.headers()).await;
    let writes = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    // cookies ride along on cross-site requests; machine tokens do not
    if writes && principal.as_ref().is_none_or(|p| p.is_user()) && !same_origin(req.headers()) {
        return Coded(
            StatusCode::FORBIDDEN,
            "cross_origin",
            "cross-origin request refused".into(),
        )
        .into_response();
    }
    let remote = remote_of(&req);
    let loopback = peer_ip(&req).is_some_and(|ip| ip.is_loopback());
    req.extensions_mut().insert(RemoteAddr(remote));
    req.extensions_mut().insert(PeerLoopback(loopback));
    if let Some(p) = principal {
        req.extensions_mut().insert(p);
    }
    next.run(req).await
}

fn principal_of(req: &Request) -> Option<&crate::auth::Principal> {
    req.extensions().get::<crate::auth::Principal>()
}

fn login_required(state: &Shared) -> Response {
    if crate::auth::setup_required(state) {
        Coded(
            StatusCode::UNAUTHORIZED,
            "setup_required",
            "请先完成初始化，创建管理员账号".into(),
        )
        .into_response()
    } else {
        Coded(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "需要登录".into(),
        )
        .into_response()
    }
}

/// Everything except the public auth endpoints and the static dashboard.
async fn require_login(State(state): State<Shared>, req: Request, next: Next) -> Response {
    if principal_of(&req).is_none() {
        return login_required(&state);
    }
    next.run(req).await
}

/// Account endpoints: a signed-in person, not a token.
async fn require_user(State(state): State<Shared>, req: Request, next: Next) -> Response {
    match principal_of(&req) {
        Some(p) if p.is_user() => next.run(req).await,
        Some(_) => Coded(
            StatusCode::FORBIDDEN,
            "user_required",
            "只能由登录的账号操作".into(),
        )
        .into_response(),
        None => login_required(&state),
    }
}

/// Changes to TServerMonitor's own settings: a signed-in account (or the deprecated
/// TSM_API_TOKEN).
async fn require_admin(State(state): State<Shared>, req: Request, next: Next) -> Response {
    match principal_of(&req) {
        Some(p) if p.can_admin() => next.run(req).await,
        Some(_) => Coded(
            StatusCode::FORBIDDEN,
            "forbidden",
            "API 令牌不能修改设置，请登录面板操作".into(),
        )
        .into_response(),
        None => login_required(&state),
    }
}

/// Server changes (web and `/mcp/ops`): an account that confirmed its password in the last
/// ten minutes, or an API token with the `ops` scope (or the deprecated TSM_OPS_TOKEN).
pub async fn require_ops(State(state): State<Shared>, req: Request, next: Next) -> Response {
    match principal_of(&req) {
        Some(p) if p.can_ops(now_ms()) => next.run(req).await,
        Some(p) if p.is_user() => Coded(
            StatusCode::FORBIDDEN,
            "sudo_required",
            "修改服务器前请先确认密码".into(),
        )
        .into_response(),
        Some(_) => Coded(
            StatusCode::FORBIDDEN,
            "scope_required",
            "需要 ops 范围的 API 令牌".into(),
        )
        .into_response(),
        None => login_required(&state),
    }
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
    let queued = state
        .agent()
        .is_some_and(|a| a.queued_conversations().contains(&conv.id));
    let requests =
        crate::approvals::for_conversations(&state.db, std::slice::from_ref(&conv.id)).await?;
    let mut v = serde_json::to_value(conv).map_err(anyhow::Error::from)?;
    v["runs"] = json!(runs);
    v["queued"] = json!(queued);
    v["requests"] = json!(requests);
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

/// Report sections a conversation can be about (`context.item.section`).
pub const REPORT_SECTIONS: &[&str] = &[
    "root_causes",
    "recommendations",
    "security_risks",
    "anomalies",
];

/// `{report_id, item: {section, index}, intent: explain|ask|fix}`: one item of a report.
fn report_item_context(obj: &serde_json::Map<String, Value>) -> bool {
    let item_ok = obj.get("item").is_none_or(|i| {
        i.as_object().is_some_and(|o| {
            o.len() == 2
                && o.get("section")
                    .and_then(Value::as_str)
                    .is_some_and(|s| REPORT_SECTIONS.contains(&s))
                && o.get("index")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n < 100)
        })
    });
    let intent_ok = obj.get("intent").is_none_or(|i| {
        i.as_str()
            .is_some_and(|s| matches!(s, "explain" | "ask" | "fix"))
    });
    obj.get("report_id").is_some_and(Value::is_i64)
        && obj
            .keys()
            .all(|k| matches!(k.as_str(), "report_id" | "item" | "intent"))
        && item_ok
        && intent_ok
}

/// Accepts exactly one of `report_id` (optionally with one of its items), `alert_id`, `run_id`
/// or `text` (a note such as a package list).
fn clean_context(ctx: &Value) -> Result<Value, ApiError> {
    let obj = ctx
        .as_object()
        .ok_or_else(|| bad_request("context 必须是对象"))?;
    let ok = report_item_context(obj)
        || obj.len() == 1
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
            "context 只能是 report_id（可附 item 与 intent）、alert_id、run_id 或 text 之一",
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

/// Conversations about a report and its items, with their change requests.
async fn get_report_conversations(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<Value> {
    let convs = store::report_conversations(&state.db, id).await?;
    let queued = state
        .agent()
        .map(|a| a.queued_conversations())
        .unwrap_or_default();
    let ids: Vec<String> = convs.iter().map(|c| c.id.clone()).collect();
    let requests = crate::approvals::for_conversations(&state.db, &ids).await?;
    let list: Vec<Value> = convs
        .into_iter()
        .map(|c| {
            let q = queued.contains(&c.id);
            let mut v = json!(c);
            v["queued"] = json!(q);
            v
        })
        .collect();
    Ok(Json(json!({ "conversations": list, "requests": requests })))
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
    let stopping = async move { state.shutdown_requested().await };
    let s = BroadcastStream::new(rx).filter_map(|ev| {
        // lagging subscribers just skip missed events
        let ev = ev.ok()?;
        Some(Ok(SseEvent::default()
            .event(ev.name())
            .data(ev.data().to_string())))
    });
    // an open dashboard would otherwise keep graceful shutdown waiting forever
    let s = futures::StreamExt::take_until(s, stopping);
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

// ---------------------------------------------------------------- change requests

#[derive(Deserialize)]
struct ApprovalsQ {
    /// open (default) | all | a single status
    status: Option<String>,
    limit: Option<i64>,
}

async fn get_approvals(
    State(state): State<Shared>,
    Query(q): Query<ApprovalsQ>,
) -> ApiResult<Value> {
    let status = match q.status.as_deref() {
        None | Some("") | Some("open") => Some("open"),
        Some("all") => None,
        Some(s) => Some(s),
    };
    Ok(Json(json!({
        "requests": crate::approvals::list(&state.db, status, q.limit.unwrap_or(100)).await?,
        "pending": crate::approvals::pending_count(&state.db).await?,
    })))
}

async fn get_approval(
    State(state): State<Shared>,
    Path(id): Path<i64>,
) -> ApiResult<crate::approvals::ChangeRequest> {
    crate::approvals::get(&state.db, id)
        .await?
        .map(Json)
        .ok_or_else(|| not_found("change request"))
}

async fn get_approval_policy(
    State(state): State<Shared>,
) -> ApiResult<Vec<crate::approvals::PolicyView>> {
    Ok(Json(crate::approvals::policies(&state.db).await?))
}

/// Approving runs the change: same bar as changing the server from the dashboard.
async fn post_approve(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(id): Path<i64>,
) -> AuthResult<crate::approvals::ChangeRequest> {
    need_sudo(&p)?;
    Ok(Json(
        crate::approvals::approve(&state, id, &p.actor()).await?,
    ))
}

#[derive(Deserialize, Default)]
struct RejectBody {
    note: Option<String>,
}

async fn post_reject(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(id): Path<i64>,
    body: Option<Json<RejectBody>>,
) -> AuthResult<crate::approvals::ChangeRequest> {
    let note = body.and_then(|b| b.0.note);
    Ok(Json(
        crate::approvals::reject(&state, id, &p.actor(), note.as_deref()).await?,
    ))
}

#[derive(Deserialize)]
struct PolicyBody {
    mode: String,
}

/// Loosening or tightening what agents may do without asking: password-confirmed accounts only.
async fn put_approval_policy(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(action): Path<String>,
    Json(b): Json<PolicyBody>,
) -> AuthResult<Vec<crate::approvals::PolicyView>> {
    need_sudo(&p)?;
    crate::approvals::set_policy(&state.db, &action, &b.mode, &p.actor()).await?;
    Ok(Json(crate::approvals::policies(&state.db).await?))
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
    axum::Extension(who): axum::Extension<crate::auth::Principal>,
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
                actor: who.actor(),
            },
        },
    )
    .await?;
    crate::ops::wait(&state, id, Duration::from_secs(20))
        .await?
        .map(Json)
        .ok_or_else(|| not_found("job"))
}

// ---------------------------------------------------------------- accounts

use crate::auth::{self as authn, Principal};

type AuthResult<T> = Result<Json<T>, Coded>;

fn user_of(p: &Principal) -> (i64, &str, &str) {
    match p {
        Principal::User {
            id,
            username,
            session,
            ..
        } => (*id, username.as_str(), session.as_str()),
        // require_user guarantees a session
        _ => (0, "", ""),
    }
}

fn need_sudo(p: &Principal) -> Result<(), Coded> {
    if p.can_ops(now_ms()) {
        Ok(())
    } else {
        Err(Coded(
            StatusCode::FORBIDDEN,
            "sudo_required",
            "此操作需要先确认密码".into(),
        ))
    }
}

fn with_cookie<T: serde::Serialize>(cookie: String, body: T) -> Response {
    ([(header::SET_COOKIE, cookie)], Json(body)).into_response()
}

async fn get_auth_state(State(state): State<Shared>, req: Request) -> Json<Value> {
    let p = principal_of(&req);
    let (user, kind, sudo_until) = match p {
        Some(Principal::User {
            id,
            username,
            sudo_until,
            ..
        }) => (
            json!({ "id": id, "username": username }),
            "session",
            *sudo_until,
        ),
        Some(Principal::Token { name, scope, .. }) => {
            (json!({ "token": name, "scope": scope }), "token", 0)
        }
        Some(Principal::Legacy { .. }) => (Value::Null, "legacy", 0),
        None => (Value::Null, "", 0),
    };
    Json(json!({
        "setup_required": authn::setup_required(&state),
        "authenticated": p.is_some(),
        "kind": if kind.is_empty() { Value::Null } else { json!(kind) },
        "user": user,
        "sudo_until": sudo_until,
    }))
}

#[derive(Deserialize)]
struct SetupBody {
    code: String,
    username: String,
    password: String,
}

async fn post_setup(
    State(state): State<Shared>,
    axum::Extension(remote): axum::Extension<RemoteAddr>,
    axum::Extension(lo): axum::Extension<PeerLoopback>,
    headers: HeaderMap,
    Json(b): Json<SetupBody>,
) -> Result<Response, Coded> {
    if !authn::setup_required(&state) {
        return Err(Coded(
            StatusCode::CONFLICT,
            "already_setup",
            "已经完成初始化".into(),
        ));
    }
    let remote = remote.0.unwrap_or_default();
    let id = authn::setup(&state, &b.code, &b.username, &b.password, &remote).await?;
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie = authn::create_session(&state, id, &remote, ua).await?;
    let secure = authn::secure_request(&state, &headers, lo.0);
    Ok(with_cookie(
        authn::session_cookie(&state, &cookie, secure),
        json!({ "ok": true }),
    ))
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn post_login(
    State(state): State<Shared>,
    axum::Extension(remote): axum::Extension<RemoteAddr>,
    axum::Extension(lo): axum::Extension<PeerLoopback>,
    headers: HeaderMap,
    Json(b): Json<LoginBody>,
) -> Result<Response, Coded> {
    if authn::setup_required(&state) {
        return Err(Coded(
            StatusCode::UNAUTHORIZED,
            "setup_required",
            "请先完成初始化".into(),
        ));
    }
    let remote = remote.0.unwrap_or_default();
    let user = authn::login(&state, &b.username, &b.password, &remote)
        .await
        .map_err(|e| {
            Coded(
                StatusCode::UNAUTHORIZED,
                "bad_credentials",
                ApiError::from(e).1,
            )
        })?;
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie = authn::create_session(&state, user.id, &remote, ua).await?;
    let secure = authn::secure_request(&state, &headers, lo.0);
    Ok(with_cookie(
        authn::session_cookie(&state, &cookie, secure),
        json!({ "user": { "id": user.id, "username": user.username } }),
    ))
}

async fn post_logout(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    axum::Extension(lo): axum::Extension<PeerLoopback>,
    headers: HeaderMap,
) -> Result<Response, Coded> {
    let (_, _, session) = user_of(&p);
    authn::delete_session(&state.db, session).await?;
    let secure = authn::secure_request(&state, &headers, lo.0);
    Ok(with_cookie(
        authn::session_cookie(&state, "", secure),
        json!({ "ok": true }),
    ))
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

async fn post_sudo(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    axum::Extension(remote): axum::Extension<RemoteAddr>,
    Json(b): Json<PasswordBody>,
) -> AuthResult<Value> {
    let (id, _, session) = user_of(&p);
    let until = authn::sudo(
        &state,
        id,
        session,
        &b.password,
        &remote.0.unwrap_or_default(),
    )
    .await?;
    Ok(Json(json!({ "sudo_until": until })))
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    current: String,
    new: String,
}

async fn post_password(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Json(b): Json<ChangePasswordBody>,
) -> AuthResult<Value> {
    let (id, _, session) = user_of(&p);
    authn::change_password(&state, id, session, &b.current, &b.new).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_sessions(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
) -> AuthResult<Vec<authn::SessionView>> {
    let (id, _, session) = user_of(&p);
    Ok(Json(authn::list_sessions(&state.db, id, session).await?))
}

async fn delete_session(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(sid): Path<String>,
) -> AuthResult<Value> {
    let (id, _, _) = user_of(&p);
    authn::revoke_session(&state.db, id, &sid).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_users(State(state): State<Shared>) -> AuthResult<Vec<authn::User>> {
    Ok(Json(authn::list_users(&state.db).await?))
}

#[derive(Deserialize)]
struct NewUserBody {
    username: String,
    password: String,
}

async fn post_user(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Json(b): Json<NewUserBody>,
) -> AuthResult<Value> {
    need_sudo(&p)?;
    let id = authn::create_user(&state.db, &b.username, &b.password).await?;
    tracing::info!("account {:?} created by {}", b.username, p.actor());
    Ok(Json(json!({ "id": id })))
}

async fn delete_user(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(id): Path<i64>,
) -> AuthResult<Value> {
    need_sudo(&p)?;
    let (me, _, _) = user_of(&p);
    authn::delete_user(&state.db, id, me).await?;
    tracing::info!("account {id} deleted by {}", p.actor());
    Ok(Json(json!({ "ok": true })))
}

async fn get_tokens(State(state): State<Shared>) -> AuthResult<Vec<authn::ApiToken>> {
    Ok(Json(authn::list_tokens(&state.db).await?))
}

#[derive(Deserialize)]
struct NewTokenBody {
    name: String,
    scope: String,
    expires_days: Option<i64>,
}

async fn post_token(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Json(b): Json<NewTokenBody>,
) -> AuthResult<Value> {
    need_sudo(&p)?;
    let scope = authn::Scope::parse(&b.scope)
        .ok_or_else(|| Coded::from(bad_request("scope 只能是 read 或 ops")))?;
    let (me, _, _) = user_of(&p);
    let (plain, record) =
        authn::create_token(&state.db, &b.name, scope, b.expires_days, me).await?;
    tracing::info!(
        "API token {:?} ({}) created by {}",
        record.name,
        record.scope,
        p.actor()
    );
    Ok(Json(json!({ "token": plain, "record": record })))
}

async fn delete_token(
    State(state): State<Shared>,
    axum::Extension(p): axum::Extension<Principal>,
    Path(id): Path<i64>,
) -> AuthResult<Value> {
    need_sudo(&p)?;
    authn::revoke_token(&state.db, id).await?;
    Ok(Json(json!({ "ok": true })))
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
    let public = Router::new()
        .route("/api/v1/auth/state", get(get_auth_state))
        .route("/api/v1/auth/setup", post(post_setup))
        .route("/api/v1/auth/login", post(post_login));
    let account = Router::new()
        .route("/api/v1/auth/logout", post(post_logout))
        .route("/api/v1/auth/sudo", post(post_sudo))
        .route("/api/v1/auth/password", post(post_password))
        .route("/api/v1/auth/sessions", get(get_sessions))
        .route(
            "/api/v1/auth/sessions/{id}",
            axum::routing::delete(delete_session),
        )
        .route("/api/v1/auth/users", get(get_users).post(post_user))
        .route(
            "/api/v1/auth/users/{id}",
            axum::routing::delete(delete_user),
        )
        .route("/api/v1/auth/tokens", get(get_tokens).post(post_token))
        .route("/api/v1/approvals/{id}/approve", post(post_approve))
        .route("/api/v1/approvals/{id}/reject", post(post_reject))
        .route(
            "/api/v1/approvals/policy/{action}",
            axum::routing::put(put_approval_policy),
        )
        .route(
            "/api/v1/auth/tokens/{id}",
            axum::routing::delete(delete_token),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_user,
        ));
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
        .route(
            "/api/v1/reports/{id}/conversations",
            get(get_report_conversations),
        )
        .route("/api/v1/approvals", get(get_approvals))
        .route("/api/v1/approvals/policy", get(get_approval_policy))
        .route("/api/v1/approvals/{id}", get(get_approval))
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
        .nest_service("/mcp", crate::mcp::service(state.clone(), false))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_login,
        ));
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
    public
        .merge(account)
        .merge(api)
        .merge(admin)
        .merge(ops)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            identify,
        ))
        .fallback(static_handler)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_context() {
        let ok = |v: Value| clean_context(&v).is_ok();
        assert!(ok(json!({ "report_id": 3 })));
        assert!(ok(json!({ "alert_id": 3 })));
        assert!(ok(
            json!({ "report_id": 3, "item": { "section": "recommendations", "index": 1 }, "intent": "fix" })
        ));
        assert!(ok(
            json!({ "report_id": 3, "item": { "section": "anomalies", "index": 0 } })
        ));
        assert!(!ok(
            json!({ "report_id": 3, "item": { "section": "summary", "index": 0 } })
        ));
        assert!(!ok(
            json!({ "report_id": 3, "item": { "section": "anomalies", "index": -1 } })
        ));
        assert!(!ok(json!({ "report_id": 3, "intent": "delete" })));
        assert!(!ok(json!({ "report_id": 3, "alert_id": 1 })));
        assert!(!ok(json!({ "alert_id": 3, "intent": "fix" })));
    }

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

    const PW: &str = "correct horse battery";

    struct App {
        base: String,
        state: Shared,
        _dir: tempfile::TempDir,
    }

    async fn app(edit: impl FnOnce(&mut crate::config::Config)) -> App {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.storage.data_dir = dir.path().to_path_buf();
        cfg.server.token_env = "TSM_TEST_API_TOKEN_UNSET".into();
        cfg.server.ops_token_env = "TSM_TEST_OPS_TOKEN_UNSET".into();
        edit(&mut cfg);
        let state = crate::state::AppState::new(
            std::sync::Arc::new(cfg),
            crate::store::open_memory().await,
        );
        crate::auth::init(&state).await.unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let st = state.clone();
        tokio::spawn(async move { axum::serve(l, router(st)).await.unwrap() });
        App {
            base,
            state,
            _dir: dir,
        }
    }

    /// Creates the account directly (no wizard) and signs in; returns the Cookie header value.
    async fn admin(a: &App) -> String {
        crate::auth::create_user(&a.state.db, "admin", PW)
            .await
            .unwrap();
        crate::auth::init(&a.state).await.unwrap();
        login(a, "admin", PW).await
    }

    async fn login(a: &App, user: &str, pw: &str) -> String {
        let r = reqwest::Client::new()
            .post(format!("{}/api/v1/auth/login", a.base))
            .json(&json!({ "username": user, "password": pw }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
        cookie_of(&r)
    }

    fn cookie_of(r: &reqwest::Response) -> String {
        let c = r
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict"),
            "{c}"
        );
        c.split(';').next().unwrap().to_string()
    }

    async fn code(r: reqwest::Response) -> (u16, String) {
        let s = r.status().as_u16();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        (s, v["code"].as_str().unwrap_or_default().to_string())
    }

    #[tokio::test]
    async fn event_stream_ends_on_shutdown() {
        let a = app(|_| {}).await;
        let cookie = admin(&a).await;
        let r = reqwest::Client::new()
            .get(format!("{}/api/v1/stream", a.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        a.state.request_shutdown();
        // the body only completes when the server ends the stream
        tokio::time::timeout(Duration::from_secs(5), r.text())
            .await
            .expect("SSE stream still open after shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn setup_wizard_login_and_logout() {
        let a = app(|_| {}).await;
        let c = reqwest::Client::new();
        let get = |path: &str, cookie: Option<&str>| {
            let mut r = c.get(format!("{}{path}", a.base));
            if let Some(k) = cookie {
                r = r.header(header::COOKIE, k);
            }
            r.send()
        };
        // before setup everything but the auth endpoints is closed
        assert_eq!(
            code(get("/api/v1/status", None).await.unwrap()).await,
            (401, "setup_required".into())
        );
        let st: Value = get("/api/v1/auth/state", None)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(st["setup_required"], true);
        assert_eq!(st["authenticated"], false);
        // the dashboard itself is still served
        assert_ne!(get("/", None).await.unwrap().status(), 401);

        let setup = |code: &str, user: &str| {
            c.post(format!("{}/api/v1/auth/setup", a.base))
                .json(&json!({ "code": code, "username": user, "password": PW }))
                .send()
        };
        assert_eq!(setup("WRONG", "admin").await.unwrap().status(), 400);
        let setup_code = std::fs::read_to_string(crate::auth::setup_code_path(&a.state)).unwrap();
        let r = setup(setup_code.trim(), "admin").await.unwrap();
        assert_eq!(r.status(), 200);
        let cookie = cookie_of(&r);
        assert_eq!(
            get("/api/v1/status", Some(&cookie)).await.unwrap().status(),
            200
        );
        let st: Value = get("/api/v1/auth/state", Some(&cookie))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(st["user"]["username"], "admin");
        assert_eq!(st["kind"], "session");
        // the wizard cannot run twice
        assert_eq!(
            setup(setup_code.trim(), "evil").await.unwrap().status(),
            409
        );

        let r = c
            .post(format!("{}/api/v1/auth/logout", a.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert!(
            r.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(
            code(get("/api/v1/status", Some(&cookie)).await.unwrap()).await,
            (401, "login_required".into())
        );
        // the old ?token= form is gone
        assert_eq!(
            get("/api/v1/stream?token=x", None).await.unwrap().status(),
            401
        );
        let r = c
            .post(format!("{}/api/v1/auth/login", a.base))
            .json(&json!({ "username": "admin", "password": "wrong password!" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        login(&a, "admin", PW).await;
    }

    #[tokio::test]
    async fn settings_writes_need_an_account_and_same_origin() {
        let a = app(|_| {}).await;
        let cookie = admin(&a).await;
        let c = reqwest::Client::new();
        let url = format!("{}/api/v1/settings/providers", a.base);
        assert_eq!(
            c.post(&url).json(&json!({})).send().await.unwrap().status(),
            401
        );
        let r = c
            .post(&url)
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "https://evil.example")
            .json(&json!({ "name": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(code(r).await, (403, "cross_origin".into()));
        // signed in and same origin: reaches validation
        let r = c
            .post(&url)
            .header(header::COOKIE, &cookie)
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
        bearer: Option<&str>,
        session: Option<&str>,
        body: Value,
    ) -> (u16, Option<String>, Value) {
        let mut req = c
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
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
        (
            status,
            sid,
            serde_json::from_str(&json).unwrap_or(Value::Null),
        )
    }

    async fn mcp_tools(c: &reqwest::Client, url: &str, bearer: Option<&str>) -> (u16, Vec<String>) {
        let (status, sid, _) = mcp_call(c, url, bearer, None, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } } })).await;
        let Some(sid) = sid else {
            return (status, vec![]);
        };
        let _ = mcp_call(
            c,
            url,
            bearer,
            Some(&sid),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
        let (_, _, v) = mcp_call(
            c,
            url,
            bearer,
            Some(&sid),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        )
        .await;
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

    async fn token(a: &App, cookie: &str, name: &str, scope: &str) -> String {
        let r = reqwest::Client::new()
            .post(format!("{}/api/v1/auth/tokens", a.base))
            .header(header::COOKIE, cookie)
            .json(&json!({ "name": name, "scope": scope }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        r.json::<Value>().await.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn sudo(a: &App, cookie: &str) {
        let r = reqwest::Client::new()
            .post(format!("{}/api/v1/auth/sudo", a.base))
            .header(header::COOKIE, cookie)
            .json(&json!({ "password": PW }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }

    #[tokio::test]
    async fn sudo_api_tokens_and_mcp_scopes() {
        let a = app(|cfg| cfg.ops.helper_socket = "/nonexistent/helper.sock".into()).await;
        let cookie = admin(&a).await;
        let c = reqwest::Client::new();
        let run = |auth: (&str, String)| {
            c.post(format!("{}/api/v1/ops/run", a.base))
                .header(auth.0, auth.1)
                .json(&json!({ "call": "docker.container", "args": { "id": "web", "action": "restart" } }))
                .send()
        };
        // server changes and token creation need a fresh password confirmation
        assert_eq!(
            code(
                run((header::COOKIE.as_str(), cookie.clone()))
                    .await
                    .unwrap()
            )
            .await,
            (403, "sudo_required".into())
        );
        let r = c
            .post(format!("{}/api/v1/auth/tokens", a.base))
            .header(header::COOKIE, &cookie)
            .json(&json!({ "name": "x", "scope": "read" }))
            .send()
            .await
            .unwrap();
        assert_eq!(code(r).await, (403, "sudo_required".into()));
        let r = c
            .post(format!("{}/api/v1/auth/sudo", a.base))
            .header(header::COOKIE, &cookie)
            .json(&json!({ "password": "not the password" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        sudo(&a, &cookie).await;
        // now allowed: refused only because no helper runs (and audited with the account name)
        let r = run((header::COOKIE.as_str(), cookie.clone()))
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(r.text().await.unwrap().contains("运维助手"));
        let audit: Value = c
            .get(format!("{}/api/v1/ops/audit", a.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(audit[0]["outcome"], "refused");
        assert_eq!(audit[0]["actor"], "admin");

        let read = token(&a, &cookie, "dashboard-reader", "read").await;
        let ops = token(&a, &cookie, "agent", "ops").await;
        let bearer = |t: &str| (header::AUTHORIZATION.as_str(), format!("Bearer {t}"));
        assert_eq!(
            c.get(format!("{}/api/v1/status", a.base))
                .bearer_auth(&read)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            code(run(bearer(&read)).await.unwrap()).await,
            (403, "scope_required".into())
        );
        // tokens cannot change settings or manage accounts
        let r = c
            .post(format!("{}/api/v1/settings/providers", a.base))
            .bearer_auth(&ops)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let r = c
            .get(format!("{}/api/v1/auth/tokens", a.base))
            .bearer_auth(&ops)
            .send()
            .await
            .unwrap();
        assert_eq!(code(r).await, (403, "user_required".into()));
        assert_eq!(run(bearer(&ops)).await.unwrap().status(), 403); // no helper, but past the gate

        // MCP: nothing without a token, writes only for ops tokens on /mcp/ops
        let (status, none) = mcp_tools(&c, &format!("{}/mcp", a.base), None).await;
        assert_eq!((status, none.len()), (401, 0));
        let (_, read_tools) = mcp_tools(&c, &format!("{}/mcp", a.base), Some(&read)).await;
        assert!(
            read_tools.contains(&"firewall_status".to_string()),
            "{read_tools:?}"
        );
        for w in [
            "docker_container_action",
            "nginx_write_file",
            "nginx_save_site",
            "nginx_delete_site",
            "nginx_issue_certificate",
            "firewall_rule_add",
            "ssh_set_options",
            "revert_change",
        ] {
            assert!(!read_tools.contains(&w.to_string()), "{w} exposed on /mcp");
        }
        let (status, _) = mcp_tools(&c, &format!("{}/mcp/ops", a.base), Some(&read)).await;
        assert_eq!(status, 403);
        let (_, ops_tools) = mcp_tools(&c, &format!("{}/mcp/ops", a.base), Some(&ops)).await;
        assert!(
            ops_tools.contains(&"nginx_write_file".to_string())
                && ops_tools.contains(&"nginx_save_site".to_string()),
            "{ops_tools:?}"
        );
        assert!(read_tools.contains(&"nginx_get_site".to_string()));
        assert!(!ops_tools.iter().any(|n| n.contains("upload")));
        assert!(!ops_tools.iter().any(|n| n.contains("confirm")));

        // revoked tokens stop working
        let list: Value = c
            .get(format!("{}/api/v1/auth/tokens", a.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = list
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "dashboard-reader")
            .unwrap()["id"]
            .as_i64()
            .unwrap();
        let r = c
            .delete(format!("{}/api/v1/auth/tokens/{id}", a.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            c.get(format!("{}/api/v1/status", a.base))
                .bearer_auth(&read)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }

    #[tokio::test]
    async fn deprecated_env_tokens_still_work() {
        // SAFETY: unique variable names for this test.
        unsafe { std::env::set_var("TSM_TEST_API_TOKEN_LEGACY", "legacy-api-token") };
        unsafe { std::env::set_var("TSM_TEST_OPS_TOKEN_LEGACY", "legacy-ops-token-0123") };
        let a = app(|cfg| {
            cfg.server.token_env = "TSM_TEST_API_TOKEN_LEGACY".into();
            cfg.server.ops_token_env = "TSM_TEST_OPS_TOKEN_LEGACY".into();
        })
        .await;
        let c = reqwest::Client::new();
        assert_eq!(
            c.get(format!("{}/api/v1/status", a.base))
                .bearer_auth("legacy-api-token")
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let r = c
            .post(format!("{}/api/v1/settings/providers", a.base))
            .bearer_auth("legacy-api-token")
            .json(&json!({ "name": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let (_, tools) = mcp_tools(&c, &format!("{}/mcp", a.base), Some("legacy-api-token")).await;
        assert!(!tools.is_empty());
        assert_eq!(
            c.get(format!("{}/api/v1/status", a.base))
                .bearer_auth("wrong")
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }

    #[tokio::test]
    async fn mcp_lists_shared_tools_without_workspace_tools() {
        let a = app(|_| {}).await;
        let dir = tempfile::tempdir().unwrap();
        let sb = std::sync::Arc::new(
            crate::sandbox::Sandbox::init(dir.path(), a.state.cfg.sandbox.clone()).unwrap(),
        );
        a.state
            .set_agent(crate::agent::AgentManager::init(&a.state, sb).await);
        let cookie = admin(&a).await;
        sudo(&a, &cookie).await;
        let read = token(&a, &cookie, "reader", "read").await;
        crate::collect::pipeline().access.record(
            r#"203.0.113.9 - - [x] "GET /health HTTP/1.1" 200 2 "-" "-""#,
            now_ms(),
        );
        let c = reqwest::Client::new();
        let url = format!("{}/mcp", a.base);
        let (_, names) = mcp_tools(&c, &url, Some(&read)).await;
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
            assert!(names.iter().any(|x| x == n), "{n} missing from {names:?}");
        }
        for n in ["run_python", "write_script", "export_log_sample"] {
            assert!(!names.iter().any(|x| x == n), "{n} must not be exposed");
        }
        let (_, sid, _) = mcp_call(&c, &url, Some(&read), None, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } } })).await;
        let sid = sid.unwrap();
        let _ = mcp_call(
            &c,
            &url,
            Some(&read),
            Some(&sid),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
        let (_, _, call) = mcp_call(&c, &url, Some(&read), Some(&sid), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "get_access_stats", "arguments": { "window_mins": 5 } } })).await;
        let text = call["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("203.0.113.x"), "{call}");
        assert!(!text.contains("203.0.113.9"));
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

        let a = app(move |cfg| {
            cfg.ops.helper_socket = socket;
            cfg.ops.secret_env = "TSM_TEST_HELPER_SECRET".into();
            cfg.ops.allow_without_sandbox = true;
        })
        .await;
        let cookie = admin(&a).await;
        let c = reqwest::Client::new();
        let get = |path: &str| {
            c.get(format!("{}{path}", a.base))
                .header(header::COOKIE, &cookie)
                .send()
        };

        let caps: Value = get("/api/v1/ops/capabilities")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(caps["available"], true, "{caps}");
        assert_eq!(caps["write_ready"], true, "{caps}");
        let sites: Value = get("/api/v1/ops/read/nginx.sites")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(sites["source"], "helper");
        assert_eq!(sites["data"]["sites"][0]["enabled"], true);

        sudo(&a, &cookie).await;
        let run = |body: Value| {
            c.post(format!("{}/api/v1/ops/run", a.base))
                .header(header::COOKIE, &cookie)
                .json(&body)
                .send()
        };
        let job: Value =
            run(json!({ "call": "nginx.site", "args": { "name": "app", "enabled": false } }))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(job["status"], "succeeded", "{job}");
        assert_eq!(job["actor"], "admin");
        assert!(root.join("conf.d/app.conf.disabled").exists());

        // an operation the helper does not allow
        let job: Value = run(json!({ "call": "nginx.reload" }))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(job["status"], "failed");
        assert!(job["error"].as_str().unwrap().contains("未允许"), "{job}");

        let audit: Value = get("/api/v1/ops/audit")
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
        assert_eq!(audit[1]["actor"], "admin");
    }
}
