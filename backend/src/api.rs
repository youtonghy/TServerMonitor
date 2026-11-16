//! HTTP API (read-only except the manual trigger), SSE stream, MCP endpoint and the embedded
//! dashboard. See `docs/api.md`.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
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
        Err(crate::agent::TriggerError::Busy(id)) => Err(ApiError(
            StatusCode::CONFLICT,
            format!("analysis {id} is already running"),
        )),
    }
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

// ---------------------------------------------------------------- static dashboard

async fn static_handler(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path == "mcp" {
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
        .nest_service("/mcp", crate::mcp::service(state.clone()))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), auth));
    api.fallback(static_handler).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
