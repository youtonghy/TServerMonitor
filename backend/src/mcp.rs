//! MCP (Streamable HTTP) endpoint so upper-layer agents (e.g. Harms) can pull diagnostics.
//! All tools are read-only. Besides the report/alert tools, the analysis tools listed in
//! `agent::tools::MCP_SHARED` run the same implementation the built-in agent uses (client
//! addresses are masked); the workspace/script tools are never exposed here.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::state::Shared;
use crate::{alerts, store};

#[derive(Clone)]
pub struct McpServer {
    state: Shared,
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct ListAlertsArgs {
    /// "open" (default) or "all"
    pub status: Option<String>,
    /// max items, default 50
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LatestReportArgs {
    /// hourly | daily | incident | audit; omit for any kind
    pub kind: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReportArgs {
    pub id: i64,
}

fn json_result<T: serde::Serialize>(v: &T) -> Result<CallToolResult, ErrorData> {
    let text =
        serde_json::to_string(v).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![
        rmcp::model::ContentBlock::text(text),
    ]))
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct AnalyzeLogsArgs {
    /// time range in hours, default 1 (max 168)
    pub since_hours: Option<f64>,
    /// only this log source
    pub source: Option<String>,
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct AccessArgs {
    /// last N minutes, 1..60, default 15
    pub window_mins: Option<i64>,
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct RangeArgs {
    /// 1h | 6h | 24h | 7d | 30d
    pub range: String,
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct ClusterArgs {
    pub source: Option<String>,
    /// error | warning | info | slow
    pub level: Option<String>,
    /// keyword contained in the template
    pub query: Option<String>,
    pub since_hours: Option<f64>,
    /// max items, default 20
    pub limit: Option<i64>,
}

/// Drops `null` fields so the agent tool's strict argument parsing accepts the input.
fn args<T: serde::Serialize>(a: &T) -> serde_json::Value {
    let mut v = serde_json::to_value(a).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.retain(|_, x| !x.is_null());
    }
    v
}

fn internal(e: anyhow::Error) -> ErrorData {
    tracing::warn!("mcp tool error: {e:#}");
    ErrorData::internal_error("internal error", None)
}

impl McpServer {
    async fn shared(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<CallToolResult, ErrorData> {
        debug_assert!(crate::agent::tools::MCP_SHARED.contains(&name));
        let agent = self
            .state
            .agent()
            .ok_or_else(|| ErrorData::internal_error("not ready", None))?;
        let ctx = crate::agent::tools::ToolCtx {
            state: &self.state,
            sandbox: agent.sandbox(),
        };
        match crate::agent::tools::execute(&ctx, name, &input).await {
            Ok(v) => json_result(&v),
            Err(e) => Err(ErrorData::invalid_params(format!("{e:#}"), None)),
        }
    }
}

#[tool_router]
impl McpServer {
    #[tool(
        description = "System status analysis: live host metrics, health score per dimension, operating mode, containers, open alert counts and the latest report."
    )]
    async fn get_system_status(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("get_system_status", serde_json::json!({}))
            .await
    }

    #[tool(
        description = "Log analysis: per-source rates, top error/warning/slow templates (redacted) and error trends for the last N hours."
    )]
    async fn analyze_logs(
        &self,
        Parameters(a): Parameters<AnalyzeLogsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("analyze_logs", args(&a)).await
    }

    #[tool(
        description = "Real-time access analysis from nginx access logs: requests per minute, status classes, 5xx ratio, bytes, busiest paths and client addresses (masked)."
    )]
    async fn get_access_stats(
        &self,
        Parameters(a): Parameters<AccessArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("get_access_stats", args(&a)).await
    }

    #[tool(description = "Host metric statistics (min/avg/max/p95/latest) over a range.")]
    async fn get_host_metrics(
        &self,
        Parameters(a): Parameters<RangeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("get_host_metrics", args(&a)).await
    }

    #[tool(description = "Search folded log templates by source, level and keyword.")]
    async fn search_log_clusters(
        &self,
        Parameters(a): Parameters<ClusterArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("search_log_clusters", args(&a)).await
    }

    #[tool(
        description = "Docker containers with resource use, restarts, OOM and health, plus 24h container events."
    )]
    async fn list_containers(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("list_containers", serde_json::json!({})).await
    }

    #[tool(
        description = "Current server health snapshot: host metrics, health score, mode, container summary, open alert counts, AI status and the latest report summary."
    )]
    async fn get_health_snapshot(&self) -> Result<CallToolResult, ErrorData> {
        json_result(&crate::api::snapshot(&self.state).await.map_err(internal)?)
    }

    #[tool(description = "List alerts, newest first.")]
    async fn list_alerts(
        &self,
        Parameters(a): Parameters<ListAlertsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let open_only = a.status.as_deref() != Some("all");
        json_result(
            &alerts::list(&self.state.db, open_only, a.limit.unwrap_or(50))
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "Latest diagnostic report (health score, root causes, security risks, recommendations)."
    )]
    async fn get_latest_report(
        &self,
        Parameters(a): Parameters<LatestReportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let kind = a
            .kind
            .as_deref()
            .and_then(crate::model::ReportKind::parse)
            .map(|k| k.as_str());
        match store::get_report(&self.state.db, None, kind)
            .await
            .map_err(internal)?
        {
            Some(r) => json_result(&r),
            None => Err(ErrorData::invalid_params("no report yet", None)),
        }
    }

    #[tool(description = "Get one diagnostic report by id.")]
    async fn get_report(
        &self,
        Parameters(a): Parameters<ReportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match store::get_report(&self.state.db, Some(a.id), None)
            .await
            .map_err(internal)?
        {
            Some(r) => json_result(&r),
            None => Err(ErrorData::invalid_params("report not found", None)),
        }
    }

    #[tool(
        description = "Open security and configuration findings (exposed ports, brute force, pending updates, kernel and SSH settings)."
    )]
    async fn list_findings(&self) -> Result<CallToolResult, ErrorData> {
        json_result(
            &store::list_findings(&self.state.db, false)
                .await
                .map_err(internal)?,
        )
    }
}

pub fn service(state: Shared) -> StreamableHttpService<McpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || {
            Ok(McpServer {
                state: state.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info = Implementation::new("tsmonitor", env!("CARGO_PKG_VERSION"));
        info.instructions = Some("Read-only diagnostics of one server: system status, log analysis, real-time access analysis, host metrics, containers, alerts, findings and AI/rule reports.".into());
        info
    }
}
