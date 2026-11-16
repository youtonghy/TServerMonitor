//! MCP (Streamable HTTP) endpoint so upper-layer agents (e.g. Harms) can pull diagnostics.
//! All tools are read-only.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::state::Shared;
use crate::{alerts, store};

#[derive(Clone)]
pub struct McpServer {
    state: Shared,
}

#[derive(Deserialize, JsonSchema)]
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

fn internal(e: anyhow::Error) -> ErrorData {
    tracing::warn!("mcp tool error: {e:#}");
    ErrorData::internal_error("internal error", None)
}

#[tool_router(server_handler)]
impl McpServer {
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
