//! MCP (Streamable HTTP) endpoints for upper-layer agents.
//!
//! * `/mcp` is read-only: diagnostics, plus the inventory of nginx, firewall, SSH and Docker
//!   (secrets redacted). The analysis tools listed in `agent::tools::MCP_SHARED` run the same
//!   implementation the built-in agent uses; workspace/script tools are never exposed.
//! * Both need an API token (`Authorization: Bearer tsm_...`) created in the dashboard.
//! * `/mcp/ops` additionally registers the write tools and needs a token with the `ops`
//!   scope; every write is a dry run unless `dry_run: false` is passed. A real change becomes
//!   a change request (`approvals`) with the caller's reason, which a person approves in the
//!   dashboard unless the operator set that action to run automatically. Host changes go
//!   through the root helper, which applies its own allow-list. Agents can revert pending
//!   firewall/SSH changes but never confirm them.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
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
    tool_router: ToolRouter<McpServer>,
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
            conversation: None,
            run_id: None,
        };
        match crate::agent::tools::execute(&ctx, name, &input).await {
            Ok(v) => json_result(&v),
            Err(e) => Err(ErrorData::invalid_params(format!("{e:#}"), None)),
        }
    }
}

#[tool_router(router = read_router)]
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

    #[tool(
        description = "Persisted nginx access history over a range (1h, 6h, 24h, 7d, 30d): request series with 4xx/5xx and P95 latency; for ranges up to 24h also latency percentiles, top and slowest paths, hosts, user-agent classes and suspicious (scanning) client addresses, masked.",
        annotations(read_only_hint = true)
    )]
    async fn get_access_history(
        &self,
        Parameters(a): Parameters<RangeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match crate::collect::access_history::history(
            &self.state.db,
            &a.range,
            crate::model::now_ms(),
            15,
            true,
        )
        .await
        .map_err(internal)?
        {
            Some(h) => json_result(&h),
            None => Err(ErrorData::invalid_params(
                "range must be 1h, 6h, 24h, 7d or 30d",
                None,
            )),
        }
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
        description = "Pending package updates (apt / dnf / Homebrew) with versions and whether they are security updates. Read-only; nothing is installed."
    )]
    async fn list_package_updates(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("list_package_updates", serde_json::json!({}))
            .await
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

    // ------------------------------------------------------------ management inventory (read)

    #[tool(
        description = "Ops capabilities of this host: whether the root helper runs, which domains (docker, nginx, firewall, ssh) and operations the operator enabled, dry-run mode and the confirm window.",
        annotations(read_only_hint = true)
    )]
    async fn get_ops_capabilities(&self) -> Result<CallToolResult, ErrorData> {
        json_result(&crate::ops::capabilities(&self.state).await)
    }

    #[tool(
        description = "Docker containers (all states) with compose project/service labels and protection flags, plus compose projects grouped by label.",
        annotations(read_only_hint = true)
    )]
    async fn docker_inventory(&self) -> Result<CallToolResult, ErrorData> {
        self.read("docker.containers", serde_json::json!({})).await
    }

    #[tool(
        description = "Docker images: id, tags, size, created, dangling.",
        annotations(read_only_hint = true)
    )]
    async fn docker_list_images(&self) -> Result<CallToolResult, ErrorData> {
        self.read("docker.images", serde_json::json!({})).await
    }

    #[tool(
        description = "Docker volumes and whether a container uses them.",
        annotations(read_only_hint = true)
    )]
    async fn docker_list_volumes(&self) -> Result<CallToolResult, ErrorData> {
        self.read("docker.volumes", serde_json::json!({})).await
    }

    #[tool(description = "Docker networks.", annotations(read_only_hint = true))]
    async fn docker_list_networks(&self) -> Result<CallToolResult, ErrorData> {
        self.read("docker.networks", serde_json::json!({})).await
    }

    #[tool(
        description = "nginx sites (sites-available/sites-enabled or conf.d layout): name, file, enabled, server_name, listen, TLS.",
        annotations(read_only_hint = true)
    )]
    async fn nginx_list_sites(&self) -> Result<CallToolResult, ErrorData> {
        self.read("nginx.sites", serde_json::json!({})).await
    }

    #[tool(
        description = "nginx config files (relative paths) and which ones are editable.",
        annotations(read_only_hint = true)
    )]
    async fn nginx_list_files(&self) -> Result<CallToolResult, ErrorData> {
        self.read("nginx.files", serde_json::json!({})).await
    }

    #[tool(
        description = "nginx itself: runtime (host package/binary, Docker container created by the panel, or none), version, compiled modules, running state, workers, systemd unit or container, apt installed/candidate versions, previous image for rollback, and why a Docker install is impossible.",
        annotations(read_only_hint = true)
    )]
    async fn nginx_status(&self) -> Result<CallToolResult, ErrorData> {
        self.read("nginx.status", serde_json::json!({})).await
    }

    #[tool(
        description = "nginx versions available as Docker image tags (newest first; channel stable = even minor, mainline = odd), for nginx_install and nginx_upgrade.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn nginx_versions(&self) -> Result<CallToolResult, ErrorData> {
        self.read("nginx.versions", serde_json::json!({})).await
    }

    #[tool(
        description = "Read one nginx config file by relative path, e.g. sites-available/shop. Secret values are replaced with <redacted>; sha256 is of the real file, pass it as base_sha256 when writing.",
        annotations(read_only_hint = true)
    )]
    async fn nginx_get_file(
        &self,
        Parameters(a): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut v = crate::ops::read(
            &self.state,
            "nginx.file",
            serde_json::json!({ "path": a.path }),
        )
        .await
        .map_err(op_err)?;
        if let Some(c) = v["data"]["content"].as_str() {
            v["data"]["content"] = crate::ops::redact_config(c).into();
        }
        json_result(&v)
    }

    #[tool(
        description = "Settings of a managed nginx site (created from the dashboard form): spec, file, enabled, sha256 (pass as base_sha256 to nginx_save_site), drifted (edited by hand) and certificate state.",
        annotations(read_only_hint = true)
    )]
    async fn nginx_get_site(
        &self,
        Parameters(a): Parameters<SiteNameArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut v = crate::ops::read(
            &self.state,
            "nginx.site_get",
            serde_json::json!({ "name": a.name }),
        )
        .await
        .map_err(op_err)?;
        if let Some(c) = v["data"]["spec"]["extra"].as_str() {
            v["data"]["spec"]["extra"] = crate::ops::redact_config(c).into();
        }
        json_result(&v)
    }

    #[tool(
        description = "Firewall status: backend (ufw, firewalld, nftables, iptables), active, default policy, rules with their delete spec, SSH ports and caveats.",
        annotations(read_only_hint = true)
    )]
    async fn firewall_status(&self) -> Result<CallToolResult, ErrorData> {
        self.read("firewall.status", serde_json::json!({})).await
    }

    #[tool(
        description = "sshd effective configuration (sshd -T subset), listening ports, options managed by the panel, and which options can be changed.",
        annotations(read_only_hint = true)
    )]
    async fn ssh_get_config(&self) -> Result<CallToolResult, ErrorData> {
        self.read("ssh.config", serde_json::json!({})).await
    }

    #[tool(
        description = "authorized_keys of every login user: key type, SHA256 fingerprint, comment (redacted) and whether it has restrictions.",
        annotations(read_only_hint = true)
    )]
    async fn ssh_list_keys(&self) -> Result<CallToolResult, ErrorData> {
        let mut v = crate::ops::read(&self.state, "ssh.keys", serde_json::json!({}))
            .await
            .map_err(op_err)?;
        if let Some(keys) = v["data"]["keys"].as_array_mut() {
            for k in keys {
                if let Some(c) = k["comment"].as_str() {
                    k["comment"] = crate::preprocess::redact(c).into();
                }
            }
        }
        json_result(&v)
    }

    #[tool(
        description = "Logged-in sessions (who), client addresses masked.",
        annotations(read_only_hint = true)
    )]
    async fn ssh_list_sessions(&self) -> Result<CallToolResult, ErrorData> {
        let mut s = crate::ops::sessions().await;
        for x in &mut s {
            x.from = x.from.as_deref().map(crate::collect::access::mask_ip);
        }
        json_result(&s)
    }

    #[tool(
        description = "Recent management jobs (newest first), optionally for one domain.",
        annotations(read_only_hint = true)
    )]
    async fn list_ops_jobs(
        &self,
        Parameters(a): Parameters<JobsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::ops::list_jobs(&self.state.db, a.domain.as_deref(), a.limit.unwrap_or(20))
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "One management job with its full log and result.",
        annotations(read_only_hint = true)
    )]
    async fn get_ops_job(
        &self,
        Parameters(a): Parameters<ReportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match crate::ops::get_job(&self.state.db, a.id)
            .await
            .map_err(internal)?
        {
            Some(j) => json_result(&j),
            None => Err(ErrorData::invalid_params("job not found", None)),
        }
    }

    #[tool(
        description = "Firewall/SSH changes applied provisionally and waiting for a person to confirm them in the dashboard (they revert automatically at the deadline).",
        annotations(read_only_hint = true)
    )]
    async fn list_pending_changes(&self) -> Result<CallToolResult, ErrorData> {
        json_result(&crate::ops::pending(&self.state).await)
    }

    // ------------------------------------------------------------ more diagnostics

    #[tool(
        description = "Recent stdout/stderr of one container (redacted).",
        annotations(read_only_hint = true)
    )]
    async fn get_container_logs(
        &self,
        Parameters(a): Parameters<ContainerLogsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("get_container_logs", args(&a)).await
    }

    #[tool(
        description = "Log sources (files and containers) with line and error counts and current rate.",
        annotations(read_only_hint = true)
    )]
    async fn list_log_sources(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("list_log_sources", serde_json::json!({})).await
    }

    #[tool(
        description = "Lines and errors per log source over time (bucketed).",
        annotations(read_only_hint = true)
    )]
    async fn get_log_rates(
        &self,
        Parameters(a): Parameters<LogRatesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.shared("get_log_rates", args(&a)).await
    }

    #[tool(
        description = "Listening ports and whether they are exposed beyond loopback.",
        annotations(read_only_hint = true)
    )]
    async fn list_ports(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("list_ports", serde_json::json!({})).await
    }

    #[tool(
        description = "Read-only database metrics (connections, QPS/TPS, slow queries, buffer hit rate, lock waits).",
        annotations(read_only_hint = true)
    )]
    async fn get_db_metrics(&self) -> Result<CallToolResult, ErrorData> {
        self.shared("get_db_metrics", serde_json::json!({})).await
    }

    #[tool(
        description = "List diagnostic reports (summaries, newest first), optionally of one kind.",
        annotations(read_only_hint = true)
    )]
    async fn list_reports(
        &self,
        Parameters(a): Parameters<ListReportsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let kind = match a.kind.as_deref().filter(|k| !k.is_empty()) {
            None => None,
            Some(k) => Some(
                crate::model::ReportKind::parse(k)
                    .ok_or_else(|| ErrorData::invalid_params("unknown report kind", None))?
                    .as_str(),
            ),
        };
        json_result(
            &store::list_reports(&self.state.db, kind, a.limit.unwrap_or(20))
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "Conversations of the built-in AI agent (kind: chat = started by people or agents, task = scheduled analyses), newest first.",
        annotations(read_only_hint = true)
    )]
    async fn list_conversations(
        &self,
        Parameters(a): Parameters<ListConversationsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        json_result(
            &store::list_conversations(&self.state.db, a.kind.as_deref(), a.limit.unwrap_or(20))
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "One conversation of the built-in agent with every run, step (tool calls, results, messages) and its change requests. Use it to read the answer to agent.ask.",
        annotations(read_only_hint = true)
    )]
    async fn get_conversation(
        &self,
        Parameters(a): Parameters<IdStrArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let conv = store::get_conversation(&self.state.db, &a.id)
            .await
            .map_err(internal)?
            .ok_or_else(|| ErrorData::invalid_params("conversation not found", None))?;
        let runs: Vec<serde_json::Value> = store::conversation_runs(&self.state.db, &a.id)
            .await
            .map_err(internal)?
            .into_iter()
            .map(|(run, steps)| serde_json::json!({ "run": run, "steps": steps }))
            .collect();
        let requests =
            crate::approvals::for_conversations(&self.state.db, std::slice::from_ref(&a.id))
                .await
                .map_err(internal)?;
        json_result(
            &serde_json::json!({ "conversation": conv, "runs": runs, "requests": requests }),
        )
    }

    #[tool(
        description = "Scheduled analysis tasks (trigger, prompt, last run) and the built-in system jobs.",
        annotations(read_only_hint = true)
    )]
    async fn list_tasks(&self) -> Result<CallToolResult, ErrorData> {
        json_result(&serde_json::json!({
            "tasks": crate::tasks::list(&self.state.db).await.map_err(internal)?,
            "system": crate::tasks::system_jobs(&self.state),
        }))
    }

    #[tool(
        description = "Prompt library used by scheduled tasks (built-in and custom).",
        annotations(read_only_hint = true)
    )]
    async fn list_prompts(&self) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::agent::library::list(&self.state.db)
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "Notification channels (Telegram, email, webhooks): kind, enabled, minimum severity, events. Secrets are never returned.",
        annotations(read_only_hint = true)
    )]
    async fn list_notify_channels(&self) -> Result<CallToolResult, ErrorData> {
        let list: Vec<crate::channels::ChannelView> = crate::channels::all(&self.state)
            .await
            .iter()
            .map(Into::into)
            .collect();
        json_result(&list)
    }

    #[tool(
        description = "Package update jobs (refresh / upgrade) with status, newest first.",
        annotations(read_only_hint = true)
    )]
    async fn list_package_jobs(&self) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::updater::list_jobs(&self.state.db)
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "One package update job with its log.",
        annotations(read_only_hint = true)
    )]
    async fn get_package_job(
        &self,
        Parameters(a): Parameters<ReportArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match crate::updater::get_job(&self.state.db, a.id)
            .await
            .map_err(internal)?
        {
            Some(j) => json_result(&j),
            None => Err(ErrorData::invalid_params("job not found", None)),
        }
    }

    #[tool(
        description = "Audit log of every change request to the ops helper (who, from where, what, outcome), newest first.",
        annotations(read_only_hint = true)
    )]
    async fn get_ops_audit(
        &self,
        Parameters(a): Parameters<LimitArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::ops::list_audit(&self.state.db, a.limit.unwrap_or(50))
                .await
                .map_err(internal)?,
        )
    }

    // ------------------------------------------------------------ change requests (read)

    #[tool(
        description = "Changes you can ask for with request_change (or the dedicated write tools on /mcp/ops): name, label, whether a person must approve it, and the argument format.",
        annotations(read_only_hint = true)
    )]
    async fn list_change_actions(&self) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::approvals::catalog_view(&self.state.db, false)
                .await
                .map_err(internal)?,
        )
    }

    #[tool(
        description = "Change requests (newest first): status open (default, waiting for approval), all, or one of pending|executed|failed|rejected|expired.",
        annotations(read_only_hint = true)
    )]
    async fn list_change_requests(
        &self,
        Parameters(a): Parameters<ListRequestsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let status = match a.status.as_deref() {
            None | Some("") | Some("open") => Some("open"),
            Some("all") => None,
            Some(s) => Some(s),
        };
        let list = crate::approvals::list(&self.state.db, status, a.limit.unwrap_or(20))
            .await
            .map_err(internal)?;
        json_result(&list.iter().map(request_view).collect::<Vec<_>>())
    }

    #[tool(
        description = "One change request. wait_secs (0-120) waits for it to be decided and run before answering.",
        annotations(read_only_hint = true)
    )]
    async fn get_change_request(
        &self,
        Parameters(a): Parameters<GetRequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let wait = std::time::Duration::from_secs(a.wait_secs.unwrap_or(0).min(120));
        match crate::approvals::wait(&self.state, a.id, wait)
            .await
            .map_err(internal)?
        {
            Some(r) => json_result(&request_view(&r)),
            None => Err(ErrorData::invalid_params("change request not found", None)),
        }
    }
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct ContainerLogsArgs {
    /// container name or id
    pub container: String,
    /// max lines, 1..500, default 200
    pub tail: Option<i64>,
    /// only lines that look like warnings or errors
    pub errors_only: Option<bool>,
}

#[derive(Deserialize, serde::Serialize, JsonSchema)]
pub struct LogRatesArgs {
    /// 1h | 6h | 24h | 7d | 30d
    pub range: String,
    pub source: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListReportsArgs {
    /// hourly | daily | incident | audit | custom
    pub kind: Option<String>,
    /// default 20
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListConversationsArgs {
    /// chat | task; omit for both
    pub kind: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct IdStrArgs {
    pub id: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct LimitArgs {
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListRequestsArgs {
    /// open (default) | all | pending | executed | failed | rejected | expired
    pub status: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GetRequestArgs {
    pub id: i64,
    /// wait up to this many seconds (max 120) for a decision and the result
    pub wait_secs: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RequestChangeArgs {
    /// action name from list_change_actions, e.g. alert.ack, task.run, packages.job
    pub action: String,
    /// arguments of the action (see list_change_actions)
    #[serde(default)]
    pub args: serde_json::Value,
    /// why: the problem, the evidence and the expected effect; shown to the approver
    pub reason: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct PathArgs {
    /// path relative to the nginx root, e.g. conf.d/app.conf
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct JobsArgs {
    /// docker | nginx | firewall | ssh | pending
    pub domain: Option<String>,
    pub limit: Option<i64>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
pub struct ContainerActionArgs {
    /// container name or id (as in docker_inventory)
    pub container: String,
    /// start | stop | restart | kill | remove
    pub action: String,
    /// default true: only report what would happen
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ProjectActionArgs {
    pub project: String,
    /// start | stop | restart
    pub action: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImagePullArgs {
    /// e.g. nginx:1.27 or ghcr.io/org/app:2.1
    pub reference: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImageRemoveArgs {
    /// image id or reference
    pub image: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PruneArgs {
    /// images | volumes
    pub target: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct NameDryArgs {
    pub name: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DryArgs {
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SiteToggleArgs {
    pub name: String,
    pub enabled: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SiteNameArgs {
    /// managed site name, as listed by nginx_list_sites (managed = true)
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct SiteSaveArgs {
    /// Site description, same shape as `spec` from nginx_get_site: { name, domains[],
    /// kind: proxy|static, proxy: { upstream, websocket, pass_host, timeout_secs },
    /// static: { root, index, spa }, listen: { http, https, ipv6 }, features: { force_https,
    /// http2, hsts, gzip, static_cache, access_log, client_max_body_mb }, ssl: { mode:
    /// none|acme|upload|path, cert_path, key_path }, extra }. Omitted fields take defaults.
    pub spec: serde_json::Value,
    /// sha256 from nginx_get_site; omit only to create a new site
    pub base_sha256: Option<String>,
    /// replace a managed config that was edited by hand
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SiteDeleteArgs {
    pub name: String,
    /// also delete the uploaded / issued certificate
    #[serde(default)]
    pub purge_certs: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct NginxServiceArgs {
    /// start | stop | restart
    pub action: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct NginxVersionArgs {
    /// image tag such as 1.27.3 (see nginx_versions)
    pub version: Option<String>,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CertIssueArgs {
    pub name: String,
    /// issue even if the current certificate is not due for renewal
    #[serde(default)]
    pub force: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct WriteFileArgs {
    /// path relative to the nginx root, inside an editable directory
    pub path: String,
    /// complete new file content
    pub content: String,
    /// sha256 from nginx_get_file; omit only for a new file
    pub base_sha256: Option<String>,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RuleAddArgs {
    /// allow | deny | reject | limit (limit: ufw only)
    pub action: String,
    /// port or range, e.g. 443 or 8000-8100
    pub port: String,
    /// tcp | udp | any (default any)
    pub proto: Option<String>,
    /// source address or CIDR; any source when omitted
    pub from: Option<String>,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RuleDeleteArgs {
    /// the rule's `spec` exactly as listed by firewall_status
    pub spec: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ToggleArgs {
    pub enabled: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SshOptionsArgs {
    /// sshd options to set, e.g. {"PasswordAuthentication": "no"}; see ssh_get_config for the allowed keys
    pub options: std::collections::BTreeMap<String, String>,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct KeyAddArgs {
    pub user: String,
    /// one public key line, e.g. "ssh-ed25519 AAAA... comment"
    pub key: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct KeyRemoveArgs {
    pub user: String,
    /// SHA256:... as listed by ssh_list_keys
    pub fingerprint: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// required when dry_run=false: why the change is needed, the evidence and the expected
    /// effect; shown to the person who approves it
    pub reason: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ChangeIdArgs {
    /// id from list_pending_changes
    pub id: String,
    pub reason: Option<String>,
}

fn op_err(e: crate::ops::proto::OpError) -> ErrorData {
    ErrorData::invalid_params(e.message, None)
}

impl McpServer {
    async fn read(&self, call: &str, args: serde_json::Value) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::ops::read(&self.state, call, args)
                .await
                .map_err(op_err)?,
        )
    }

    /// A write tool call: a dry run runs at once; a real change becomes a change request that
    /// a person approves in the dashboard (or that runs at once when its policy is `auto`).
    async fn write(
        &self,
        ext: &rmcp::model::Extensions,
        call: &str,
        args: serde_json::Value,
        dry_run: bool,
        reason: Option<String>,
    ) -> Result<CallToolResult, ErrorData> {
        if dry_run {
            let job = crate::approvals::run_host(
                &self.state,
                call,
                args,
                true,
                origin(ext).via(None),
                std::time::Duration::from_secs(120),
            )
            .await
            .map_err(request_err)?;
            let out = crate::approvals::job_view(&job);
            return if job.status == "failed" {
                Ok(CallToolResult::error(vec![
                    rmcp::model::ContentBlock::text(out.to_string()),
                ]))
            } else {
                json_result(&out)
            };
        }
        self.request(ext, call, args, reason.unwrap_or_default())
            .await
    }

    async fn request(
        &self,
        ext: &rmcp::model::Extensions,
        action: &str,
        args: serde_json::Value,
        reason: String,
    ) -> Result<CallToolResult, ErrorData> {
        let r = crate::approvals::request(&self.state, action, args, &reason, origin(ext))
            .await
            .map_err(request_err)?;
        let out = request_view(&r);
        if r.status == "failed" {
            return Ok(CallToolResult::error(vec![
                rmcp::model::ContentBlock::text(out.to_string()),
            ]));
        }
        json_result(&out)
    }
}

/// Who is calling, from the HTTP request behind the MCP session.
fn origin(ext: &rmcp::model::Extensions) -> crate::approvals::Origin {
    let parts = ext.get::<axum::http::request::Parts>();
    let remote = parts
        .and_then(|p| p.extensions.get::<crate::api::RemoteAddr>())
        .and_then(|r| r.0.clone());
    let actor = parts
        .and_then(|p| p.extensions.get::<crate::auth::Principal>())
        .map(|p| p.actor())
        .unwrap_or_else(|| "unknown".into());
    crate::approvals::Origin {
        source: "mcp",
        actor,
        remote,
        conversation_id: None,
        run_id: None,
    }
}

fn request_err(e: anyhow::Error) -> ErrorData {
    if let Some(i) = e.downcast_ref::<crate::settings::Invalid>() {
        return ErrorData::invalid_params(i.0.clone(), None);
    }
    match e.downcast::<crate::ops::proto::OpError>() {
        Ok(op) => op_err(op),
        Err(e) => internal(e),
    }
}

/// What an agent needs to know about its request.
fn request_view(r: &crate::approvals::ChangeRequest) -> serde_json::Value {
    let note = match r.status.as_str() {
        "pending" => {
            "waiting for a person to approve it in the dashboard; poll get_change_request (wait_secs up to 120)"
        }
        "approved" => "approved and running; poll get_change_request",
        "executed" => "done",
        "failed" => "failed; see error",
        "rejected" => "rejected by a person; see note",
        "expired" => "nobody approved it in time; ask again if still needed",
        _ => "",
    };
    serde_json::json!({
        "request_id": r.id,
        "action": r.action,
        "summary": r.summary,
        "status": r.status,
        "needs_approval": r.mode == "approve",
        "preview": r.preview,
        "result": r.result,
        "error": r.error,
        "note_from_approver": r.note,
        "decided_by": r.decided_by,
        "expires_at": r.expires_at,
        "next": note,
    })
}

#[tool_router(router = ops_router)]
impl McpServer {
    #[tool(
        description = "Start, stop, restart, kill or remove a Docker container (volumes are kept). Protected containers (socket proxy, TServerMonitor, operator-listed) can only be started. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn docker_container_action(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ContainerActionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "docker.container",
            serde_json::json!({ "id": a.container, "action": a.action }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Start, stop or restart every container of a docker compose project (found by label). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn docker_project_action(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ProjectActionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "docker.project",
            serde_json::json!({ "name": a.project, "action": a.action }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Pull a Docker image from its registry (public images only). Does not restart containers. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn docker_image_pull(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ImagePullArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "docker.image_pull",
            serde_json::json!({ "reference": a.reference }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Remove a Docker image. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn docker_image_remove(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ImageRemoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "docker.image_remove",
            serde_json::json!({ "id": a.image, "force": a.force }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Prune dangling images (target=images) or unused volumes (target=volumes; data is lost). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn docker_prune(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<PruneArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let call = match a.target.as_str() {
            "images" => "docker.image_prune",
            "volumes" => "docker.volume_prune",
            _ => {
                return Err(ErrorData::invalid_params(
                    "target must be images or volumes",
                    None,
                ));
            }
        };
        self.write(&ext, call, serde_json::json!({}), a.dry_run, a.reason)
            .await
    }

    #[tool(
        description = "Remove one Docker volume (data is lost). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn docker_volume_remove(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<NameDryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "docker.volume_remove",
            serde_json::json!({ "name": a.name }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Run nginx -t (configuration test). Changes nothing.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn nginx_test(&self, ext: rmcp::model::Extensions) -> Result<CallToolResult, ErrorData> {
        self.request(
            &ext,
            "nginx.test",
            serde_json::json!({}),
            "nginx -t 检查配置".into(),
        )
        .await
    }

    #[tool(
        description = "nginx -t, then reload nginx. Rolls back nothing (no files change). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn nginx_reload(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<DryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.reload",
            serde_json::json!({}),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Enable or disable an nginx site, then test and reload; rolled back if the test, reload or probe fails. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn nginx_site_toggle(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<SiteToggleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.site",
            serde_json::json!({ "name": a.name, "enabled": a.enabled }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Replace an nginx config file with new content; the dry run (default) returns a unified diff. On apply the file is backed up, nginx -t and reload run, and everything is restored on failure. Never send redacted placeholders.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn nginx_write_file(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if crate::ops::has_placeholder(&a.content) {
            return Err(ErrorData::invalid_params(
                "content contains a redaction placeholder (e.g. <redacted>); edit only the lines you need and keep the original secret values, or ask the operator to change them in the dashboard",
                None,
            ));
        }
        self.write(&ext, "nginx.write", serde_json::json!({ "path": a.path, "content": a.content, "base_sha256": a.base_sha256 }), a.dry_run, a.reason).await
    }

    #[tool(
        description = "Create or change a managed nginx site (reverse proxy or static files) from a structured spec; the helper renders the config from its template. The dry run (default) returns a unified diff. On apply: test, reload, probe, and everything is restored on failure. Static roots must lie under the host's allowed site roots; `extra` needs the edit permission; never send redacted placeholders.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn nginx_save_site(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<SiteSaveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if a.spec["extra"]
            .as_str()
            .is_some_and(crate::ops::has_placeholder)
        {
            return Err(ErrorData::invalid_params(
                "spec.extra contains a redaction placeholder (e.g. <redacted>); keep the original values or ask the operator to change them in the dashboard",
                None,
            ));
        }
        self.write(
            &ext,
            "nginx.site_save",
            serde_json::json!({ "spec": a.spec, "base_sha256": a.base_sha256, "overwrite": a.overwrite }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Delete a managed nginx site (config, link and stored settings), then test and reload; restored on failure. Manual sites are refused. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn nginx_delete_site(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<SiteDeleteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.site_delete",
            serde_json::json!({ "name": a.name, "purge_certs": a.purge_certs }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Issue (or renew) a certificate for a managed site whose SSL mode is acme, using ACME HTTP-01, then switch the site to HTTPS. Runs a local self-check first; can take a few minutes (poll the job). Skipped when the certificate is not due unless force=true. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn nginx_issue_certificate(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<CertIssueArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.cert_issue",
            serde_json::json!({ "name": a.name, "force": a.force }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Start, stop or restart nginx (systemd unit, binary or the panel's Docker container). Start/restart require nginx -t to pass and are probed afterwards. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn nginx_service(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<NginxServiceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.service",
            serde_json::json!({ "action": a.action }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Install nginx as a Docker container (official image, host networking) when the host has no nginx. Seeds /etc/nginx from the image if empty, tests the config with the new image first. Long-running (image pull). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn nginx_install(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<NginxVersionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let Some(v) = a.version else {
            return Err(ErrorData::invalid_params("version is required", None));
        };
        self.write(
            &ext,
            "nginx.install",
            serde_json::json!({ "version": v }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Upgrade nginx. Docker runtime: switch the container to image tag `version` (tested with nginx -t first, probed after, reverted automatically on failure). Host package: omit version; upgrades to the apt candidate, which cannot be rolled back automatically. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn nginx_upgrade(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<NginxVersionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = match a.version {
            Some(v) => serde_json::json!({ "version": v }),
            None => serde_json::json!({}),
        };
        self.write(&ext, "nginx.upgrade", args, a.dry_run, a.reason)
            .await
    }

    #[tool(
        description = "Docker runtime only: switch nginx back to the image it ran before the last upgrade (previous_image in nginx_status). Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn nginx_rollback(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<DryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "nginx.rollback",
            serde_json::json!({}),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Add a firewall rule (ufw/firewalld; nftables: deny/reject only). Blocking SSH for every source is refused. Applied provisionally: it reverts unless a person confirms it in the dashboard. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn firewall_rule_add(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<RuleAddArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let args = serde_json::json!({ "action": a.action, "port": a.port, "proto": a.proto.unwrap_or_else(|| "any".into()), "from": a.from });
        self.write(&ext, "firewall.add", args, a.dry_run, a.reason)
            .await
    }

    #[tool(
        description = "Delete a firewall rule by its spec from firewall_status. Deleting the last rule that admits SSH is refused. Provisional until confirmed by a person. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn firewall_rule_delete(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<RuleDeleteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "firewall.delete",
            serde_json::json!({ "spec": a.spec }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Enable or disable ufw. Enabling requires a rule admitting SSH. Provisional until confirmed by a person. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn firewall_toggle(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ToggleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "firewall.toggle",
            serde_json::json!({ "enabled": a.enabled }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Set sshd options through the panel's drop-in file (sshd -t and effective-config checks, lockout guards). Provisional until confirmed by a person. Dry run (default) returns the diff.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_set_options(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<SshOptionsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "ssh.set",
            serde_json::json!({ "options": a.options }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Add a public key to a login user's authorized_keys. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_key_add(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<KeyAddArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "ssh.key_add",
            serde_json::json!({ "user": a.user, "key": a.key }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Remove a public key (by fingerprint) from a user's authorized_keys; refused if it would leave no way to log in. Dry run unless dry_run=false.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn ssh_key_remove(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<KeyRemoveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write(
            &ext,
            "ssh.key_remove",
            serde_json::json!({ "user": a.user, "fingerprint": a.fingerprint }),
            a.dry_run,
            a.reason,
        )
        .await
    }

    #[tool(
        description = "Ask for any change in list_change_actions (alerts, analyses, the built-in agent, scheduled tasks, prompts, package updates, notification tests, and every server change). A reason is required. Actions that need approval wait for a person in the dashboard (host changes are dry-run first, so the request carries the plan or diff); the others run at once. Returns the request; poll get_change_request.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn request_change(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<RequestChangeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.request(&ext, &a.action, a.args, a.reason).await
    }

    #[tool(
        description = "Revert a pending (unconfirmed) firewall or SSH change now. Agents cannot confirm changes.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn revert_change(
        &self,
        ext: rmcp::model::Extensions,
        Parameters(a): Parameters<ChangeIdArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.request(
            &ext,
            "pending.revert",
            serde_json::json!({ "id": a.id }),
            a.reason.unwrap_or_else(|| "撤销待确认的变更".into()),
        )
        .await
    }
}

/// `ops = true` serves the read tools plus the write tools (mounted behind the ops token).
pub fn service(state: Shared, ops: bool) -> StreamableHttpService<McpServer, LocalSessionManager> {
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    hosts.extend(state.cfg.server.mcp_allowed_hosts.iter().cloned());
    StreamableHttpService::new(
        move || {
            let tool_router = if ops {
                McpServer::read_router() + McpServer::ops_router()
            } else {
                McpServer::read_router()
            };
            Ok(McpServer {
                state: state.clone(),
                tool_router,
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts),
    )
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info = Implementation::new("tsmonitor", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(INSTRUCTIONS.into());
        info
    }
}

const INSTRUCTIONS: &str = "Operations view of one server. Diagnostics: system status, log analysis, real-time access analysis, host metrics, containers, ports, databases, alerts, findings, reports and the built-in AI agent's conversations. Inventory: Docker (containers, compose projects, images, volumes, networks), nginx sites and config files, firewall rules, sshd effective config, authorized keys and login sessions (secrets redacted); scheduled tasks, prompts, notification channels, package jobs and the ops audit log. \
When connected to /mcp/ops, you can also ask for changes. Server write tools are a dry run unless dry_run=false: call once with the default to see the plan or diff. A real change (dry_run=false, or request_change for anything in list_change_actions) needs a `reason` (the problem, your evidence, the expected effect) and becomes a change request: unless the operator lets that action run automatically, a person approves or rejects it in the dashboard, so the call returns status=pending; poll get_change_request with wait_secs. Do not report a change as done until its status is executed. Changes run through a root helper that only permits what the host operator enabled. Firewall and sshd changes are additionally applied provisionally and reverted unless a person confirms them; you may call revert_change but cannot confirm. Before changing a file, read it with nginx_get_file and pass its sha256 as base_sha256; never write back redacted placeholders such as <redacted>. Sites marked managed in nginx_list_sites are generated from a form: change them with nginx_get_site and nginx_save_site instead of editing their file; certificate uploads are only possible in the dashboard.";
