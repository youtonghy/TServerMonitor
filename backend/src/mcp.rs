//! MCP (Streamable HTTP) endpoints for upper-layer agents.
//!
//! * `/mcp` is read-only: diagnostics, plus the inventory of nginx, firewall, SSH and Docker
//!   (secrets redacted). The analysis tools listed in `agent::tools::MCP_SHARED` run the same
//!   implementation the built-in agent uses; workspace/script tools are never exposed.
//! * `/mcp/ops` additionally registers the write tools. It sits behind the ops token
//!   (`X-TSM-Ops-Token`), every write is a dry run unless `dry_run: false` is passed, and
//!   everything goes through the root helper, which applies its own allow-list. Agents can
//!   revert pending firewall/SSH changes but never confirm them.

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
}

#[derive(Deserialize, JsonSchema)]
pub struct ProjectActionArgs {
    pub project: String,
    /// start | stop | restart
    pub action: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImagePullArgs {
    /// e.g. nginx:1.27 or ghcr.io/org/app:2.1
    pub reference: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImageRemoveArgs {
    /// image id or reference
    pub image: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct PruneArgs {
    /// images | volumes
    pub target: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct NameDryArgs {
    pub name: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct DryArgs {
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct SiteToggleArgs {
    pub name: String,
    pub enabled: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
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
}

#[derive(Deserialize, JsonSchema)]
pub struct RuleDeleteArgs {
    /// the rule's `spec` exactly as listed by firewall_status
    pub spec: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct ToggleArgs {
    pub enabled: bool,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct SshOptionsArgs {
    /// sshd options to set, e.g. {"PasswordAuthentication": "no"}; see ssh_get_config for the allowed keys
    pub options: std::collections::BTreeMap<String, String>,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct KeyAddArgs {
    pub user: String,
    /// one public key line, e.g. "ssh-ed25519 AAAA... comment"
    pub key: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct KeyRemoveArgs {
    pub user: String,
    /// SHA256:... as listed by ssh_list_keys
    pub fingerprint: String,
    #[serde(default = "yes")]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct ChangeIdArgs {
    /// id from list_pending_changes
    pub id: String,
}

fn op_err(e: crate::ops::proto::OpError) -> ErrorData {
    ErrorData::invalid_params(e.message, None)
}

/// Keeps the tail of a job log for the model.
fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = s.len() - max;
    while !s.is_char_boundary(cut) {
        cut += 1;
    }
    format!("…{}", &s[cut..])
}

impl McpServer {
    async fn read(&self, call: &str, args: serde_json::Value) -> Result<CallToolResult, ErrorData> {
        json_result(
            &crate::ops::read(&self.state, call, args)
                .await
                .map_err(op_err)?,
        )
    }

    /// Submits a change as `mcp`, waits for it, and returns status, result and log tail.
    async fn write(
        &self,
        ext: &rmcp::model::Extensions,
        call: &str,
        args: serde_json::Value,
        dry_run: bool,
    ) -> Result<CallToolResult, ErrorData> {
        let remote = ext
            .get::<axum::http::request::Parts>()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').next().unwrap_or(v).trim().to_string());
        let summary = crate::ops::calls::summary(call, &args);
        let id = crate::ops::submit(
            &self.state,
            crate::ops::Submit {
                call: call.into(),
                args,
                dry_run,
                summary,
                via: crate::ops::Via { via: "mcp", remote },
            },
        )
        .await
        .map_err(|e| match e.downcast::<crate::ops::proto::OpError>() {
            Ok(op) => op_err(op),
            Err(e) => internal(e),
        })?;
        let job = crate::ops::wait(&self.state, id, std::time::Duration::from_secs(120))
            .await
            .map_err(internal)?
            .ok_or_else(|| ErrorData::internal_error("job vanished", None))?;
        let out = serde_json::json!({
            "job_id": job.id,
            "status": job.status,
            "dry_run": job.dry_run,
            "error": job.error,
            "result": job.result,
            "log": tail(job.log.as_deref().unwrap_or(""), 6000),
            "note": if job.status == "running" { "still running; poll get_ops_job" } else { "" },
        });
        if job.status == "failed" {
            let text = serde_json::to_string(&out).unwrap_or_default();
            return Ok(CallToolResult::error(vec![
                rmcp::model::ContentBlock::text(text),
            ]));
        }
        json_result(&out)
    }
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
        self.write(&ext, call, serde_json::json!({}), a.dry_run)
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
        )
        .await
    }

    #[tool(
        description = "Run nginx -t (configuration test). Changes nothing.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn nginx_test(&self, ext: rmcp::model::Extensions) -> Result<CallToolResult, ErrorData> {
        self.write(&ext, "nginx.test", serde_json::json!({}), false)
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
        self.write(&ext, "nginx.reload", serde_json::json!({}), a.dry_run)
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
        self.write(&ext, "nginx.write", serde_json::json!({ "path": a.path, "content": a.content, "base_sha256": a.base_sha256 }), a.dry_run).await
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
        self.write(&ext, "firewall.add", args, a.dry_run).await
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
        )
        .await
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
        self.write(
            &ext,
            "pending.revert",
            serde_json::json!({ "id": a.id }),
            false,
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

const INSTRUCTIONS: &str = "Operations view of one server. Diagnostics: system status, log analysis, real-time access analysis, host metrics, containers, alerts, findings and reports. Inventory: Docker (containers, compose projects, images, volumes, networks), nginx sites and config files, firewall rules, sshd effective config, authorized keys and login sessions (secrets redacted). \
When connected to /mcp/ops, write tools are available as well. Every write tool is a dry run unless dry_run=false: call it once with the default to see the plan or diff, then repeat with dry_run=false. Changes run through a root helper that only permits what the host operator enabled. Firewall and sshd changes are applied provisionally and reverted automatically unless a person confirms them in the dashboard; you may call revert_change but cannot confirm. Before changing a file, read it with nginx_get_file and pass its sha256 as base_sha256; never write back redacted placeholders such as <redacted>.";
