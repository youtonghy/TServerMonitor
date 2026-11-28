# Connecting an agent over MCP

TServerMonitor serves the Model Context Protocol over Streamable HTTP on the dashboard port.

| Endpoint | What it offers | Headers |
| --- | --- | --- |
| `/mcp` | Read-only: diagnostics, logs, access analysis, alerts, reports, the built-in agent's conversations, scheduled tasks, prompts, notification channels, package jobs, the ops audit log, change requests, and the server inventory (Docker, nginx, firewall, SSH), secrets redacted | `Authorization: Bearer <token>` with a `read` or `ops` API token |
| `/mcp/ops` | Everything on `/mcp` plus write tools for Docker, nginx, firewall and SSH, and `request_change` for every other dashboard action (alerts, analyses, the built-in agent, tasks, prompts, package updates, notification tests). Real changes need a reason and, by default, a person's approval | `Authorization: Bearer <token>` with an `ops` API token |

Create the tokens in the dashboard under **Settings → API 令牌** (shown once; revocable, optional
expiry). The deprecated `TSM_API_TOKEN` / `X-TSM-Ops-Token: $TSM_OPS_TOKEN` still work when set.

Account management (users, API tokens, passwords), AI provider keys and notification channel secrets
are dashboard-only and never exposed over MCP.

Give an agent `/mcp/ops` only if you would give it root on the host once you approve a change: what
it can change is limited by the ops helper's own config (`/etc/tsmonitor/helper.toml`) and by the
approval policy, but Docker control and nginx config editing are root-equivalent.

## Example client configuration

Most MCP clients accept a URL plus headers. For example, a project-level `.mcp.json`
(`TSM_READ_TOKEN` / `TSM_AGENT_OPS_TOKEN` are environment variables holding API tokens you created; never paste tokens into the file):

```json
{
  "mcpServers": {
    "tsmonitor": {
      "type": "http",
      "url": "http://127.0.0.1:8787/mcp",
      "headers": { "Authorization": "Bearer ${TSM_READ_TOKEN}" }
    },
    "tsmonitor-ops": {
      "type": "http",
      "url": "http://127.0.0.1:8787/mcp/ops",
      "headers": { "Authorization": "Bearer ${TSM_AGENT_OPS_TOKEN}" }
    }
  }
}
```

Remote agents: keep the dashboard on loopback and reach it through an SSH tunnel
(`ssh -L 8787:127.0.0.1:8787 host`), or put it behind a TLS reverse proxy and add the public host
name to `[server] mcp_allowed_hosts` (the MCP transport rejects unknown `Host` headers).

## How write tools behave

1. **Dry run by default.** Every server write tool takes `dry_run` and defaults to `true`: the call
   returns the plan (commands, or a unified diff for `nginx_write_file`, `nginx_save_site` and `ssh_set_options`)
   without changing anything. Dry runs never need approval.
2. **Real changes are change requests.** With `dry_run: false` (or `request_change { action, args,
   reason }` for any action from `list_change_actions`) the agent must pass a `reason`: the problem,
   its evidence and the expected effect. The call returns `{ request_id, status, preview, ... }`:
   * `pending`: the action needs approval. Host changes are dry-run first and the plan or diff is
     attached as `preview`. A person approves or rejects it under **变更审批** in the dashboard
     (approving asks for their password again). Requests nobody decides expire after 30 minutes.
   * `executed` / `failed`: the action is set to run automatically, and already ran.
   Poll `get_change_request { id, wait_secs: 120 }` until the status is `executed`, `failed`,
   `rejected` (see `note_from_approver`) or `expired`. Never report a pending change as done.
3. **Approval policy.** Under **变更审批 → 批准策略** the operator chooses, per action, whether it
   needs approval. Defaults: every server change (Docker, nginx, firewall, SSH, package upgrades,
   task and prompt edits) needs approval; `nginx -t`, reverting a pending change, acknowledging,
   silencing or closing alerts, triggering an analysis, asking the built-in agent, running a task,
   checking package updates and sending a test notification run automatically. Changing the policy
   needs the password.
4. **Files.** Read with `nginx_get_file`, edit, and pass its `sha256` as `base_sha256`. Values shown
   as `<redacted>` are secrets: content that still contains a placeholder is refused, so change only
   lines you can reproduce exactly, or ask the operator.
   Sites marked `managed` in `nginx_list_sites` were created from the dashboard form: read them
   with `nginx_get_site`, change the `spec`, and save with `nginx_save_site` (pass its `sha256` as
   `base_sha256`); `nginx_issue_certificate` issues or renews an ACME certificate for them.
5. **Rollback.** nginx changes are tested (`nginx -t`), reloaded and probed; any failure restores the
   previous files byte for byte. `nginx_status` shows how nginx runs (package or the panel's Docker
   container) and its version; `nginx_upgrade` on a container tests the new image first and switches
   back automatically on failure (`nginx_rollback` returns to the previous image later), while an apt
   upgrade cannot be undone automatically.
6. **Confirm-or-revert.** Firewall and sshd changes, once approved, apply provisionally and return
   `result.pending`. A person must also confirm them in the dashboard before the deadline, otherwise
   they revert. Agents can call `revert_change` but cannot confirm. `list_pending_changes` shows what
   is waiting.
7. **Guards.** Blocking SSH for every source, deleting the last rule that admits SSH, disabling all
   login methods, or turning off passwords without a usable key are refused.

Every request is recorded under **变更审批** (with the reason and who approved it), and every server
change also appears with `via = mcp` in the dashboard's ops log and in the helper's journal.

The built-in agent uses the same mechanism: in a conversation (for example **让 Agent 修复** on a
report item) it can call `propose_change`, which files a request with `source = agent`. When a person
approves it, the result is posted back to that conversation and the agent checks the effect.

## A typical session

```text
get_ops_capabilities                      -> which domains and operations this host allows
get_access_stats {window_mins: 15}        -> 5xx spike on GET /api/orders/<n>
docker_inventory                          -> shop-api-1 restarting
docker_container_action {container: "shop-api-1", action: "restart"}            (dry run)
docker_container_action {container: "shop-api-1", action: "restart", dry_run: false,
                         reason: "restart loop since 10:02, 5xx on /api/orders"}  -> request_id 12, pending
get_change_request {id: 12, wait_secs: 120}  -> executed (a person approved it)
get_access_stats {window_mins: 5}         -> verify the error rate dropped
```
