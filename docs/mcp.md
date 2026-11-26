# Connecting an agent over MCP

TServerMonitor serves the Model Context Protocol over Streamable HTTP on the dashboard port.

| Endpoint | What it offers | Headers |
| --- | --- | --- |
| `/mcp` | Read-only: diagnostics, logs, access analysis, alerts, reports, and the server inventory (Docker, nginx, firewall, SSH), secrets redacted | `Authorization: Bearer <token>` with a `read` or `ops` API token |
| `/mcp/ops` | Everything on `/mcp` plus write tools for Docker, nginx, firewall and SSH | `Authorization: Bearer <token>` with an `ops` API token |

Create the tokens in the dashboard under **Settings → API 令牌** (shown once; revocable, optional
expiry). The deprecated `TSM_API_TOKEN` / `X-TSM-Ops-Token: $TSM_OPS_TOKEN` still work when set.

Give an agent `/mcp/ops` only if you would give it root on the host: what it can change is limited
by the ops helper's own config (`/etc/tsmonitor/helper.toml`), but Docker control and nginx config
editing are root-equivalent.

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

1. **Dry run by default.** Every write tool takes `dry_run` and defaults to `true`: the first call
   returns the plan (commands, or a unified diff for `nginx_write_file` and `ssh_set_options`)
   without changing anything. Call again with `dry_run: false` to apply.
2. **Jobs.** A write returns `{ job_id, status, dry_run, error, result, log }` after up to 120 s.
   Long jobs (an image pull) may still be `running`; poll `get_ops_job`.
3. **Files.** Read with `nginx_get_file`, edit, and pass its `sha256` as `base_sha256`. Values shown
   as `<redacted>` are secrets: content that still contains a placeholder is refused, so change only
   lines you can reproduce exactly, or ask the operator.
4. **Rollback.** nginx changes are tested (`nginx -t`), reloaded and probed; any failure restores the
   previous files byte for byte.
5. **Confirm-or-revert.** Firewall and sshd changes apply provisionally and return `result.pending`.
   A person must confirm them in the dashboard before the deadline, otherwise they revert. Agents
   can call `revert_change` but cannot confirm. `list_pending_changes` shows what is waiting.
6. **Guards.** Blocking SSH for every source, deleting the last rule that admits SSH, disabling all
   login methods, or turning off passwords without a usable key are refused.

Every call is recorded with `via = mcp` in the dashboard's ops log, and in the helper's journal.

## A typical session

```text
get_ops_capabilities                      -> which domains and operations this host allows
get_access_stats {window_mins: 15}        -> 5xx spike on GET /api/orders/<n>
docker_inventory                          -> shop-api-1 restarting
docker_container_action {container: "shop-api-1", action: "restart"}            (dry run)
docker_container_action {container: "shop-api-1", action: "restart", dry_run: false}
get_access_stats {window_mins: 5}         -> verify the error rate dropped
```
