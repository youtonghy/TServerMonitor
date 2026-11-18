//! AI analysis hub. Rust owns scheduling, tools, validation and persistence; a Node.js sidecar
//! running the Vercel AI SDK only talks to the model. They speak newline-delimited JSON over
//! stdio:
//!
//! ```text
//! sidecar -> {"type":"ready"}
//! rust    -> {"type":"run", run_id, system, prompt, model:{format,base_url,model,api_key_env,auth,effort}, max_steps, tools:[...], output_schema}
//! sidecar -> {"type":"tool_call", run_id, call_id, name, input}
//! rust    -> {"type":"tool_result", run_id, call_id, output, is_error}
//! sidecar -> {"type":"step", run_id, text}
//! sidecar -> {"type":"result", run_id, output, usage} | {"type":"error", run_id, message}
//! ```
//! API keys reach the sidecar only through its environment, never through the protocol.

pub mod prompt;
pub mod tools;

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::model::{AgentStep, AiStatus, Diagnosis, Event, ReportKind, now_ms};
use crate::sandbox::Sandbox;
use crate::settings::{ResolvedModel, auth_str, format_str};
use crate::state::{AppState, Shared};
use crate::store;

#[derive(rust_embed::Embed)]
#[folder = "../agent-sidecar/dist/"]
#[allow_missing = true]
struct SidecarAsset;

#[derive(Debug, thiserror::Error)]
pub enum TriggerError {
    #[error("an analysis is already running ({0})")]
    Busy(String),
}

struct Sidecar {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    rx: mpsc::Receiver<Value>,
    last_used: Instant,
    /// Settings generation the environment was built from; a mismatch forces a respawn.
    generation: u64,
}

impl Sidecar {
    async fn send(&mut self, msg: &Value) -> Result<()> {
        let mut line = msg.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .context("writing to AI sidecar")?;
        self.stdin.flush().await?;
        Ok(())
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Step body; `seq` and `ts` are filled in by `record`.
fn draft(
    kind: &str,
    tool: Option<&str>,
    input: Option<Value>,
    output: Option<Value>,
    text: Option<String>,
) -> AgentStep {
    AgentStep {
        seq: 0,
        ts: 0,
        kind: kind.into(),
        tool: tool.map(str::to_string),
        input,
        output,
        text,
    }
}

pub struct AgentManager {
    state: Weak<AppState>,
    sandbox: Arc<Sandbox>,
    node: Option<PathBuf>,
    script: Option<PathBuf>,
    static_reason: Option<String>,
    proc: tokio::sync::Mutex<Option<Sidecar>>,
    running: Mutex<Option<String>>,
    /// Scheduled work postponed while the host is busy.
    deferred: Mutex<Vec<(ReportKind, String)>>,
}

async fn node_version(bin: &str) -> Option<(PathBuf, u32)> {
    let path = crate::sandbox::which(bin)?;
    let out = tokio::process::Command::new(&path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout);
    let major = v
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()?;
    Some((path, major))
}

fn materialize_script(state: &AppState) -> Option<PathBuf> {
    if let Some(p) = &state.cfg.ai.sidecar_path {
        return p.is_file().then(|| p.clone());
    }
    let asset = SidecarAsset::get("sidecar.mjs")?;
    let dir = state.cfg.storage.data_dir.join("sidecar");
    let path = dir.join("sidecar.mjs");
    let current = std::fs::read(&path).ok();
    if current.as_deref() != Some(asset.data.as_ref())
        && let Err(e) =
            std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, asset.data.as_ref()))
    {
        tracing::error!("writing AI sidecar script: {e}");
        return None;
    }
    Some(path)
}

impl AgentManager {
    pub async fn init(state: &Shared, sandbox: Arc<Sandbox>) -> Arc<Self> {
        let cfg = &state.cfg.ai;
        let node = node_version(&cfg.node_bin).await;
        let script = materialize_script(state);
        let static_reason = if !cfg.enabled {
            Some("AI 分析已在配置中关闭".to_string())
        } else if node.is_none() {
            Some(format!(
                "未找到 Node.js（node_bin = {}），AI 子进程无法启动",
                cfg.node_bin
            ))
        } else if node.as_ref().is_some_and(|(_, v)| *v < 20) {
            Some(format!(
                "Node.js 版本过低（v{}），需要 20 以上",
                node.as_ref().map(|n| n.1).unwrap_or(0)
            ))
        } else if script.is_none() {
            Some("未找到 AI 子进程脚本，请先构建 agent-sidecar".to_string())
        } else {
            None
        };
        if let Some(r) = &static_reason {
            tracing::warn!("AI analysis disabled: {r}; rule-based reports will be used");
        }
        let mgr = Arc::new(Self {
            state: Arc::downgrade(state),
            sandbox,
            node: node.map(|n| n.0),
            script,
            static_reason,
            proc: tokio::sync::Mutex::new(None),
            running: Mutex::new(None),
            deferred: Mutex::new(Vec::new()),
        });
        tokio::spawn(Self::reaper(Arc::downgrade(&mgr)));
        mgr
    }

    /// Stops the sidecar after `idle_exit_secs` without work so it costs nothing at rest.
    async fn reaper(me: Weak<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let Some(me) = me.upgrade() else { return };
            let Some(state) = me.state.upgrade() else {
                return;
            };
            let idle = Duration::from_secs(state.cfg.ai.idle_exit_secs);
            if let Ok(mut guard) = me.proc.try_lock()
                && guard.as_ref().is_some_and(|s| s.last_used.elapsed() > idle)
                && let Some(mut s) = guard.take()
            {
                let _ = s.child.kill().await;
                tracing::debug!("AI sidecar stopped after idle timeout");
            }
        }
    }

    fn profile(&self, state: &AppState, route: &str) -> Option<ResolvedModel> {
        state.settings.resolve(route)
    }

    async fn runs_today(state: &AppState) -> u32 {
        let midnight = chrono::Local::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .and_then(|t| t.and_local_timezone(chrono::Local).single())
            .map(|t| t.timestamp_millis())
            .unwrap_or(0);
        store::runs_since(&state.db, midnight).await.unwrap_or(0)
    }

    /// Why a model-backed run is not possible right now (None = possible).
    async fn unavailable(&self, state: &AppState, route: &str) -> Option<String> {
        if let Some(r) = &self.static_reason {
            return Some(r.clone());
        }
        let Some(p) = self.profile(state, route) else {
            return Some("未配置模型：请在设置页添加 Provider 并设置任务路由".into());
        };
        if !p.has_key {
            return Some(if p.source == "config" {
                format!("环境变量 {} 未设置", p.key_env)
            } else {
                format!("Provider {} 未填写密钥", p.provider)
            });
        }
        if Self::runs_today(state).await >= state.cfg.ai.daily_budget {
            return Some(format!(
                "今日 AI 分析次数已达上限（{}）",
                state.cfg.ai.daily_budget
            ));
        }
        None
    }

    pub async fn status(&self) -> AiStatus {
        let Some(state) = self.state.upgrade() else {
            return AiStatus::default();
        };
        let profile = self.profile(&state, "daily");
        let reason = self.unavailable(&state, "daily").await;
        AiStatus {
            enabled: reason.is_none(),
            reason,
            format: profile.as_ref().map(|p| p.api_format),
            model: profile.map(|p| p.model),
            runs_today: Self::runs_today(&state).await,
            daily_budget: state.cfg.ai.daily_budget,
            running: self
                .running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Starts an analysis in the background and returns its run id.
    pub fn trigger(
        self: &Arc<Self>,
        kind: ReportKind,
        trigger: &str,
    ) -> Result<String, TriggerError> {
        let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
        {
            let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(r) = running.as_ref() {
                return Err(TriggerError::Busy(r.clone()));
            }
            *running = Some(run_id.clone());
        }
        let me = self.clone();
        let id = run_id.clone();
        let trigger = trigger.to_string();
        tokio::spawn(async move {
            if let Err(e) = me.execute(&id, kind, &trigger).await {
                tracing::error!("analysis {id} failed: {e:#}");
            }
            *me.running.lock().unwrap_or_else(|e| e.into_inner()) = None;
        });
        Ok(run_id)
    }

    /// Scheduler/rule entry point: defers while the host is busy or another run is active.
    pub fn trigger_background(self: &Arc<Self>, kind: ReportKind, trigger: &str) {
        let busy_host = self.state.upgrade().is_some_and(|s| s.is_yielding());
        if busy_host {
            self.defer(kind, trigger);
            return;
        }
        match self.trigger(kind, trigger) {
            Ok(id) => tracing::info!("analysis {id} started ({}, {trigger})", kind.as_str()),
            Err(TriggerError::Busy(_)) => self.defer(kind, trigger),
        }
    }

    fn defer(&self, kind: ReportKind, trigger: &str) {
        let mut d = self.deferred.lock().unwrap_or_else(|e| e.into_inner());
        if !d.iter().any(|(k, _)| *k == kind) {
            tracing::info!("analysis {} deferred ({trigger})", kind.as_str());
            d.push((kind, trigger.to_string()));
        }
    }

    /// Called by the scheduler every minute.
    pub fn run_deferred(self: &Arc<Self>) {
        if self.state.upgrade().is_none_or(|s| s.is_yielding()) || self.is_running() {
            return;
        }
        let next = {
            let mut d = self.deferred.lock().unwrap_or_else(|e| e.into_inner());
            if d.is_empty() {
                None
            } else {
                Some(d.remove(0))
            }
        };
        if let Some((kind, trigger)) = next {
            self.trigger_background(kind, &format!("{trigger} (deferred)"));
        }
    }

    async fn record(&self, state: &AppState, run_id: &str, seq: &mut i64, mut step: AgentStep) {
        *seq += 1;
        step.seq = *seq;
        step.ts = now_ms();
        if let Err(e) = store::insert_step(&state.db, run_id, &step).await {
            tracing::warn!("storing agent step: {e:#}");
        }
        state.emit(Event::Agent {
            run_id: run_id.into(),
            status: "running".into(),
            step: Some(step),
        });
    }

    async fn execute(
        self: &Arc<Self>,
        run_id: &str,
        kind: ReportKind,
        trigger: &str,
    ) -> Result<()> {
        let state = self.state.upgrade().context("daemon shutting down")?;
        let reason = self.unavailable(&state, kind.as_str()).await;
        let profile = self.profile(&state, kind.as_str());
        let model = if reason.is_none() {
            profile.as_ref().map(|p| p.model.clone())
        } else {
            None
        };

        if reason.is_some() && kind == ReportKind::Hourly {
            // hourly checks are only worth it with a model; nothing to record
            return Ok(());
        }
        store::insert_run(&state.db, run_id, trigger, kind.as_str(), model.as_deref()).await?;
        state.emit(Event::Agent {
            run_id: run_id.into(),
            status: "running".into(),
            step: None,
        });
        let mut seq = 0;

        let outcome: Result<Diagnosis> = match (&reason, profile) {
            (None, Some(p)) => {
                let timeout = Duration::from_secs(state.cfg.ai.timeout_secs);
                match tokio::time::timeout(
                    timeout,
                    self.run_model(&state, run_id, kind, trigger, &p, &mut seq),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        // a stuck sidecar is killed; the next run starts a fresh one
                        if let Some(mut s) = self.proc.lock().await.take() {
                            let _ = s.child.kill().await;
                        }
                        Err(anyhow::anyhow!(
                            "AI 分析超时（{} 秒）",
                            state.cfg.ai.timeout_secs
                        ))
                    }
                }
            }
            _ => Err(anyhow::anyhow!(
                reason.clone().unwrap_or_else(|| "未配置模型".into())
            )),
        };

        match outcome {
            Ok(diag) => {
                let report = self
                    .save_report(&state, kind, &diag, "ai", model.as_deref(), run_id)
                    .await?;
                store::finish_run(&state.db, run_id, "succeeded", None, Some(report)).await?;
                state.emit(Event::Agent {
                    run_id: run_id.into(),
                    status: "succeeded".into(),
                    step: None,
                });
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if reason.is_none() {
                    tracing::warn!("analysis {run_id} failed, falling back to rules: {msg}");
                    self.record(
                        &state,
                        run_id,
                        &mut seq,
                        draft("error", None, None, None, Some(msg.clone())),
                    )
                    .await;
                }
                if kind == ReportKind::Hourly {
                    store::finish_run(&state.db, run_id, "failed", Some(&msg), None).await?;
                    state.emit(Event::Agent {
                        run_id: run_id.into(),
                        status: "failed".into(),
                        step: None,
                    });
                } else {
                    let diag = crate::rules::fallback_diagnosis(&state, kind).await?;
                    let report = self
                        .save_report(&state, kind, &diag, "rules", None, run_id)
                        .await?;
                    store::finish_run(&state.db, run_id, "fallback", Some(&msg), Some(report))
                        .await?;
                    state.emit(Event::Agent {
                        run_id: run_id.into(),
                        status: "fallback".into(),
                        step: None,
                    });
                }
            }
        }
        Ok(())
    }

    async fn save_report(
        &self,
        state: &Shared,
        kind: ReportKind,
        d: &Diagnosis,
        by: &str,
        model: Option<&str>,
        run_id: &str,
    ) -> Result<i64> {
        let title = format!(
            "{} · {}",
            kind.label(),
            chrono::Local::now().format("%Y-%m-%d %H:%M")
        );
        let body = serde_json::to_value(d)?;
        let summary = store::insert_report(
            &state.db,
            &store::NewReport {
                kind: kind.as_str(),
                health_score: d.health_score,
                title: &title,
                summary: &d.summary,
                generated_by: by,
                model,
                run_id: Some(run_id),
                body: &body,
            },
        )
        .await?;
        state.emit(Event::Report(summary.clone()));
        state.notifier.report(state, &summary, d).await;
        Ok(summary.id)
    }

    async fn ensure_sidecar<'a>(
        &self,
        state: &AppState,
        guard: &'a mut Option<Sidecar>,
    ) -> Result<&'a mut Sidecar> {
        let generation = state.settings.generation();
        // dead, or started with outdated provider keys
        if let Some(mut s) = guard.take_if(|s| !s.alive() || s.generation != generation) {
            let _ = s.child.kill().await;
        }
        if guard.is_none() {
            *guard = Some(self.spawn_sidecar(state).await?);
        }
        Ok(guard.as_mut().expect("sidecar just ensured"))
    }

    async fn spawn_sidecar(&self, state: &AppState) -> Result<Sidecar> {
        let node = self.node.as_ref().context("node not available")?;
        let script = self
            .script
            .as_ref()
            .context("sidecar script not available")?;
        let mut cmd = tokio::process::Command::new(node);
        cmd.arg(script).env_clear().env("NODE_ENV", "production");
        for k in [
            "PATH",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "no_proxy",
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "TZ",
        ] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        // only the model keys the sidecar needs, nothing else from our environment
        let generation = state.settings.generation();
        for p in state.cfg.ai.profiles.values() {
            if let Some(v) = crate::config::secret(&p.api_key_env) {
                cmd.env(&p.api_key_env, v);
            }
        }
        for (env, key) in state.settings.provider_env(&state.db).await {
            cmd.env(env, key);
        }
        cmd.current_dir(script.parent().unwrap_or(std::path::Path::new("/")))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().context("starting AI sidecar")?;
        let stdin = child.stdin.take().context("sidecar stdin")?;
        let stdout = child.stdout.take().context("sidecar stdout")?;
        let stderr = child.stderr.take().context("sidecar stderr")?;
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => {
                        if tx.send(v).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => tracing::debug!(
                        "sidecar stdout (non-JSON): {}",
                        crate::rules::truncate(&line, 300)
                    ),
                }
            }
        });
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!(target: "sidecar", "{}", crate::rules::truncate(&crate::preprocess::redact(&line), 500));
            }
        });
        let ready = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .context("AI sidecar did not start in time")?;
        match ready {
            Some(v) if v["type"] == "ready" => {}
            Some(v) => bail!("unexpected first message from AI sidecar: {v}"),
            None => bail!("AI sidecar exited during startup (see logs)"),
        }
        Ok(Sidecar {
            child,
            stdin,
            rx,
            last_used: Instant::now(),
            generation,
        })
    }

    async fn run_model(
        &self,
        state: &Shared,
        run_id: &str,
        kind: ReportKind,
        trigger: &str,
        p: &ResolvedModel,
        seq: &mut i64,
    ) -> Result<Diagnosis> {
        let prompt = prompt::user_prompt(state, kind, trigger).await?;
        let mut guard = self.proc.lock().await;
        let sc = self.ensure_sidecar(state, &mut guard).await?;
        sc.last_used = Instant::now();
        let msg = json!({
            "type": "run",
            "run_id": run_id,
            "system": prompt::SYSTEM,
            "prompt": prompt,
            "model": {
                "format": format_str(p.api_format),
                "base_url": p.base_url,
                "model": p.model,
                "api_key_env": p.key_env,
                "auth": auth_str(p.auth),
                "effort": p.effort,
            },
            "max_steps": state.cfg.ai.max_steps,
            "tools": tools::definitions(),
            "output_schema": prompt::output_schema(),
        });
        sc.send(&msg).await?;
        let ctx = tools::ToolCtx {
            state,
            sandbox: &self.sandbox,
        };
        loop {
            let m = sc
                .rx
                .recv()
                .await
                .context("AI sidecar exited unexpectedly")?;
            sc.last_used = Instant::now();
            if m["run_id"].as_str() != Some(run_id) {
                continue;
            }
            match m["type"].as_str().unwrap_or("") {
                "tool_call" => {
                    let name = m["name"].as_str().unwrap_or("").to_string();
                    let call_id = m["call_id"].clone();
                    let input = m["input"].clone();
                    self.record(
                        state,
                        run_id,
                        seq,
                        draft("tool_call", Some(&name), Some(input.clone()), None, None),
                    )
                    .await;
                    let (output, is_error) = match tools::execute(&ctx, &name, &input).await {
                        Ok(v) => (v, false),
                        Err(e) => (json!({ "error": format!("{e:#}") }), true),
                    };
                    self.record(
                        state,
                        run_id,
                        seq,
                        draft("tool_result", Some(&name), None, Some(output.clone()), None),
                    )
                    .await;
                    sc.send(&json!({ "type": "tool_result", "run_id": run_id, "call_id": call_id, "output": output, "is_error": is_error })).await?;
                }
                "step" => {
                    if let Some(t) = m["text"].as_str().filter(|t| !t.trim().is_empty()) {
                        self.record(
                            state,
                            run_id,
                            seq,
                            draft("message", None, None, None, Some(t.to_string())),
                        )
                        .await;
                    }
                }
                "result" => {
                    let d: Diagnosis = serde_json::from_value(m["output"].clone())
                        .context("model output does not match the diagnosis schema")?;
                    return Ok(d.normalized());
                }
                "error" => bail!("{}", m["message"].as_str().unwrap_or("AI sidecar error")),
                _ => {}
            }
        }
    }
}
