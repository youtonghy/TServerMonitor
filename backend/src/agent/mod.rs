//! AI analysis hub. Rust owns scheduling, tools, validation and persistence; a Node.js sidecar
//! running the Vercel AI SDK only talks to the model. They speak newline-delimited JSON over
//! stdio:
//!
//! ```text
//! sidecar -> {"type":"ready"}
//! rust    -> {"type":"run", run_id, mode:"structured"|"chat", system, prompt | messages:[{role,content}],
//!             model:{format,base_url,model,api_key_env,auth,effort}, max_steps, tools:[...], output_schema?}
//! sidecar -> {"type":"tool_call", run_id, call_id, name, input}
//! rust    -> {"type":"tool_result", run_id, call_id, output, is_error}
//! sidecar -> {"type":"step", run_id, text} | {"type":"delta", run_id, text}   (delta: chat only)
//! sidecar -> {"type":"result", run_id, output, usage} | {"type":"error", run_id, message}
//! rust    -> {"type":"cancel", run_id}
//! ```
//! API keys reach the sidecar only through its environment, never through the protocol.
//!
//! One sidecar process serves several runs at once: its stdout is demultiplexed by `run_id`.
//! Runs use one of two lanes: a single background lane for scheduled analyses and a small
//! interactive lane for conversations, so chatting never waits for (or blocks) a daily report.

pub mod library;
pub mod prompt;
pub mod tools;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use crate::model::{AgentStep, AiStatus, Diagnosis, Event, ReportKind, now_ms};
use crate::sandbox::Sandbox;
use crate::settings::{ResolvedModel, auth_str, format_str};
use crate::state::{AppState, Shared};
use crate::store;

#[derive(rust_embed::Embed)]
#[folder = "../agent-sidecar/dist/"]
#[allow_missing = true]
struct SidecarAsset;

/// A configured task (`scheduled_tasks`) to run as a custom analysis.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub id: String,
    pub name: String,
    /// Routing kind that picks the model.
    pub route: String,
    /// Task text from the prompt library.
    pub prompt: String,
}

/// Background work: a fixed report kind or a configured task.
#[derive(Debug, Clone)]
enum Job {
    Report(ReportKind),
    Task(TaskSpec),
}

impl Job {
    fn kind(&self) -> ReportKind {
        match self {
            Job::Report(k) => *k,
            Job::Task(_) => ReportKind::Custom,
        }
    }
    /// Deferred jobs are de-duplicated by this key.
    fn key(&self) -> String {
        match self {
            Job::Report(k) => k.as_str().to_string(),
            Job::Task(t) => t.id.clone(),
        }
    }
    fn route(&self) -> &str {
        match self {
            Job::Report(k) => k.as_str(),
            Job::Task(t) => &t.route,
        }
    }
}

/// How a conversation turn is run.
pub struct ChatSpec {
    pub route: String,
    /// Replaces the conversation system prompt (prompt generation).
    pub system: Option<String>,
    pub tools: bool,
}

impl Default for ChatSpec {
    fn default() -> Self {
        Self {
            route: "chat".into(),
            system: None,
            tools: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TriggerError {
    #[error("an analysis is already running ({0})")]
    Busy(String),
    #[error("conversation not found")]
    NotFound,
}

/// Per-run inboxes of the live sidecar; `None` once its stdout closed.
type Routes = Arc<Mutex<Option<HashMap<String, mpsc::UnboundedSender<Value>>>>>;
type Stdin = Arc<tokio::sync::Mutex<tokio::process::ChildStdin>>;

struct Sidecar {
    child: tokio::process::Child,
    stdin: Stdin,
    routes: Routes,
    /// Settings generation the environment was built from; a mismatch forces a respawn.
    generation: u64,
}

impl Sidecar {
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

async fn write_line(stdin: &Stdin, msg: &Value) -> Result<()> {
    let mut line = msg.to_string();
    line.push('\n');
    let mut w = stdin.lock().await;
    w.write_all(line.as_bytes())
        .await
        .context("writing to AI sidecar")?;
    w.flush().await?;
    Ok(())
}

/// One run's connection to the shared sidecar. Dropping it unregisters the run.
struct Link {
    run_id: String,
    stdin: Stdin,
    routes: Routes,
    rx: mpsc::UnboundedReceiver<Value>,
}

impl Link {
    async fn send(&self, msg: &Value) -> Result<()> {
        write_line(&self.stdin, msg).await
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(m) = self
            .routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            m.remove(&self.run_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Background,
    Interactive,
}

/// Concurrent conversations; each one also holds at most one run at a time.
const INTERACTIVE_SLOTS: usize = 2;
/// Messages waiting for a free conversation slot (e.g. report items sent to the background).
const MAX_QUEUED: usize = 10;

/// A conversation message waiting for a slot; it runs under `run_id` once started.
struct Queued {
    run_id: String,
    conversation: String,
    text: String,
}

struct Active {
    lane: Lane,
    conversation: String,
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

/// What a run produced: the sidecar's `output` and the last intermediate text it streamed.
struct Outcome {
    output: Value,
    last_text: Option<String>,
}

pub struct AgentManager {
    state: Weak<AppState>,
    sandbox: Arc<Sandbox>,
    node: Option<PathBuf>,
    script: Option<PathBuf>,
    static_reason: Option<String>,
    proc: tokio::sync::Mutex<Option<Sidecar>>,
    active: Mutex<HashMap<String, Active>>,
    cancelled: Mutex<HashSet<String>>,
    last_used: Mutex<Instant>,
    /// Scheduled work postponed while the host is busy.
    deferred: Mutex<Vec<(Job, String)>>,
    /// Conversation messages waiting for an interactive slot, oldest first.
    queue: Mutex<std::collections::VecDeque<Queued>>,
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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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
            active: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(HashSet::new()),
            last_used: Mutex::new(Instant::now()),
            deferred: Mutex::new(Vec::new()),
            queue: Mutex::new(std::collections::VecDeque::new()),
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
            let quiet = lock(&me.active).is_empty() && lock(&me.last_used).elapsed() > idle;
            if quiet
                && let Ok(mut guard) = me.proc.try_lock()
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

    async fn runs_today(state: &AppState, chat: bool) -> u32 {
        let midnight = chrono::Local::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .and_then(|t| t.and_local_timezone(chrono::Local).single())
            .map(|t| t.timestamp_millis())
            .unwrap_or(0);
        store::runs_since(&state.db, midnight, chat)
            .await
            .unwrap_or(0)
    }

    /// Why a model-backed run is not possible right now (None = possible).
    async fn unavailable(&self, state: &AppState, route: &str, chat: bool) -> Option<String> {
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
        // conversations and background analyses each get the full daily budget
        if Self::runs_today(state, chat).await >= state.cfg.ai.daily_budget {
            return Some(format!(
                "今日{}次数已达上限（{}）",
                if chat { "对话" } else { "AI 分析" },
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
        let reason = self.unavailable(&state, "daily", false).await;
        AiStatus {
            enabled: reason.is_none(),
            reason,
            format: profile.as_ref().map(|p| p.api_format),
            model: profile.map(|p| p.model),
            runs_today: Self::runs_today(&state, false).await,
            daily_budget: state.cfg.ai.daily_budget,
            running: self.background_run(),
        }
    }

    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    fn background_run(&self) -> Option<String> {
        lock(&self.active)
            .iter()
            .find(|(_, a)| a.lane == Lane::Background)
            .map(|(id, _)| id.clone())
    }

    /// True while a scheduled analysis runs (conversations do not count).
    pub fn is_running(&self) -> bool {
        self.background_run().is_some()
    }

    fn finish_active(&self, run_id: &str) {
        lock(&self.active).remove(run_id);
        lock(&self.cancelled).remove(run_id);
    }

    fn was_cancelled(&self, run_id: &str) -> bool {
        lock(&self.cancelled).contains(run_id)
    }

    /// Starts an analysis in the background lane and returns its run id.
    pub fn trigger(
        self: &Arc<Self>,
        kind: ReportKind,
        trigger: &str,
    ) -> Result<String, TriggerError> {
        self.start_job(Job::Report(kind), trigger)
    }

    /// Starts a configured task now, or defers it while the host or the lane is busy.
    pub fn trigger_task(self: &Arc<Self>, task: TaskSpec, trigger: &str) -> Option<String> {
        self.background(Job::Task(task), trigger)
    }

    fn start_job(self: &Arc<Self>, job: Job, trigger: &str) -> Result<String, TriggerError> {
        let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
        let conversation = format!("c_{run_id}");
        {
            let mut active = lock(&self.active);
            if let Some((id, _)) = active.iter().find(|(_, a)| a.lane == Lane::Background) {
                return Err(TriggerError::Busy(id.clone()));
            }
            active.insert(
                run_id.clone(),
                Active {
                    lane: Lane::Background,
                    conversation,
                },
            );
        }
        let me = self.clone();
        let id = run_id.clone();
        let trigger = trigger.to_string();
        tokio::spawn(async move {
            if let Err(e) = me.execute(&id, &job, &trigger).await {
                tracing::error!("analysis {id} failed: {e:#}");
            }
            me.finish_active(&id);
        });
        Ok(run_id)
    }

    /// Scheduler/rule entry point: defers while the host is busy or another run is active.
    pub fn trigger_background(self: &Arc<Self>, kind: ReportKind, trigger: &str) {
        self.background(Job::Report(kind), trigger);
    }

    fn background(self: &Arc<Self>, job: Job, trigger: &str) -> Option<String> {
        let busy_host = self.state.upgrade().is_some_and(|s| s.is_yielding());
        if busy_host {
            self.defer(job, trigger);
            return None;
        }
        let key = job.key();
        match self.start_job(job.clone(), trigger) {
            Ok(id) => {
                tracing::info!("analysis {id} started ({key}, {trigger})");
                Some(id)
            }
            Err(TriggerError::Busy(_)) => {
                self.defer(job, trigger);
                None
            }
            Err(TriggerError::NotFound) => None,
        }
    }

    fn defer(&self, job: Job, trigger: &str) {
        let mut d = lock(&self.deferred);
        if !d.iter().any(|(j, _)| j.key() == job.key()) {
            tracing::info!("analysis {} deferred ({trigger})", job.key());
            d.push((job, trigger.to_string()));
        }
    }

    /// Called by the scheduler every minute.
    pub fn run_deferred(self: &Arc<Self>) {
        if self.state.upgrade().is_none_or(|s| s.is_yielding()) || self.is_running() {
            return;
        }
        let next = {
            let mut d = lock(&self.deferred);
            if d.is_empty() {
                None
            } else {
                Some(d.remove(0))
            }
        };
        if let Some((job, trigger)) = next {
            self.background(job, &format!("{trigger} (deferred)"));
        }
    }

    /// Sends a user message to a conversation; the reply streams over SSE. Returns the run id.
    /// When every conversation slot is busy the message waits in a short queue and starts (under
    /// the returned run id) as soon as a slot frees up.
    pub async fn send_message(
        self: &Arc<Self>,
        conversation: &str,
        text: &str,
    ) -> Result<String, TriggerError> {
        let state = self.state.upgrade().ok_or(TriggerError::NotFound)?;
        let conv = store::get_conversation(&state.db, conversation)
            .await
            .ok()
            .flatten()
            .ok_or(TriggerError::NotFound)?;
        let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
        match self.reserve_interactive(&conv.id, &run_id) {
            Ok(()) => {
                self.spawn_chat(run_id.clone(), conv, text.to_string());
                Ok(run_id)
            }
            Err(busy) => {
                let mut q = lock(&self.queue);
                if q.len() >= MAX_QUEUED || q.iter().any(|x| x.conversation == conv.id) {
                    return Err(busy);
                }
                q.push_back(Queued {
                    run_id: run_id.clone(),
                    conversation: conv.id,
                    text: text.to_string(),
                });
                Ok(run_id)
            }
        }
    }

    /// Conversations with a message waiting for a slot.
    pub fn queued_conversations(&self) -> HashSet<String> {
        lock(&self.queue)
            .iter()
            .map(|q| q.conversation.clone())
            .collect()
    }

    fn spawn_chat(
        self: &Arc<Self>,
        run_id: String,
        conv: crate::model::Conversation,
        text: String,
    ) {
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me
                .execute_chat(&run_id, &conv, &text, &ChatSpec::default())
                .await
            {
                tracing::error!("conversation run {run_id} failed: {e:#}");
            }
            me.finish_active(&run_id);
            me.start_queued().await;
        });
    }

    /// Starts queued messages while slots are free (skipping conversations still running).
    async fn start_queued(self: &Arc<Self>) {
        loop {
            let next = {
                let mut q = lock(&self.queue);
                let pos = q
                    .iter()
                    .position(|x| self.reserve_interactive(&x.conversation, &x.run_id).is_ok());
                pos.and_then(|i| q.remove(i))
            };
            let Some(next) = next else { return };
            let conv = match self.state.upgrade() {
                Some(state) => store::get_conversation(&state.db, &next.conversation)
                    .await
                    .ok()
                    .flatten(),
                None => None,
            };
            match conv {
                Some(conv) => self.spawn_chat(next.run_id, conv, next.text),
                // deleted while waiting
                None => self.finish_active(&next.run_id),
            }
        }
    }

    /// One-shot, tool-less request recorded as its own conversation (visible in the console).
    /// Waits for the answer and returns its text.
    pub async fn complete(
        self: &Arc<Self>,
        kind: &str,
        title: &str,
        spec: ChatSpec,
        text: &str,
    ) -> Result<String> {
        let state = self.state.upgrade().context("daemon shutting down")?;
        let conv_id = format!("c_{}", uuid::Uuid::new_v4().simple());
        store::create_conversation(&state.db, &conv_id, title, kind, None).await?;
        let conv = store::get_conversation(&state.db, &conv_id)
            .await?
            .context("conversation just created")?;
        let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
        self.reserve_interactive(&conv_id, &run_id)
            .map_err(|_| anyhow!("当前进行中的对话已达上限，请稍后再试"))?;
        let result = self.execute_chat(&run_id, &conv, text, &spec).await;
        self.finish_active(&run_id);
        self.start_queued().await;
        result?;
        let (run, steps) = store::get_run(&state.db, &run_id)
            .await?
            .context("run just finished")?;
        if run.status != "succeeded" {
            bail!("{}", run.error.unwrap_or_else(|| "生成失败".into()));
        }
        steps
            .iter()
            .rev()
            .find(|s| s.kind == "message")
            .and_then(|s| s.text.clone())
            .context("模型没有返回内容")
    }

    /// Structured request with optional read-only tools, recorded as its own conversation.
    #[allow(clippy::too_many_arguments)]
    pub async fn draft_structured(
        self: &Arc<Self>,
        kind: &str,
        title: &str,
        context: Option<&Value>,
        route: &str,
        system: &str,
        prompt_text: &str,
        output_schema: Value,
        with_tools: bool,
    ) -> Result<(String, Value)> {
        let state = self.state.upgrade().context("daemon shutting down")?;
        let reason = self.unavailable(&state, route, true).await;
        let profile = self.profile(&state, route);
        let p = match (reason, profile) {
            (None, Some(p)) => p,
            (reason, _) => bail!("{}", reason.unwrap_or_else(|| "未配置模型".into())),
        };
        let conv_id = format!("c_{}", uuid::Uuid::new_v4().simple());
        let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
        self.reserve_interactive(&conv_id, &run_id)
            .map_err(|_| anyhow!("当前进行中的对话已达上限，请稍后再试"))?;
        if let Err(e) =
            store::create_conversation(&state.db, &conv_id, title, kind, context).await
        {
            self.finish_active(&run_id);
            self.start_queued().await;
            return Err(e);
        }
        let res = async {
            store::insert_run(
                &state.db,
                &store::NewRun {
                    id: &run_id,
                    trigger: "user",
                    kind: "chat",
                    model: Some(&p.model),
                    conversation_id: &conv_id,
                },
            )
            .await?;
            let mut seq = 0;
            self.record(
                &state,
                &run_id,
                &conv_id,
                &mut seq,
                draft("user", None, None, None, Some(prompt_text.to_string())),
            )
            .await;
            let msg = json!({
                "type": "run",
                "run_id": run_id,
                "mode": "structured",
                "system": system,
                "prompt": prompt_text,
                "model": model_spec(&p),
                "max_steps": state.cfg.ai.max_steps.min(8),
                "tools": if with_tools { tools::definitions() } else { Vec::new() },
                "output_schema": output_schema,
            });
            match self
                .run_with_timeout(&state, &run_id, &conv_id, &mut seq, &msg)
                .await
            {
                Ok(o) => {
                    if let Some(summary) =
                        o.output["summary"].as_str().filter(|s| !s.trim().is_empty())
                    {
                        self.record(
                            &state,
                            &run_id,
                            &conv_id,
                            &mut seq,
                            draft("message", None, None, None, Some(summary.trim().to_string())),
                        )
                        .await;
                    }
                    self.finish(&state, &run_id, &conv_id, "succeeded", None, None)
                        .await?;
                    Ok((conv_id.clone(), o.output))
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    self.record(
                        &state,
                        &run_id,
                        &conv_id,
                        &mut seq,
                        draft("error", None, None, None, Some(msg.clone())),
                    )
                    .await;
                    let _ = self
                        .finish(&state, &run_id, &conv_id, "failed", Some(&msg), None)
                        .await;
                    Err(e)
                }
            }
        }
        .await;
        self.finish_active(&run_id);
        self.start_queued().await;
        res
    }

    fn reserve_interactive(&self, conversation: &str, run_id: &str) -> Result<(), TriggerError> {
        {
            let mut active = lock(&self.active);
            if let Some((id, _)) = active.iter().find(|(_, a)| a.conversation == conversation) {
                return Err(TriggerError::Busy(id.clone()));
            }
            let busy: Vec<&String> = active
                .iter()
                .filter(|(_, a)| a.lane == Lane::Interactive)
                .map(|(id, _)| id)
                .collect();
            if busy.len() >= INTERACTIVE_SLOTS {
                return Err(TriggerError::Busy(busy[0].clone()));
            }
            active.insert(
                run_id.to_string(),
                Active {
                    lane: Lane::Interactive,
                    conversation: conversation.to_string(),
                },
            );
        }
        Ok(())
    }

    /// Asks the sidecar to stop a run. Returns false when the run is not active.
    pub async fn cancel(&self, run_id: &str) -> bool {
        if !lock(&self.active).contains_key(run_id) {
            return false;
        }
        lock(&self.cancelled).insert(run_id.to_string());
        let stdin = self.proc.lock().await.as_ref().map(|s| s.stdin.clone());
        if let Some(stdin) = stdin
            && let Err(e) = write_line(&stdin, &json!({ "type": "cancel", "run_id": run_id })).await
        {
            tracing::warn!("cancelling {run_id}: {e:#}");
        }
        true
    }

    async fn record(
        &self,
        state: &AppState,
        run_id: &str,
        conversation: &str,
        seq: &mut i64,
        mut step: AgentStep,
    ) {
        *seq += 1;
        step.seq = *seq;
        step.ts = now_ms();
        if let Err(e) = store::insert_step(&state.db, run_id, &step).await {
            tracing::warn!("storing agent step: {e:#}");
        }
        state.emit(Event::Agent {
            run_id: run_id.into(),
            conversation_id: Some(conversation.into()),
            status: "running".into(),
            step: Some(step),
        });
    }

    async fn finish(
        &self,
        state: &AppState,
        run_id: &str,
        conversation: &str,
        status: &str,
        error: Option<&str>,
        report: Option<i64>,
    ) -> Result<()> {
        store::finish_run(&state.db, run_id, status, error, report).await?;
        state.emit(Event::Agent {
            run_id: run_id.into(),
            conversation_id: Some(conversation.into()),
            status: status.into(),
            step: None,
        });
        Ok(())
    }

    async fn execute(self: &Arc<Self>, run_id: &str, job: &Job, trigger: &str) -> Result<()> {
        let state = self.state.upgrade().context("daemon shutting down")?;
        let kind = job.kind();
        let task = match job {
            Job::Task(t) => Some(t),
            Job::Report(_) => None,
        };
        let reason = self.unavailable(&state, job.route(), false).await;
        let profile = self.profile(&state, job.route());
        let model = if reason.is_none() {
            profile.as_ref().map(|p| p.model.clone())
        } else {
            None
        };

        if reason.is_some() && kind == ReportKind::Hourly {
            // hourly checks are only worth it with a model; nothing to record
            return Ok(());
        }
        let conv = format!("c_{run_id}");
        let title = format!(
            "{} · {}",
            task.map_or(kind.label(), |t| t.name.as_str()),
            chrono::Local::now().format("%Y-%m-%d %H:%M")
        );
        // configured tasks show under their routing kind (security_check, log_scan, ...)
        let conv_kind = match task {
            Some(t) if t.route != "default" => t.route.as_str(),
            _ => kind.as_str(),
        };
        store::create_conversation(&state.db, &conv, &title, conv_kind, None).await?;
        store::insert_run(
            &state.db,
            &store::NewRun {
                id: run_id,
                trigger,
                kind: kind.as_str(),
                model: model.as_deref(),
                conversation_id: &conv,
            },
        )
        .await?;
        state.emit(Event::Agent {
            run_id: run_id.into(),
            conversation_id: Some(conv.clone()),
            status: "running".into(),
            step: None,
        });
        let mut seq = 0;

        let outcome: Result<Diagnosis> = match (&reason, profile) {
            (None, Some(p)) => {
                let msg = json!({
                    "type": "run",
                    "run_id": run_id,
                    "mode": "structured",
                    "system": prompt::SYSTEM,
                    "prompt": prompt::user_prompt(&state, kind, trigger, task.map(|t| t.prompt.as_str())).await?,
                    "model": model_spec(&p),
                    "max_steps": state.cfg.ai.max_steps,
                    "tools": tools::definitions(),
                    "output_schema": prompt::output_schema(),
                });
                self.run_with_timeout(&state, run_id, &conv, &mut seq, &msg)
                    .await
                    .and_then(|o| {
                        let d: Diagnosis = serde_json::from_value(o.output)
                            .context("model output does not match the diagnosis schema")?;
                        Ok(d.normalized())
                    })
            }
            _ => Err(anyhow!(
                reason.clone().unwrap_or_else(|| "未配置模型".into())
            )),
        };

        match outcome {
            Ok(diag) => {
                let report = self
                    .save_report(&state, kind, task, &diag, "ai", model.as_deref(), run_id)
                    .await?;
                self.finish(&state, run_id, &conv, "succeeded", None, Some(report))
                    .await?;
            }
            Err(_) if self.was_cancelled(run_id) => {
                self.finish(&state, run_id, &conv, "cancelled", Some("已取消"), None)
                    .await?;
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if reason.is_none() {
                    tracing::warn!("analysis {run_id} failed, falling back to rules: {msg}");
                    self.record(
                        &state,
                        run_id,
                        &conv,
                        &mut seq,
                        draft("error", None, None, None, Some(msg.clone())),
                    )
                    .await;
                }
                if kind == ReportKind::Hourly {
                    self.finish(&state, run_id, &conv, "failed", Some(&msg), None)
                        .await?;
                } else {
                    let diag = crate::rules::fallback_diagnosis(&state, kind).await?;
                    let report = self
                        .save_report(&state, kind, task, &diag, "rules", None, run_id)
                        .await?;
                    self.finish(&state, run_id, &conv, "fallback", Some(&msg), Some(report))
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn execute_chat(
        self: &Arc<Self>,
        run_id: &str,
        conv: &crate::model::Conversation,
        text: &str,
        spec: &ChatSpec,
    ) -> Result<()> {
        let state = self.state.upgrade().context("daemon shutting down")?;
        let reason = self.unavailable(&state, &spec.route, true).await;
        let profile = self.profile(&state, &spec.route);
        let model = profile
            .as_ref()
            .filter(|_| reason.is_none())
            .map(|p| p.model.clone());
        // history first, so the new message is not part of it
        let mut messages = prompt::chat_history(&state, &conv.id).await?;
        store::insert_run(
            &state.db,
            &store::NewRun {
                id: run_id,
                trigger: "user",
                kind: "chat",
                model: model.as_deref(),
                conversation_id: &conv.id,
            },
        )
        .await?;
        if conv.runs == 0 && conv.title == prompt::NEW_CHAT_TITLE {
            let title: String = text.trim().chars().take(30).collect();
            store::rename_conversation(&state.db, &conv.id, &title).await?;
        }
        let mut seq = 0;
        self.record(
            &state,
            run_id,
            &conv.id,
            &mut seq,
            draft("user", None, None, None, Some(text.to_string())),
        )
        .await;

        let p = match (reason, profile) {
            (None, Some(p)) => p,
            (reason, _) => {
                let msg = reason.unwrap_or_else(|| "未配置模型".into());
                self.record(
                    &state,
                    run_id,
                    &conv.id,
                    &mut seq,
                    draft("error", None, None, None, Some(msg.clone())),
                )
                .await;
                return self
                    .finish(&state, run_id, &conv.id, "failed", Some(&msg), None)
                    .await;
            }
        };
        messages.push(prompt::Turn::user(text));
        let msg = json!({
            "type": "run",
            "run_id": run_id,
            "mode": "chat",
            "system": match &spec.system {
                Some(s) => s.clone(),
                None => prompt::chat_system(&state, conv).await,
            },
            "messages": prompt::normalize_turns(messages),
            "model": model_spec(&p),
            "max_steps": state.cfg.ai.max_steps,
            "tools": if spec.tools { tools::chat_definitions() } else { Vec::new() },
        });
        match self
            .run_with_timeout(&state, run_id, &conv.id, &mut seq, &msg)
            .await
        {
            Ok(o) => {
                let answer = o.output.as_str().unwrap_or_default().trim().to_string();
                // the final text normally already arrived as a step
                if !answer.is_empty() && o.last_text.as_deref().map(str::trim) != Some(&answer) {
                    self.record(
                        &state,
                        run_id,
                        &conv.id,
                        &mut seq,
                        draft("message", None, None, None, Some(answer)),
                    )
                    .await;
                }
                self.finish(&state, run_id, &conv.id, "succeeded", None, None)
                    .await
            }
            Err(_) if self.was_cancelled(run_id) => {
                self.finish(&state, run_id, &conv.id, "cancelled", Some("已取消"), None)
                    .await
            }
            Err(e) => {
                let msg = format!("{e:#}");
                self.record(
                    &state,
                    run_id,
                    &conv.id,
                    &mut seq,
                    draft("error", None, None, None, Some(msg.clone())),
                )
                .await;
                self.finish(&state, run_id, &conv.id, "failed", Some(&msg), None)
                    .await
            }
        }
    }

    /// Runs one sidecar request under the configured timeout; a timed-out run is cancelled.
    async fn run_with_timeout(
        &self,
        state: &Shared,
        run_id: &str,
        conversation: &str,
        seq: &mut i64,
        msg: &Value,
    ) -> Result<Outcome> {
        let changes = msg["tools"]
            .as_array()
            .is_some_and(|t| t.iter().any(|d| d["name"] == "propose_change"));
        let mut link = self.open_link(state, run_id).await?;
        link.send(msg).await?;
        let timeout = Duration::from_secs(state.cfg.ai.timeout_secs);
        match tokio::time::timeout(
            timeout,
            self.drive(state, &mut link, run_id, conversation, seq, changes),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                let _ = link
                    .send(&json!({ "type": "cancel", "run_id": run_id }))
                    .await;
                Err(anyhow!("AI 分析超时（{} 秒）", state.cfg.ai.timeout_secs))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn save_report(
        &self,
        state: &Shared,
        kind: ReportKind,
        task: Option<&TaskSpec>,
        d: &Diagnosis,
        by: &str,
        model: Option<&str>,
        run_id: &str,
    ) -> Result<i64> {
        let title = format!(
            "{} · {}",
            task.map_or(kind.label(), |t| t.name.as_str()),
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

    /// Registers a run with the shared sidecar, starting (or refreshing) the process if needed.
    async fn open_link(&self, state: &AppState, run_id: &str) -> Result<Link> {
        let mut guard = self.proc.lock().await;
        let generation = state.settings.generation();
        // outdated keys: respawn only when no other run would be cut off
        let alone = lock(&self.active).len() <= 1;
        if let Some(mut s) = guard.take_if(|s| !s.alive() || (s.generation != generation && alone))
        {
            let _ = s.child.kill().await;
        }
        if guard.is_none() {
            *guard = Some(self.spawn_sidecar(state).await?);
        }
        let sc = guard.as_ref().expect("sidecar just ensured");
        let (tx, rx) = mpsc::unbounded_channel();
        match lock(&sc.routes).as_mut() {
            Some(m) => {
                m.insert(run_id.to_string(), tx);
            }
            None => bail!("AI sidecar exited unexpectedly"),
        }
        *lock(&self.last_used) = Instant::now();
        Ok(Link {
            run_id: run_id.to_string(),
            stdin: sc.stdin.clone(),
            routes: sc.routes.clone(),
            rx,
        })
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
        let routes: Routes = Arc::new(Mutex::new(Some(HashMap::new())));
        let (ready_tx, ready_rx) = oneshot::channel();
        let r = routes.clone();
        tokio::spawn(async move {
            let mut ready = Some(ready_tx);
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    tracing::debug!(
                        "sidecar stdout (non-JSON): {}",
                        crate::rules::truncate(&line, 300)
                    );
                    continue;
                };
                if v["type"] == "ready" {
                    if let Some(t) = ready.take() {
                        let _ = t.send(());
                    }
                    continue;
                }
                let target = v["run_id"]
                    .as_str()
                    .and_then(|id| lock(&r).as_ref().and_then(|m| m.get(id).cloned()));
                if let Some(tx) = target {
                    let _ = tx.send(v);
                }
            }
            // dropping every inbox tells waiting runs that the sidecar is gone
            *lock(&r) = None;
        });
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!(target: "sidecar", "{}", crate::rules::truncate(&crate::preprocess::redact(&line), 500));
            }
        });
        match tokio::time::timeout(Duration::from_secs(20), ready_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => bail!("AI sidecar exited during startup (see logs)"),
            Err(_) => bail!("AI sidecar did not start in time"),
        }
        Ok(Sidecar {
            child,
            stdin: Arc::new(tokio::sync::Mutex::new(stdin)),
            routes,
            generation,
        })
    }

    /// Serves tool calls and records steps until the sidecar reports a result or an error.
    async fn drive(
        &self,
        state: &Shared,
        link: &mut Link,
        run_id: &str,
        conversation: &str,
        seq: &mut i64,
        changes: bool,
    ) -> Result<Outcome> {
        // only conversation runs are offered propose_change; refuse it anywhere else
        let ctx = tools::ToolCtx {
            state,
            sandbox: &self.sandbox,
            conversation: changes.then_some(conversation),
            run_id: Some(run_id),
        };
        let mut last_text = None;
        loop {
            let m = link
                .rx
                .recv()
                .await
                .context("AI sidecar exited unexpectedly")?;
            *lock(&self.last_used) = Instant::now();
            match m["type"].as_str().unwrap_or("") {
                "tool_call" => {
                    let name = m["name"].as_str().unwrap_or("").to_string();
                    let call_id = m["call_id"].clone();
                    let input = m["input"].clone();
                    self.record(
                        state,
                        run_id,
                        conversation,
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
                        conversation,
                        seq,
                        draft("tool_result", Some(&name), None, Some(output.clone()), None),
                    )
                    .await;
                    link.send(&json!({ "type": "tool_result", "run_id": run_id, "call_id": call_id, "output": output, "is_error": is_error })).await?;
                }
                "step" => {
                    if let Some(t) = m["text"].as_str().filter(|t| !t.trim().is_empty()) {
                        last_text = Some(t.to_string());
                        self.record(
                            state,
                            run_id,
                            conversation,
                            seq,
                            draft("message", None, None, None, Some(t.to_string())),
                        )
                        .await;
                    }
                }
                "delta" => {
                    if let Some(t) = m["text"].as_str() {
                        state.emit(Event::AgentDelta {
                            run_id: run_id.into(),
                            conversation_id: conversation.into(),
                            text: t.to_string(),
                        });
                    }
                }
                "result" => {
                    return Ok(Outcome {
                        output: m["output"].clone(),
                        last_text,
                    });
                }
                "error" => bail!("{}", m["message"].as_str().unwrap_or("AI sidecar error")),
                _ => {}
            }
        }
    }
}

fn model_spec(p: &ResolvedModel) -> Value {
    json!({
        "format": format_str(p.api_format),
        "base_url": p.base_url,
        "model": p.model,
        "api_key_env": p.key_env,
        "auth": auth_str(p.auth),
        "effort": p.effort,
    })
}
