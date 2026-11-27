//! Shared daemon state: config, database, live in-memory view and the event bus.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock, RwLock};

use serde::Serialize;
use tokio::sync::{broadcast, watch};

use crate::agent::AgentManager;
use crate::config::Config;
use crate::model::{
    ContainerInfo, DbStatus, Event, HostMetrics, LogSourceInfo, Mode, ModeState, PortInfo, now_ms,
};
use crate::notify::Notifier;
use crate::settings::Settings;
use crate::store::Db;

#[derive(Debug, Clone, Serialize)]
pub struct CollectorStatus {
    pub ok: bool,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct Live {
    pub host: Option<HostMetrics>,
    /// Recent CPU% samples, newest last, used for yield / idle decisions.
    pub cpu_recent: VecDeque<f64>,
    pub containers: Vec<ContainerInfo>,
    pub container_history: BTreeMap<String, VecDeque<crate::model::ContainerPoint>>,
    pub log_sources: BTreeMap<String, LogSourceInfo>,
    pub ports: Vec<PortInfo>,
    pub dbs: Vec<DbStatus>,
    pub collectors: BTreeMap<String, CollectorStatus>,
    /// Active burst sources -> since (ms).
    pub bursts: BTreeMap<String, i64>,
    pub yield_reason: Option<String>,
    pub idle_audit_since: Option<i64>,
    pub mode: Option<ModeState>,
}

pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Db,
    pub events: broadcast::Sender<Event>,
    /// Flips to true once the daemon starts shutting down; see [`AppState::shutdown_requested`].
    pub shutdown: watch::Sender<bool>,
    pub live: RwLock<Live>,
    pub started_at: i64,
    pub notifier: Notifier,
    pub settings: Settings,
    pub ops: crate::ops::Runtime,
    pub auth: crate::auth::Runtime,
    agent: OnceLock<Arc<AgentManager>>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Arc<Config>, db: Db) -> Shared {
        let (events, _) = broadcast::channel(512);
        let notifier = Notifier::new();
        let settings = Settings::new(cfg.clone());
        Arc::new(Self {
            cfg,
            db,
            events,
            shutdown: watch::channel(false).0,
            live: RwLock::new(Live::default()),
            started_at: now_ms(),
            notifier,
            settings,
            ops: crate::ops::Runtime::default(),
            auth: crate::auth::Runtime::default(),
            agent: OnceLock::new(),
        })
    }

    pub fn set_agent(&self, agent: Arc<AgentManager>) {
        let _ = self.agent.set(agent);
    }

    pub fn agent(&self) -> Option<&Arc<AgentManager>> {
        self.agent.get()
    }

    /// Starts the shutdown: long-lived responses (the SSE stream) end so the server can drain.
    pub fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    /// Resolves once [`AppState::request_shutdown`] was called.
    pub async fn shutdown_requested(&self) {
        let mut rx = self.shutdown.subscribe();
        // the sender lives in self, so the channel cannot close while we wait
        let _ = rx.wait_for(|stopping| *stopping).await;
    }

    pub fn emit(&self, ev: Event) {
        // No receivers is fine (nobody watching the dashboard).
        let _ = self.events.send(ev);
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, Live> {
        self.live.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, Live> {
        self.live.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_collector(&self, name: &str, ok: bool, detail: Option<String>) {
        self.write()
            .collectors
            .insert(name.to_string(), CollectorStatus { ok, detail });
    }

    pub fn mode(&self) -> ModeState {
        self.read().mode.clone().unwrap_or(ModeState {
            mode: Mode::Normal,
            reason: "常规调度".into(),
            since: self.started_at,
        })
    }

    pub fn is_yielding(&self) -> bool {
        self.read().yield_reason.is_some()
    }
}
