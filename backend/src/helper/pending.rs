//! Confirm-or-revert for changes that can lock the operator out (firewall, sshd).
//!
//! The revert plan is written to `<state_dir>/pending/<id>.json` *before* the change is applied.
//! If nobody confirms within the window the helper reverts it; if the helper dies or restarts,
//! every record still on disk is reverted at startup. A daemon restart is harmless: no confirm
//! arrives, so the change reverts on time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::exec;
use super::fsutil::{self, Backup};
use crate::model::now_ms;
use crate::ops::proto::{Actor, OpError, OpResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertPlan {
    /// Files restored first, in order.
    #[serde(default)]
    pub restore: Vec<Backup>,
    /// Then these commands run (e.g. `ufw reload`, `firewall-cmd --reload`).
    #[serde(default)]
    pub commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChange {
    pub id: String,
    pub domain: String,
    pub summary: String,
    pub created_at: i64,
    pub deadline: i64,
    #[serde(default)]
    pub actor: Actor,
    pub revert: RevertPlan,
    /// Run on confirm (e.g. `firewall-cmd --runtime-to-permanent`).
    #[serde(default)]
    pub on_confirm: Vec<Vec<String>>,
}

/// What the daemon and dashboard see (no file paths).
#[derive(Debug, Clone, Serialize)]
pub struct PendingView {
    pub id: String,
    pub domain: String,
    pub summary: String,
    pub created_at: i64,
    pub deadline: i64,
    pub via: String,
}

impl From<&PendingChange> for PendingView {
    fn from(p: &PendingChange) -> Self {
        Self {
            id: p.id.clone(),
            domain: p.domain.clone(),
            summary: p.summary.clone(),
            created_at: p.created_at,
            deadline: p.deadline,
            via: p.actor.via.clone(),
        }
    }
}

pub struct Pending {
    dir: PathBuf,
    window: Duration,
    map: Mutex<HashMap<String, PendingChange>>,
}

impl Pending {
    pub fn new(state_dir: &Path, window: Duration) -> Result<Arc<Self>> {
        let dir = state_dir.join("pending");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Arc::new(Self {
            dir,
            window,
            map: Mutex::new(HashMap::new()),
        }))
    }

    fn file(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Reverts every change left over from a previous run (crash, restart, reboot).
    pub async fn recover(&self) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<PendingChange>(&b).ok())
            {
                Some(p) => {
                    tracing::warn!(
                        "reverting unconfirmed {} change {} from a previous run: {}",
                        p.domain,
                        p.id,
                        p.summary
                    );
                    if let Err(e) = run_revert(&p.revert).await {
                        tracing::error!("reverting {}: {e:#}", p.id);
                    }
                }
                None => tracing::error!("unreadable pending record {}", path.display()),
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    pub async fn list(&self) -> Vec<PendingView> {
        let mut v: Vec<PendingView> = self.map.lock().await.values().map(Into::into).collect();
        v.sort_by_key(|p| p.created_at);
        v
    }

    pub async fn has_domain(&self, domain: &str) -> bool {
        self.map.lock().await.values().any(|p| p.domain == domain)
    }

    /// Persists the revert plan, then runs `apply`. If `apply` fails the change is reverted at
    /// once; otherwise a timer reverts it unless [`Pending::confirm`] is called in time.
    pub async fn guarded<F, Fut>(
        self: &Arc<Self>,
        domain: &str,
        summary: String,
        actor: Actor,
        revert: RevertPlan,
        on_confirm: Vec<Vec<String>>,
        apply: F,
    ) -> OpResult<PendingView>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = OpResult<()>>,
    {
        if self.has_domain(domain).await {
            return Err(OpError::busy(
                "已有一项待确认的变更，请先确认或撤销它".to_string(),
            ));
        }
        let now = now_ms();
        let p = PendingChange {
            id: uuid::Uuid::new_v4().simple().to_string(),
            domain: domain.into(),
            summary,
            created_at: now,
            deadline: now + self.window.as_millis() as i64,
            actor,
            revert,
            on_confirm,
        };
        std::fs::write(
            self.file(&p.id),
            serde_json::to_vec(&p).map_err(|e| OpError::failed(e.to_string()))?,
        )
        .map_err(|e| OpError::failed(format!("保存回滚记录失败：{e}")))?;
        if let Err(e) = apply().await {
            if let Err(re) = run_revert(&p.revert).await {
                tracing::error!("rollback of failed change {}: {re:#}", p.id);
            }
            let _ = std::fs::remove_file(self.file(&p.id));
            return Err(e);
        }
        let view = PendingView::from(&p);
        let id = p.id.clone();
        self.map.lock().await.insert(id.clone(), p);
        let me = self.clone();
        let window = self.window;
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            if me.revert(&id).await.is_ok() {
                tracing::warn!("change {id} was not confirmed in time and has been reverted");
            }
        });
        Ok(view)
    }

    pub async fn confirm(&self, id: &str) -> OpResult<PendingView> {
        let p = self
            .map
            .lock()
            .await
            .remove(id)
            .ok_or_else(|| OpError::invalid("没有这项待确认变更（可能已超时回滚）"))?;
        let _ = std::fs::remove_file(self.file(id));
        for argv in &p.on_confirm {
            match exec::run(argv, Duration::from_secs(60)).await {
                Ok(o) if o.ok() => {}
                Ok(o) => {
                    return Err(OpError::failed(format!(
                        "变更已保留在运行时，但持久化失败：{}",
                        o.message()
                    )));
                }
                Err(e) => return Err(OpError::failed(format!("{e:#}"))),
            }
        }
        Ok((&p).into())
    }

    pub async fn revert(&self, id: &str) -> OpResult<PendingView> {
        let p = self
            .map
            .lock()
            .await
            .remove(id)
            .ok_or_else(|| OpError::invalid("没有这项待确认变更"))?;
        let res = run_revert(&p.revert).await;
        let _ = std::fs::remove_file(self.file(id));
        res.map_err(|e| OpError::failed(format!("回滚失败：{e:#}")))?;
        Ok((&p).into())
    }
}

async fn run_revert(plan: &RevertPlan) -> Result<()> {
    let mut first_err = None;
    for b in &plan.restore {
        if let Err(e) = fsutil::restore(b) {
            first_err.get_or_insert(e);
        }
    }
    for argv in &plan.commands {
        match exec::run(argv, Duration::from_secs(60)).await {
            Ok(o) if o.ok() => {}
            Ok(o) => {
                first_err.get_or_insert(anyhow::anyhow!("{}: {}", argv.join(" "), o.message()));
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfirmed_change_reverts_and_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("user.rules");
        std::fs::write(&f, "old").unwrap();
        let state = d.path().join("state");

        // 1. timer revert
        let p = Pending::new(&state, Duration::from_millis(200)).unwrap();
        let b = fsutil::backup(&state, "firewall", &f).unwrap();
        let plan = RevertPlan {
            restore: vec![b],
            commands: vec![],
        };
        let ff = f.clone();
        p.guarded(
            "firewall",
            "t".into(),
            Actor::default(),
            plan.clone(),
            vec![],
            || async move {
                std::fs::write(&ff, "new").unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        // a second change in the same domain is refused while one is pending
        assert!(
            p.guarded(
                "firewall",
                "t2".into(),
                Actor::default(),
                plan.clone(),
                vec![],
                || async { Ok(()) }
            )
            .await
            .is_err()
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
        assert!(p.list().await.is_empty());

        // 2. helper restart inside the window: the record on disk is reverted at startup
        let p = Pending::new(&state, Duration::from_secs(600)).unwrap();
        let ff = f.clone();
        p.guarded(
            "firewall",
            "t3".into(),
            Actor::default(),
            plan.clone(),
            vec![],
            || async move {
                std::fs::write(&ff, "new").unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();
        drop(p);
        let p2 = Pending::new(&state, Duration::from_secs(600)).unwrap();
        p2.recover().await;
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
        assert_eq!(std::fs::read_dir(state.join("pending")).unwrap().count(), 0);

        // 3. confirm keeps the change; failed apply rolls back at once
        let ff = f.clone();
        let v = p2
            .guarded(
                "firewall",
                "t4".into(),
                Actor::default(),
                plan.clone(),
                vec![],
                || async move {
                    std::fs::write(&ff, "kept").unwrap();
                    Ok(())
                },
            )
            .await
            .unwrap();
        p2.confirm(&v.id).await.unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "kept");
        let b = fsutil::backup(&state, "firewall", &f).unwrap();
        let ff = f.clone();
        let r = p2
            .guarded(
                "firewall",
                "t5".into(),
                Actor::default(),
                RevertPlan {
                    restore: vec![b],
                    commands: vec![],
                },
                vec![],
                || async move {
                    std::fs::write(&ff, "half-applied").unwrap();
                    Err(OpError::failed("boom"))
                },
            )
            .await;
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "kept");
    }
}
