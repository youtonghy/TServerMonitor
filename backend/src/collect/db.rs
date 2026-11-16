//! Read-only database metrics. Only the fixed statements in this file are ever executed,
//! sessions are switched to read-only, and the model can never supply SQL.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use mysql_async::prelude::Queryable;

use crate::config::{DatabaseConfig, DbKind};
use crate::model::{DbStatus, now_ms};
use crate::state::Shared;

const MYSQL_STATUS: &str = "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Questions','Slow_queries','Aborted_connects','Aborted_clients','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Innodb_row_lock_waits','Innodb_row_lock_time','Created_tmp_disk_tables','Uptime')";
const MYSQL_MAX_CONN: &str = "SHOW GLOBAL VARIABLES WHERE Variable_name = 'max_connections'";

const PG_DB: &str = "SELECT numbackends::float8, xact_commit::float8, xact_rollback::float8, blks_read::float8, blks_hit::float8, deadlocks::float8, temp_bytes::float8 FROM pg_stat_database WHERE datname = current_database()";
const PG_ACTIVITY: &str = "SELECT count(*) FILTER (WHERE state = 'active')::float8, count(*) FILTER (WHERE state = 'active' AND now() - query_start > interval '60 seconds')::float8, count(*) FILTER (WHERE state = 'idle in transaction')::float8 FROM pg_stat_activity";
const PG_MAX_CONN: &str = "SELECT setting::float8 FROM pg_settings WHERE name = 'max_connections'";

async fn mysql_metrics(dsn: &str) -> Result<BTreeMap<String, f64>> {
    let opts = mysql_async::Opts::from_url(dsn).context("invalid MySQL DSN")?;
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .context("connecting to MySQL")?;
    conn.query_drop("SET SESSION TRANSACTION READ ONLY").await?;
    let rows: Vec<(String, String)> = conn.query(MYSQL_STATUS).await?;
    let mut m: BTreeMap<String, f64> = rows
        .into_iter()
        .filter_map(|(k, v)| v.parse().ok().map(|v| (k.to_ascii_lowercase(), v)))
        .collect();
    let max: Vec<(String, String)> = conn.query(MYSQL_MAX_CONN).await?;
    if let Some(v) = max.first().and_then(|(_, v)| v.parse().ok()) {
        m.insert("max_connections".into(), v);
    }
    conn.disconnect().await.ok();
    let reqs = m
        .get("innodb_buffer_pool_read_requests")
        .copied()
        .unwrap_or(0.0);
    let reads = m.get("innodb_buffer_pool_reads").copied().unwrap_or(0.0);
    if reqs > 0.0 {
        m.insert("buffer_hit_pct".into(), (1.0 - reads / reqs) * 100.0);
    }
    if let (Some(c), Some(max)) = (m.get("threads_connected"), m.get("max_connections"))
        && *max > 0.0
    {
        m.insert("connection_usage_pct".into(), c / max * 100.0);
    }
    Ok(m)
}

async fn postgres_metrics(dsn: &str) -> Result<BTreeMap<String, f64>> {
    let (client, conn) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .context("connecting to PostgreSQL")?;
    let task = tokio::spawn(conn);
    client
        .batch_execute("SET default_transaction_read_only = on")
        .await?;
    let mut m = BTreeMap::new();
    if let Some(r) = client.query_opt(PG_DB, &[]).await? {
        for (i, k) in [
            "numbackends",
            "xact_commit",
            "xact_rollback",
            "blks_read",
            "blks_hit",
            "deadlocks",
            "temp_bytes",
        ]
        .iter()
        .enumerate()
        {
            m.insert((*k).to_string(), r.get::<_, Option<f64>>(i).unwrap_or(0.0));
        }
    }
    let r = client.query_one(PG_ACTIVITY, &[]).await?;
    m.insert("active".into(), r.get::<_, Option<f64>>(0).unwrap_or(0.0));
    m.insert(
        "long_running".into(),
        r.get::<_, Option<f64>>(1).unwrap_or(0.0),
    );
    m.insert(
        "idle_in_transaction".into(),
        r.get::<_, Option<f64>>(2).unwrap_or(0.0),
    );
    if let Some(r) = client.query_opt(PG_MAX_CONN, &[]).await? {
        m.insert("max_connections".into(), r.get::<_, f64>(0));
    }
    drop(client);
    task.abort();
    let hit = m.get("blks_hit").copied().unwrap_or(0.0);
    let read = m.get("blks_read").copied().unwrap_or(0.0);
    if hit + read > 0.0 {
        m.insert("buffer_hit_pct".into(), hit / (hit + read) * 100.0);
    }
    if let (Some(c), Some(max)) = (m.get("numbackends"), m.get("max_connections"))
        && *max > 0.0
    {
        m.insert("connection_usage_pct".into(), c / max * 100.0);
    }
    Ok(m)
}

async fn sample(db: &DatabaseConfig) -> DbStatus {
    let base = DbStatus {
        name: db.name.clone(),
        kind: db.kind,
        ok: false,
        error: None,
        metrics: BTreeMap::new(),
        ts: now_ms(),
    };
    let Some(dsn) = crate::config::secret(&db.dsn_env) else {
        return DbStatus {
            error: Some(format!("环境变量 {} 未设置", db.dsn_env)),
            ..base
        };
    };
    let fut = async {
        match db.kind {
            DbKind::Mysql => mysql_metrics(&dsn).await,
            DbKind::Postgres => postgres_metrics(&dsn).await,
        }
    };
    match tokio::time::timeout(Duration::from_secs(15), fut).await {
        Ok(Ok(metrics)) => DbStatus {
            ok: true,
            metrics,
            ..base
        },
        // never echo the DSN: errors from drivers can include it, keep only the first line without URLs
        Ok(Err(e)) => DbStatus {
            error: Some(crate::preprocess::redact(&format!("{e:#}"))),
            ..base
        },
        Err(_) => DbStatus {
            error: Some("连接超时".into()),
            ..base
        },
    }
}

pub fn spawn(state: &Shared) {
    for db in state.cfg.databases.clone() {
        let state = state.clone();
        tokio::spawn(async move {
            // previous counters to derive per-second rates
            let mut prev: Option<(i64, BTreeMap<String, f64>)> = None;
            loop {
                if !state.is_yielding() {
                    let mut st = sample(&db).await;
                    if let Some((pts, pm)) = &prev {
                        let dt = (st.ts - pts) as f64 / 1000.0;
                        for (counter, rate) in [
                            ("questions", "qps"),
                            ("xact_commit", "tps"),
                            ("slow_queries", "slow_per_min"),
                            ("deadlocks", "deadlocks_per_min"),
                        ] {
                            if let (Some(a), Some(b)) = (pm.get(counter), st.metrics.get(counter))
                                && dt > 0.0
                                && b >= a
                            {
                                let per = if rate.ends_with("per_min") { 60.0 } else { 1.0 };
                                st.metrics.insert(rate.into(), (b - a) / dt * per);
                            }
                        }
                    }
                    if st.ok {
                        prev = Some((st.ts, st.metrics.clone()));
                    }
                    state.set_collector(&format!("db:{}", db.name), st.ok, st.error.clone());
                    crate::rules::on_db_status(&state, &st).await;
                    let mut live = state.write();
                    live.dbs.retain(|d| d.name != st.name);
                    live.dbs.push(st);
                    live.dbs.sort_by(|a, b| a.name.cmp(&b.name));
                }
                tokio::time::sleep(Duration::from_secs(db.interval_secs.max(10))).await;
            }
        });
    }
}
