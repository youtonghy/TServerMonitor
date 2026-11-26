//! Persisted access history: closed minutes from [`super::access::Access::drain_closed`] are
//! stored in `access_minutes`; history queries re-aggregate them per range.

use anyhow::Result;
use sqlx::Row;

use super::access::{AccessPoint, AccessStats, Agg, MinuteSummary, quantile};
use crate::store::Db;

pub async fn store(db: &Db, minutes: &[MinuteSummary]) -> Result<()> {
    for m in minutes {
        // a restart can re-open a minute that was already stored: add to it
        let prev: Option<String> =
            sqlx::query_scalar("SELECT detail FROM access_minutes WHERE minute = ?")
                .bind(m.minute)
                .fetch_optional(db)
                .await?;
        let merged = match prev.and_then(|p| serde_json::from_str::<MinuteSummary>(&p).ok()) {
            Some(p) => merge(&p, m),
            None => m.clone(),
        };
        sqlx::query(
            "INSERT INTO access_minutes (minute, requests, s2xx, s3xx, s4xx, s5xx, bytes, p95_ms, detail)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(minute) DO UPDATE SET requests = excluded.requests, s2xx = excluded.s2xx,
               s3xx = excluded.s3xx, s4xx = excluded.s4xx, s5xx = excluded.s5xx,
               bytes = excluded.bytes, p95_ms = excluded.p95_ms, detail = excluded.detail",
        )
        .bind(merged.minute)
        .bind(merged.requests as i64)
        .bind(merged.status[0] as i64)
        .bind(merged.status[1] as i64)
        .bind(merged.status[2] as i64)
        .bind(merged.status[3] as i64)
        .bind(merged.bytes as i64)
        .bind(quantile(&merged.hist, 0.95))
        .bind(serde_json::to_string(&merged)?)
        .execute(db)
        .await?;
    }
    Ok(())
}

fn merge(a: &MinuteSummary, b: &MinuteSummary) -> MinuteSummary {
    let mut agg = Agg::default();
    agg.add_summary(a);
    agg.add_summary(b);
    let s = agg.finish(1, vec![], 30, false);
    let mut hist = a.hist.clone();
    for (x, y) in hist.iter_mut().zip(&b.hist) {
        *x += y;
    }
    MinuteSummary {
        minute: a.minute,
        requests: s.requests,
        status: s.status,
        bytes: s.bytes,
        hist,
        // tops are re-derived from both halves
        paths: a.paths.iter().chain(&b.paths).cloned().collect(),
        ips: a.ips.iter().chain(&b.ips).cloned().collect(),
        hosts: a.hosts.iter().chain(&b.hosts).cloned().collect(),
        ua: a.ua.iter().chain(&b.ua).cloned().collect(),
    }
}

/// (span ms, bucket ms) for a range name.
pub fn range(name: &str) -> Option<(i64, i64)> {
    let m = 60_000;
    Some(match name {
        "1h" => (60 * m, m),
        "6h" => (360 * m, 5 * m),
        "24h" => (1440 * m, 15 * m),
        "7d" => (7 * 1440 * m, 60 * m),
        "30d" => (30 * 1440 * m, 360 * m),
        _ => return None,
    })
}

/// History over a range: a bucketed series for every range; top lists and latency
/// percentiles for ranges up to 24h (longer ranges would scan too many rows).
pub async fn history(
    db: &Db,
    name: &str,
    now: i64,
    top: usize,
    mask_ips: bool,
) -> Result<Option<AccessStats>> {
    let Some((span, step)) = range(name) else {
        return Ok(None);
    };
    let since = now - span;
    let rows = sqlx::query(
        "SELECT (minute / ?1) * ?1 AS b, SUM(requests), SUM(s4xx), SUM(s5xx), MAX(p95_ms)
         FROM access_minutes WHERE minute >= ?2 GROUP BY b ORDER BY b",
    )
    .bind(step)
    .bind(since)
    .fetch_all(db)
    .await?;
    let series: Vec<AccessPoint> = rows
        .iter()
        .map(|r| AccessPoint {
            ts: r.get(0),
            requests: r.get::<i64, _>(1) as u64,
            s4xx: r.get::<i64, _>(2) as u64,
            s5xx: r.get::<i64, _>(3) as u64,
            p95_ms: r.get(4),
        })
        .collect();
    let mut agg = Agg::default();
    if span <= 1440 * 60_000 {
        let details: Vec<String> =
            sqlx::query_scalar("SELECT detail FROM access_minutes WHERE minute >= ?")
                .bind(since)
                .fetch_all(db)
                .await?;
        for d in details {
            if let Ok(s) = serde_json::from_str::<MinuteSummary>(&d) {
                agg.add_summary(&s);
            }
        }
        Ok(Some(agg.finish(span / 60_000, series, top, mask_ips)))
    } else {
        let totals = sqlx::query(
            "SELECT COALESCE(SUM(requests),0), COALESCE(SUM(s2xx),0), COALESCE(SUM(s3xx),0), COALESCE(SUM(s4xx),0), COALESCE(SUM(s5xx),0), COALESCE(SUM(bytes),0)
             FROM access_minutes WHERE minute >= ?",
        )
        .bind(since)
        .fetch_one(db)
        .await?;
        let g = |i| totals.get::<i64, _>(i) as u64;
        agg.add(
            g(0),
            [g(1), g(2), g(3), g(4)],
            g(5),
            &[],
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );
        Ok(Some(agg.finish(span / 60_000, series, top, mask_ips)))
    }
}

pub async fn prune(db: &Db, before: i64) -> Result<()> {
    sqlx::query("DELETE FROM access_minutes WHERE minute < ?")
        .bind(before)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::access::Access;

    #[tokio::test]
    async fn history_survives_restart_and_merges() {
        let db = crate::store::open_memory().await;
        let t = 1_700_000_000_000 / 60_000 * 60_000;
        let line = r#"10.0.0.1 - - [x] "GET /a HTTP/1.1" 500 10 "-" "Mozilla/5.0" 0.300"#;
        let a = Access::default();
        for _ in 0..4 {
            a.record(line, t);
        }
        store(&db, &a.drain_closed(t + 60_000)).await.unwrap();
        // "restart": a fresh in-memory window that saw the same minute again
        let b = Access::default();
        b.record(line, t + 1000);
        store(&db, &b.drain_closed(t + 60_000)).await.unwrap();

        let h = history(&db, "1h", t + 120_000, 10, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(h.requests, 5);
        assert_eq!(h.status[3], 5);
        assert_eq!(h.series.len(), 1);
        assert_eq!(h.top_ips[0].ip, "10.0.0.x");
        assert!(h.latency.is_some());
        let long = history(&db, "30d", t + 120_000, 10, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(long.requests, 5);
        assert!(history(&db, "2y", t, 10, true).await.unwrap().is_none());
        prune(&db, t + 1).await.unwrap();
        let h = history(&db, "1h", t + 120_000, 10, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(h.requests, 0);
    }
}
