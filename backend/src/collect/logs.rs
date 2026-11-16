//! Side-channel log following: tails configured files (never writes to them), redacts,
//! folds repeated messages into clusters and keeps per-minute rates for burst detection.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::config::{LogKind, LogSourceConfig};
use crate::model::{LogCluster, LogSourceInfo, now_ms};
use crate::preprocess::{self, Assembler};
use crate::state::Shared;
use crate::{rules, store};

/// Max bytes read from one file per poll; the rest is picked up next time.
const MAX_READ_PER_POLL: u64 = 4 * 1024 * 1024;
const BASELINE_ALPHA: f64 = 0.1;

#[derive(Default)]
struct SourceStats {
    kind: String,
    path: Option<String>,
    container: Option<String>,
    lines_total: u64,
    errors_total: u64,
    /// (minute, lines, errors) for the last 15 minutes, newest last.
    minutes: VecDeque<(i64, u64, u64)>,
    baseline_errors: f64,
    baseline_lines: f64,
    baseline_ready: bool,
}

#[derive(Default)]
struct Agg {
    clusters: HashMap<String, LogCluster>,
    /// (source, minute) -> (lines, errors) not yet written.
    pending_rates: BTreeMap<(String, i64), (i64, i64)>,
    sources: BTreeMap<String, SourceStats>,
}

#[derive(Default)]
pub struct Pipeline {
    agg: Mutex<Agg>,
}

/// Burst signal for one source, evaluated on the running minute.
#[derive(Debug, Clone)]
pub struct BurstCheck {
    pub source: String,
    pub errors_this_min: f64,
    pub lines_this_min: f64,
    pub baseline_errors: f64,
    pub baseline_lines: f64,
}

fn minute_of(ts: i64) -> i64 {
    ts / 60_000 * 60_000
}

impl Pipeline {
    pub fn register(
        &self,
        name: &str,
        kind: LogKind,
        path: Option<&Path>,
        container: Option<&str>,
    ) {
        let mut agg = self.agg.lock().unwrap_or_else(|e| e.into_inner());
        let s = agg.sources.entry(name.to_string()).or_default();
        s.kind = kind.as_str().to_string();
        s.path = path.map(|p| p.display().to_string());
        s.container = container.map(str::to_string);
    }

    pub fn ingest(&self, source: &str, kind: LogKind, raw: &str) {
        let rec = preprocess::process(kind, raw);
        let now = now_ms();
        let minute = minute_of(now);
        let is_err = rec.level.counts_as_error();
        let mut agg = self.agg.lock().unwrap_or_else(|e| e.into_inner());

        let s = agg.sources.entry(source.to_string()).or_default();
        if s.kind.is_empty() {
            s.kind = kind.as_str().to_string();
        }
        s.lines_total += 1;
        s.errors_total += u64::from(is_err);
        match s.minutes.back_mut() {
            Some((m, l, e)) if *m == minute => {
                *l += 1;
                *e += u64::from(is_err);
            }
            _ => {
                // close the previous minute into the baseline
                if let Some(&(_, l, e)) = s.minutes.back() {
                    update_baseline(s, l as f64, e as f64);
                }
                s.minutes.push_back((minute, 1, u64::from(is_err)));
                while s.minutes.len() > 15 {
                    s.minutes.pop_front();
                }
            }
        }
        let r = agg
            .pending_rates
            .entry((source.to_string(), minute))
            .or_default();
        r.0 += 1;
        r.1 += i64::from(is_err);

        // info-level access lines are counted but not clustered (too many, little value)
        if rec.level == preprocess::Level::Info && kind == LogKind::NginxAccess {
            return;
        }
        let level = rec.level.as_str();
        let fp = preprocess::fingerprint(source, level, &rec.template);
        agg.clusters
            .entry(fp.clone())
            .and_modify(|c| {
                c.count += 1;
                c.last_seen = now;
                c.sample.clone_from(&rec.sample);
            })
            .or_insert(LogCluster {
                fingerprint: fp,
                source: source.to_string(),
                level: level.to_string(),
                template: rec.template,
                sample: rec.sample,
                count: 1,
                first_seen: now,
                last_seen: now,
            });
    }

    /// Writes pending data and returns per-source info plus burst checks.
    pub async fn flush(
        &self,
        db: &store::Db,
    ) -> anyhow::Result<(Vec<LogSourceInfo>, Vec<BurstCheck>)> {
        let now = now_ms();
        let minute = minute_of(now);
        let (clusters, rates, infos, checks) = {
            let mut agg = self.agg.lock().unwrap_or_else(|e| e.into_inner());
            let clusters: Vec<LogCluster> = agg.clusters.drain().map(|(_, c)| c).collect();
            let rates = std::mem::take(&mut agg.pending_rates);
            let mut infos = Vec::new();
            let mut checks = Vec::new();
            for (name, s) in agg.sources.iter_mut() {
                // roll minutes even when a source went quiet
                if let Some(&(m, l, e)) = s.minutes.back()
                    && m < minute
                {
                    update_baseline(s, l as f64, e as f64);
                    s.minutes.push_back((minute, 0, 0));
                    while s.minutes.len() > 15 {
                        s.minutes.pop_front();
                    }
                }
                let last_full = s
                    .minutes
                    .iter()
                    .rev()
                    .find(|(m, _, _)| *m == minute - 60_000);
                let (cur_l, cur_e) = s
                    .minutes
                    .back()
                    .filter(|(m, _, _)| *m == minute)
                    .map(|&(_, l, e)| (l, e))
                    .unwrap_or((0, 0));
                let (rate, err_rate) = last_full
                    .map(|&(_, l, e)| (l as f64, e as f64))
                    .unwrap_or((cur_l as f64, cur_e as f64));
                infos.push(LogSourceInfo {
                    name: name.clone(),
                    kind: s.kind.clone(),
                    path: s.path.clone(),
                    container: s.container.clone(),
                    lines_total: s.lines_total,
                    errors_total: s.errors_total,
                    rate_per_min: rate,
                    errors_per_min: err_rate,
                });
                checks.push(BurstCheck {
                    source: name.clone(),
                    errors_this_min: cur_e as f64,
                    lines_this_min: cur_l as f64,
                    baseline_errors: if s.baseline_ready {
                        s.baseline_errors
                    } else {
                        0.0
                    },
                    baseline_lines: if s.baseline_ready {
                        s.baseline_lines
                    } else {
                        0.0
                    },
                });
            }
            (clusters, rates, infos, checks)
        };
        if !clusters.is_empty() {
            store::upsert_clusters(db, &clusters).await?;
        }
        if !rates.is_empty() {
            let rows: Vec<store::RateRow<'_>> = rates
                .iter()
                .map(|((source, minute), (lines, errors))| store::RateRow {
                    minute: *minute,
                    source,
                    lines: *lines,
                    errors: *errors,
                    date: chrono::DateTime::from_timestamp_millis(*minute)
                        .map(|t| {
                            t.with_timezone(&chrono::Local)
                                .format("%Y-%m-%d")
                                .to_string()
                        })
                        .unwrap_or_default(),
                })
                .collect();
            store::add_log_rates(db, &rows).await?;
        }
        Ok((infos, checks))
    }
}

fn update_baseline(s: &mut SourceStats, lines: f64, errors: f64) {
    if !s.baseline_ready {
        s.baseline_lines = lines;
        s.baseline_errors = errors;
        s.baseline_ready = true;
        return;
    }
    // bursts should not drag the baseline up too quickly
    let e = errors.min(s.baseline_errors * 3.0 + 5.0);
    let l = lines.min(s.baseline_lines * 3.0 + 50.0);
    s.baseline_errors += BASELINE_ALPHA * (e - s.baseline_errors);
    s.baseline_lines += BASELINE_ALPHA * (l - s.baseline_lines);
}

/// Incremental reader that survives rotation and truncation.
pub struct FileTail {
    path: PathBuf,
    pos: u64,
    ino: u64,
    partial: String,
    started: bool,
}

#[cfg(unix)]
fn inode(meta: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}
#[cfg(not(unix))]
fn inode(_meta: &std::fs::Metadata) -> u64 {
    0
}

impl FileTail {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pos: 0,
            ino: 0,
            partial: String::new(),
            started: false,
        }
    }

    /// Returns complete new lines. The first call only seeks to the end (history is not ingested).
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        let meta = std::fs::metadata(&self.path)?;
        let ino = inode(&meta);
        if !self.started {
            self.started = true;
            self.pos = meta.len();
            self.ino = ino;
            return Ok(Vec::new());
        }
        if ino != self.ino || meta.len() < self.pos {
            // rotated or truncated: start from the beginning of the new file
            self.pos = 0;
            self.ino = ino;
            self.partial.clear();
        }
        if meta.len() == self.pos {
            return Ok(Vec::new());
        }
        let mut f = std::fs::File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.pos))?;
        let mut buf = Vec::new();
        let n = f.take(MAX_READ_PER_POLL).read_to_end(&mut buf)?;
        self.pos += n as u64;
        self.partial.push_str(&String::from_utf8_lossy(&buf));
        let mut lines: Vec<String> = Vec::new();
        while let Some(i) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=i).collect();
            lines.push(line.trim_end_matches(['\n', '\r']).to_string());
        }
        // guard against a writer that never emits a newline
        if self.partial.len() > 64 * 1024 {
            lines.push(std::mem::take(&mut self.partial));
        }
        Ok(lines)
    }
}

/// Reads up to `max_bytes` from the end of a file and returns whole lines (read-only).
pub fn read_tail(path: &Path, max_bytes: u64) -> std::io::Result<Vec<String>> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // first line is probably cut
    }
    Ok(lines)
}

async fn follow(state: Shared, src: LogSourceConfig) {
    let pipeline = &crate::collect::pipeline();
    pipeline.register(&src.name, src.kind, Some(&src.path), None);
    let collector = format!("log:{}", src.name);
    let mut tail = FileTail::new(src.path.clone());
    let mut asm = Assembler::new(src.kind);
    let mut last_err: Option<String> = None;
    loop {
        let path = tail.path.clone();
        let res = tokio::task::spawn_blocking(move || {
            let r = tail.poll();
            (tail, r)
        })
        .await;
        let (t, r) = match res {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("log tail task for {} panicked: {e}", src.name);
                return;
            }
        };
        tail = t;
        match r {
            Ok(lines) => {
                if last_err.take().is_some() || lines.is_empty() {
                    state.set_collector(&collector, true, None);
                }
                let had_lines = !lines.is_empty();
                for line in lines {
                    if let Some(rec) = asm.push(&line) {
                        pipeline.ingest(&src.name, src.kind, &rec);
                    }
                }
                if !had_lines && let Some(rec) = asm.flush() {
                    pipeline.ingest(&src.name, src.kind, &rec);
                }
            }
            Err(e) => {
                let msg = format!("{}: {e}", path.display());
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("log source {}: {msg}", src.name);
                    state.set_collector(&collector, false, Some(msg.clone()));
                    last_err = Some(msg);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(state.cfg.collect.log_poll_secs)).await;
    }
}

async fn flusher(state: Shared) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match crate::collect::pipeline().flush(&state.db).await {
            Ok((infos, checks)) => {
                {
                    let mut live = state.write();
                    for i in infos {
                        live.log_sources.insert(i.name.clone(), i);
                    }
                }
                rules::on_log_checks(&state, &checks).await;
            }
            Err(e) => tracing::warn!("flushing log aggregates: {e:#}"),
        }
    }
}

pub fn spawn(state: &Shared) {
    for src in state.cfg.logs.clone() {
        tokio::spawn(follow(state.clone(), src));
    }
    tokio::spawn(flusher(state.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tail_reads_appended_lines_and_handles_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, "old line\n").unwrap();
        let mut t = FileTail::new(p.clone());
        assert!(t.poll().unwrap().is_empty(), "history is skipped");
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "one").unwrap();
        write!(f, "two-partial").unwrap();
        assert_eq!(t.poll().unwrap(), vec!["one"]);
        writeln!(f).unwrap();
        assert_eq!(t.poll().unwrap(), vec!["two-partial"]);
        std::fs::write(&p, "new\n").unwrap();
        assert_eq!(t.poll().unwrap(), vec!["new"]);
    }

    #[tokio::test]
    async fn pipeline_folds_repeats() {
        let db = store::open_memory().await;
        let p = Pipeline::default();
        for i in 0..50 {
            p.ingest(
                "app",
                LogKind::Generic,
                &format!("ERROR user {i} failed password=abc{i}"),
            );
        }
        p.ingest("app", LogKind::Generic, "all fine");
        let (infos, checks) = p.flush(&db).await.unwrap();
        assert_eq!(infos[0].lines_total, 51);
        assert_eq!(infos[0].errors_total, 50);
        assert_eq!(checks[0].errors_this_min, 50.0);
        let clusters = store::query_clusters(
            &db,
            &store::ClusterQuery {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let err = clusters.iter().find(|c| c.level == "error").unwrap();
        assert_eq!(err.count, 50);
        assert!(
            !err.sample.contains("abc"),
            "sample must be redacted: {}",
            err.sample
        );
    }
}
