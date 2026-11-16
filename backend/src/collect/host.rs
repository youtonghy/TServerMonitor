//! Host metrics via sysinfo (procfs on Linux). Purely read-only.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use sysinfo::{Disks, Networks, System};

use crate::model::{DiskUsage, HostMetrics, MetricPoint, NetIf, now_ms};
use crate::state::Shared;
use crate::{rules, store};

const IGNORED_FS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "overlay",
    "squashfs",
    "proc",
    "sysfs",
    "nsfs",
    "autofs",
    "devfs",
    "cgroup",
    "cgroup2",
    "fuse.lxcfs",
    "efivarfs",
    "ramfs",
];

fn is_virtual_iface(name: &str) -> bool {
    name == "lo"
        || name.starts_with("lo0")
        || name.starts_with("veth")
        || name.starts_with("br-")
        || name == "docker0"
        || name.starts_with("utun")
        || name.starts_with("awdl")
        || name.starts_with("llw")
        || name.starts_with("anpi")
        || name.starts_with("bridge")
}

pub struct HostSampler {
    sys: System,
    disks: Disks,
    nets: Networks,
    last: Instant,
}

impl HostSampler {
    pub fn new() -> Result<Self, sysinfo::Error> {
        let mut sys = System::new()?;
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        Ok(Self {
            sys,
            disks: Disks::new_with_refreshed_list()?,
            nets: Networks::new_with_refreshed_list()?,
            last: Instant::now(),
        })
    }

    pub fn sample(&mut self) -> HostMetrics {
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);
        self.last = Instant::now();
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(true);
        self.nets.refresh(true);

        let load = System::load_average().unwrap_or(sysinfo::LoadAvg {
            one: 0.0,
            five: 0.0,
            fifteen: 0.0,
        });
        let mut seen = HashSet::new();
        let mut disks = Vec::new();
        let (mut rd, mut wr) = (0u64, 0u64);
        let mut sorted: Vec<_> = self.disks.iter().collect();
        sorted.sort_by_key(|d| d.mount_point().as_os_str().len());
        for d in sorted {
            let fs = d.file_system().to_string_lossy().to_string();
            let mount = d.mount_point().to_string_lossy().to_string();
            if d.total_space() == 0
                || IGNORED_FS.contains(&fs.as_str())
                || mount.starts_with("/snap/")
                || mount.starts_with("/System/Volumes/") && mount != "/System/Volumes/Data"
            {
                continue;
            }
            // the same device can be mounted many times (bind mounts, APFS volumes)
            let key = (d.name().to_string_lossy().to_string(), d.total_space());
            if !seen.insert(key) {
                continue;
            }
            let usage = d.usage();
            rd += usage.read_bytes;
            wr += usage.written_bytes;
            disks.push(DiskUsage {
                mount,
                fs,
                used: d.total_space().saturating_sub(d.available_space()),
                total: d.total_space(),
            });
        }

        let mut nets = Vec::new();
        let (mut rx, mut tx) = (0f64, 0f64);
        for (name, data) in self.nets.iter() {
            let name = name.to_string_lossy();
            if is_virtual_iface(&name) {
                continue;
            }
            let r = data.received() as f64 / elapsed;
            let t = data.transmitted() as f64 / elapsed;
            rx += r;
            tx += t;
            nets.push(NetIf {
                name: name.to_string(),
                rx_bps: r,
                tx_bps: t,
            });
        }
        nets.sort_by(|a, b| (b.rx_bps + b.tx_bps).total_cmp(&(a.rx_bps + a.tx_bps)));
        nets.truncate(8);

        HostMetrics {
            ts: now_ms(),
            hostname: System::host_name().unwrap_or_default(),
            os: System::long_os_version().unwrap_or_default(),
            kernel: System::kernel_version().unwrap_or_default(),
            uptime_secs: System::uptime().unwrap_or(0),
            cpu_pct: f64::from(self.sys.global_cpu_usage()),
            cpu_cores: self.sys.cpus().len().max(1),
            load1: load.one,
            load5: load.five,
            load15: load.fifteen,
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            swap_used: self.sys.used_swap(),
            swap_total: self.sys.total_swap(),
            disk_read_bps: rd as f64 / elapsed,
            disk_write_bps: wr as f64 / elapsed,
            net_rx_bps: rx,
            net_tx_bps: tx,
            disks,
            nets,
        }
    }
}

pub fn to_point(m: &HostMetrics) -> MetricPoint {
    MetricPoint {
        ts: m.ts,
        cpu_pct: m.cpu_pct,
        mem_pct: m.mem_pct(),
        swap_pct: m.swap_pct(),
        disk_pct: m.disk_pct(),
        load1: m.load1,
        disk_read_bps: m.disk_read_bps,
        disk_write_bps: m.disk_write_bps,
        net_rx_bps: m.net_rx_bps,
        net_tx_bps: m.net_tx_bps,
    }
}

pub async fn run(state: Shared) {
    let mut sampler = loop {
        match tokio::task::spawn_blocking(HostSampler::new).await {
            Ok(Ok(s)) => break s,
            Ok(Err(e)) => state.set_collector("host", false, Some(format!("{e}"))),
            Err(e) => state.set_collector("host", false, Some(format!("{e}"))),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    };
    // first CPU reading needs a baseline interval
    tokio::time::sleep(Duration::from_secs(1)).await;
    loop {
        let (s, m) = tokio::task::spawn_blocking(move || {
            let m = sampler.sample();
            (sampler, m)
        })
        .await
        .expect("host sampling task panicked");
        sampler = s;

        {
            let mut live = state.write();
            live.cpu_recent.push_back(m.cpu_pct);
            while live.cpu_recent.len() > 90 {
                live.cpu_recent.pop_front();
            }
            live.host = Some(m.clone());
        }
        state.set_collector("host", true, None);
        if let Err(e) = store::insert_metric(&state.db, &to_point(&m)).await {
            tracing::warn!("storing metric sample: {e:#}");
        }
        state.emit(crate::model::Event::Metrics(Box::new(m.clone())));
        rules::on_host_sample(&state, &m).await;

        let base = state.cfg.collect.interval_secs;
        // business first: sample less often while the host is busy
        let secs = if state.is_yielding() { base * 3 } else { base };
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}
