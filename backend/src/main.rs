//! TServerMonitor: a zero-intrusion side-channel monitor with an AI ops advisor. The daemon is
//! read-only; optional root helpers (`updater`, `helper`) carry out changes the operator allows.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tsmonitor::{
    agent, api, collect, config, rules, sandbox, schedule, state, store, telegram_bot,
};

#[derive(Parser)]
#[command(
    name = "tsmonitor",
    version,
    about = "Server monitor with an AI ops advisor and optional, helper-mediated management"
)]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, default_value = "config.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (default)
    Run,
    /// Validate the config file and exit
    CheckConfig,
    /// Run the optional package update helper (as root, separate from the daemon)
    Updater {
        /// Root-owned helper config (never the daemon's config.toml)
        #[arg(long, default_value = "/etc/tsmonitor/updater.toml")]
        updater_config: PathBuf,
    },
    /// Set a new random password for a dashboard account and end its sessions
    ResetPassword {
        /// Account name
        #[arg(long)]
        user: String,
    },
    /// Run the optional ops helper for nginx, firewall, SSH and Docker (as root)
    Helper {
        /// Root-owned helper config (never the daemon's config.toml)
        #[arg(long, default_value = "/etc/tsmonitor/helper.toml")]
        helper_config: PathBuf,
    },
}

fn main() -> Result<()> {
    // the sandbox launcher must run before anything else (no runtime, no threads)
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("__sandbox-exec") {
        std::process::exit(sandbox::launcher_main(&args[2..]));
    }

    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TSM_LOG")
                .unwrap_or_else(|_| "info,sqlx=warn,rmcp=warn".into()),
        )
        .init();

    if let Some(Cmd::Updater { updater_config }) = &cli.cmd {
        let ucfg = tsmonitor::updater::load_config(updater_config)?;
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(tsmonitor::updater::serve(ucfg));
    }
    if let Some(Cmd::Helper { helper_config }) = &cli.cmd {
        let hcfg = tsmonitor::helper::HelperConfig::load(helper_config)?;
        return tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(tsmonitor::helper::serve(hcfg));
    }
    let cfg = config::Config::load(&cli.config)?;
    if matches!(cli.cmd, Some(Cmd::CheckConfig)) {
        println!("config ok: {}", cli.config.display());
        return Ok(());
    }
    if let Some(Cmd::ResetPassword { user }) = &cli.cmd {
        let data_dir = cfg.storage.data_dir.clone();
        let user = user.clone();
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let db = store::open(&data_dir).await?;
                let pw = tsmonitor::auth::reset_password(&db, &user).await?;
                println!(
                    "New password for {user}: {pw}\nAll sessions of this account were signed out."
                );
                anyhow::Ok(())
            });
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run(cfg))
}

async fn run(cfg: config::Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    let db = store::open(&cfg.storage.data_dir).await?;
    store::close_stale_runs(&db).await?;
    tsmonitor::updater::close_stale_jobs(&db).await?;
    tsmonitor::ops::close_stale_jobs(&db).await?;
    if config::secret(&cfg.ops.secret_env).is_some() {
        tsmonitor::ops::protect_secret();
    }
    let state = state::AppState::new(cfg.clone(), db);
    if let Some(code) = tsmonitor::auth::init(&state).await? {
        tsmonitor::auth::announce_setup(&state, &code);
    }
    for (env, what) in [
        (&cfg.server.token_env, "API"),
        (&cfg.server.ops_token_env, "ops"),
    ] {
        if config::secret(env).is_some() {
            tracing::warn!(
                "{env} is set: the static {what} token still works but is deprecated; create API tokens in the dashboard instead"
            );
        }
    }

    let sandbox = Arc::new(sandbox::Sandbox::init(
        &cfg.storage.data_dir,
        cfg.sandbox.clone(),
    )?);
    let isolation = sandbox::probe().await;
    // the key file next to the DB is only safe when analysis scripts cannot read the data dir
    let isolated = matches!(isolation.as_str(), "fully_enforced" | "partially_enforced");
    state.settings.set_file_key_allowed(isolated);
    state.ops.set_isolation(isolated);
    state
        .settings
        .reload(&state.db)
        .await
        .context("loading runtime settings")?;
    match isolation.as_str() {
        "fully_enforced" => state.set_collector(
            "sandbox",
            true,
            Some("Landlock 已启用（文件与网络隔离）".into()),
        ),
        "partially_enforced" => {
            tracing::warn!(
                "Landlock is only partially enforced (kernel < 6.7 cannot restrict network); scripts may reach the network"
            );
            state.set_collector(
                "sandbox",
                true,
                Some("Landlock 部分生效：文件系统已隔离，内核版本过低无法限制网络".into()),
            );
        }
        other => {
            tracing::warn!(
                "sandbox isolation level: {other}; analysis scripts only get path checks, rlimits and timeouts"
            );
            state.set_collector(
                "sandbox",
                false,
                Some(format!(
                    "内核级隔离不可用（{other}），仅有路径守卫、资源上限与超时"
                )),
            );
        }
    }
    let agent = agent::AgentManager::init(&state, sandbox).await;
    state.set_agent(agent);

    rules::recompute_mode(&state);
    collect::spawn_all(&state);
    schedule::spawn(&state);
    telegram_bot::spawn(&state);
    tsmonitor::ops::spawn(&state);

    let listener = tokio::net::TcpListener::bind(cfg.server.bind)
        .await
        .with_context(|| format!("binding {}", cfg.server.bind))?;
    tracing::info!("dashboard on http://{}", cfg.server.bind);
    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
}
