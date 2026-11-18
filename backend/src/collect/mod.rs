//! Side-channel collectors. Every collector is read-only with respect to the host.

pub mod access;
pub mod db;
pub mod docker;
pub mod host;
pub mod logs;
pub mod packages;
pub mod security;

use std::sync::LazyLock;

use crate::state::Shared;

static PIPELINE: LazyLock<logs::Pipeline> = LazyLock::new(logs::Pipeline::default);

/// Process-wide log pipeline (file tails and container logs feed the same aggregates).
pub fn pipeline() -> &'static logs::Pipeline {
    &PIPELINE
}

pub fn spawn_all(state: &Shared) {
    tokio::spawn(host::run(state.clone()));
    docker::spawn(state);
    logs::spawn(state);
    security::spawn(state);
    db::spawn(state);
    packages::spawn(state);
}
