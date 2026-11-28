//! Docker domain: lifecycle of existing containers, compose projects by label, images and
//! volumes. There is deliberately no exec, no create and no arbitrary bind mount here; the
//! only containers the helper creates are nginx's, in fixed shape (`nginx_docker`).

use bollard::Docker;
use bollard::query_parameters::{
    CreateImageOptionsBuilder, KillContainerOptions, PruneImagesOptions, PruneVolumesOptions,
    RemoveContainerOptionsBuilder, RemoveImageOptionsBuilder, RemoveVolumeOptions,
    RestartContainerOptionsBuilder, StartContainerOptions, StopContainerOptionsBuilder,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};

use super::config::DockerOp;
use super::{Call, Ctx, Domain, not_enabled, op_not_allowed};
use crate::ops::docker as inv;
use crate::ops::proto::{OpError, OpResult};
use crate::ops::validate;

pub(super) fn connect(ctx: &Ctx) -> OpResult<Docker> {
    let path = ctx.cfg.docker.socket.to_string_lossy();
    Docker::connect_with_unix(&path, 120, bollard::API_DEFAULT_VERSION)
        .map_err(|e| OpError::failed(format!("连接 Docker（{path}）失败：{e}")))
}

fn engine(e: bollard::errors::Error) -> OpError {
    OpError::failed(format!("Docker：{e}"))
}

fn allow(ctx: &Ctx, op: DockerOp) -> OpResult<()> {
    if ctx.cfg.docker.allow.contains(&op) {
        Ok(())
    } else {
        Err(op_not_allowed("docker", &op))
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Start,
    Stop,
    Restart,
    Kill,
    Remove,
}

impl Action {
    fn op(self) -> DockerOp {
        match self {
            Action::Start => DockerOp::Start,
            Action::Stop => DockerOp::Stop,
            Action::Restart => DockerOp::Restart,
            Action::Kill => DockerOp::Kill,
            Action::Remove => DockerOp::Remove,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Action::Start => "启动",
            Action::Stop => "停止",
            Action::Restart => "重启",
            Action::Kill => "强制终止",
            Action::Remove => "删除",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerArgs {
    id: String,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectArgs {
    name: String,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullArgs {
    reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageArgs {
    id: String,
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameArgs {
    name: String,
}

pub async fn handle(ctx: &Ctx, op: &str, call: Call<'_>) -> OpResult<Value> {
    if !ctx.cfg.docker.enabled {
        return Err(not_enabled("docker"));
    }
    let d = connect(ctx)?;
    let protected = &ctx.cfg.docker.protected;
    match op {
        "containers" => {
            let list = inv::containers(&d, protected)
                .await
                .map_err(OpError::from)?;
            let wd = inv::project_workdirs(&d).await;
            Ok(json!({ "projects": inv::projects(&list, &wd), "containers": list }))
        }
        "images" => Ok(json!(inv::images(&d).await.map_err(OpError::from)?)),
        "volumes" => Ok(json!(inv::volumes(&d).await.map_err(OpError::from)?)),
        "networks" => Ok(json!(inv::networks(&d).await.map_err(OpError::from)?)),
        "container" => {
            let a: ContainerArgs = call.args()?;
            allow(ctx, a.action.op())?;
            validate::container_ref(&a.id)?;
            let _g = ctx.lock(Domain::Docker).await?;
            let list = inv::containers(&d, protected)
                .await
                .map_err(OpError::from)?;
            let c = list
                .iter()
                .find(|c| c.name == a.id || (a.id.len() >= 6 && c.id.starts_with(&a.id)))
                .ok_or_else(|| OpError::invalid(format!("找不到容器 {}", a.id)))?;
            if c.protected && a.action != Action::Start {
                return Err(OpError::invalid(format!(
                    "{} 受保护（套接字代理、TServerMonitor 本身或配置中列出的容器），不能{}",
                    c.name,
                    a.action.label()
                )));
            }
            container_action(&d, &c.id, &c.name, a.action, &call).await?;
            Ok(json!({ "container": c.name, "action": a.action.label(), "dry_run": call.dry_run }))
        }
        "project" => {
            let a: ProjectArgs = call.args()?;
            allow(ctx, DockerOp::Project)?;
            let name = validate::simple_name("项目", &a.name)?;
            if matches!(a.action, Action::Kill | Action::Remove) {
                return Err(OpError::invalid("项目只支持启动、停止和重启"));
            }
            let _g = ctx.lock(Domain::Docker).await?;
            let list = inv::containers(&d, protected)
                .await
                .map_err(OpError::from)?;
            let mut members: Vec<_> = list
                .iter()
                .filter(|c| c.project.as_deref() == Some(name.as_str()))
                .collect();
            if members.is_empty() {
                return Err(OpError::invalid(format!("找不到 compose 项目 {name}")));
            }
            if a.action != Action::Start
                && let Some(p) = members.iter().find(|c| c.protected)
            {
                return Err(OpError::invalid(format!(
                    "项目包含受保护的容器 {}，不能整体{}",
                    p.name,
                    a.action.label()
                )));
            }
            members.sort_by(|x, y| x.name.cmp(&y.name));
            if a.action == Action::Stop {
                members.reverse();
            }
            let mut failed = Vec::new();
            for c in &members {
                if let Err(e) = container_action(&d, &c.id, &c.name, a.action, &call).await {
                    call.log.line(format!("{}：{}", c.name, e.message));
                    failed.push(c.name.clone());
                }
            }
            if !failed.is_empty() {
                return Err(OpError::failed(format!(
                    "{} 个容器操作失败：{}",
                    failed.len(),
                    failed.join(", ")
                )));
            }
            Ok(json!({ "project": name, "containers": members.len(), "dry_run": call.dry_run }))
        }
        "image_pull" => {
            let a: PullArgs = call.args()?;
            allow(ctx, DockerOp::ImagePull)?;
            validate::image_ref(&a.reference)?;
            pull(&d, &a.reference, &call).await
        }
        "image_remove" => {
            let a: ImageArgs = call.args()?;
            allow(ctx, DockerOp::ImageRemove)?;
            validate::image_ref(&a.id)?;
            let _g = ctx.lock(Domain::Docker).await?;
            call.log.line(format!(
                "删除镜像 {}{}",
                a.id,
                if a.force { "（强制）" } else { "" }
            ));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let res = d
                .remove_image(
                    &a.id,
                    Some(RemoveImageOptionsBuilder::new().force(a.force).build()),
                    None,
                )
                .await
                .map_err(engine)?;
            for r in &res {
                if let Some(x) = &r.untagged {
                    call.log.line(format!("untagged {x}"));
                }
                if let Some(x) = &r.deleted {
                    call.log.line(format!("deleted {}", inv::short_id(x)));
                }
            }
            Ok(json!({ "removed": res.len() }))
        }
        "image_prune" => {
            allow(ctx, DockerOp::ImagePrune)?;
            let _g = ctx.lock(Domain::Docker).await?;
            call.log.line("清理未被使用的悬空镜像");
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let r = d
                .prune_images(None::<PruneImagesOptions>)
                .await
                .map_err(engine)?;
            let n = r.images_deleted.map_or(0, |v| v.len());
            let bytes = r.space_reclaimed.unwrap_or(0);
            call.log
                .line(format!("删除 {n} 个镜像层，回收 {bytes} 字节"));
            Ok(json!({ "deleted": n, "reclaimed": bytes }))
        }
        "volume_remove" => {
            let a: NameArgs = call.args()?;
            allow(ctx, DockerOp::VolumeRemove)?;
            let name = validate::simple_name("卷", &a.name)?;
            let _g = ctx.lock(Domain::Docker).await?;
            call.log.line(format!("删除卷 {name}（数据将永久丢失）"));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            d.remove_volume(&name, None::<RemoveVolumeOptions>)
                .await
                .map_err(engine)?;
            Ok(json!({ "removed": name }))
        }
        "volume_prune" => {
            allow(ctx, DockerOp::VolumePrune)?;
            let _g = ctx.lock(Domain::Docker).await?;
            call.log.line("清理未被任何容器使用的卷（数据将永久丢失）");
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let r = d
                .prune_volumes(None::<PruneVolumesOptions>)
                .await
                .map_err(engine)?;
            let names = r.volumes_deleted.unwrap_or_default();
            for n in &names {
                call.log.line(format!("deleted {n}"));
            }
            Ok(json!({ "deleted": names.len(), "reclaimed": r.space_reclaimed.unwrap_or(0) }))
        }
        _ => Err(OpError::invalid(format!("unknown call docker.{op}"))),
    }
}

async fn container_action(
    d: &Docker,
    id: &str,
    name: &str,
    action: Action,
    call: &Call<'_>,
) -> OpResult<()> {
    call.log
        .line(format!("{}容器 {name}（{id}）", action.label()));
    if call.dry_run {
        call.log.line("（演练模式：未实际执行）");
        return Ok(());
    }
    let r = match action {
        Action::Start => d.start_container(id, None::<StartContainerOptions>).await,
        Action::Stop => {
            d.stop_container(id, Some(StopContainerOptionsBuilder::new().t(15).build()))
                .await
        }
        Action::Restart => {
            d.restart_container(
                id,
                Some(RestartContainerOptionsBuilder::new().t(15).build()),
            )
            .await
        }
        Action::Kill => d.kill_container(id, None::<KillContainerOptions>).await,
        // volumes are kept; removing them is a separate, separately allowed operation
        Action::Remove => {
            d.remove_container(
                id,
                Some(
                    RemoveContainerOptionsBuilder::new()
                        .force(false)
                        .v(false)
                        .build(),
                ),
            )
            .await
        }
    };
    match r {
        Ok(()) => {
            call.log.line("完成");
            Ok(())
        }
        // 304: already in the requested state
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 304, ..
        }) => {
            call.log.line("容器已处于目标状态");
            Ok(())
        }
        Err(e) => Err(engine(e)),
    }
}

pub(super) async fn pull(d: &Docker, reference: &str, call: &Call<'_>) -> OpResult<Value> {
    let (image, tag) = split_ref(reference);
    call.log.line(format!("拉取镜像 {image}:{tag}"));
    if call.dry_run {
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true }));
    }
    let opts = CreateImageOptionsBuilder::new()
        .from_image(&image)
        .tag(&tag)
        .build();
    let mut s = d.create_image(Some(opts), None, None);
    // layer id -> last status, so progress ticks do not flood the log
    let mut last: std::collections::HashMap<String, String> = Default::default();
    while let Some(item) = s.next().await {
        let info = item.map_err(engine)?;
        if let Some(err) = info.error_detail.and_then(|e| e.message) {
            return Err(OpError::failed(err));
        }
        let status = info.status.unwrap_or_default();
        let id = info.id.unwrap_or_default();
        if matches!(status.as_str(), "Downloading" | "Extracting" | "Waiting") {
            continue;
        }
        if last.get(&id) != Some(&status) {
            last.insert(id.clone(), status.clone());
            call.log.line(if id.is_empty() {
                status
            } else {
                format!("{id}: {status}")
            });
        }
    }
    Ok(json!({ "image": format!("{image}:{tag}") }))
}

/// `repo[:tag]` or `repo@digest`; the tag defaults to `latest`. A registry port is not a tag.
fn split_ref(r: &str) -> (String, String) {
    if let Some((img, digest)) = r.split_once('@') {
        return (img.to_string(), digest.to_string());
    }
    match r.rsplit_once(':') {
        Some((img, tag)) if !tag.contains('/') => (img.to_string(), tag.to_string()),
        _ => (r.to_string(), "latest".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::split_ref;

    #[test]
    fn image_references() {
        assert_eq!(split_ref("nginx"), ("nginx".into(), "latest".into()));
        assert_eq!(split_ref("nginx:1.27"), ("nginx".into(), "1.27".into()));
        assert_eq!(
            split_ref("registry:5000/team/app"),
            ("registry:5000/team/app".into(), "latest".into())
        );
        assert_eq!(
            split_ref("ghcr.io/o/a@sha256:ab"),
            ("ghcr.io/o/a".into(), "sha256:ab".into())
        );
    }
}
