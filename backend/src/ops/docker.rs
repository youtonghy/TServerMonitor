//! Docker inventory shared by the helper (real socket) and the daemon (read-only proxy):
//! containers with compose labels, compose projects, images, volumes and networks.

use std::collections::{BTreeMap, HashMap, HashSet};

use bollard::Docker;
use bollard::query_parameters::{
    ListContainersOptionsBuilder, ListImagesOptionsBuilder, ListNetworksOptions, ListVolumesOptions,
};
use serde::{Deserialize, Serialize};

pub const PROJECT_LABEL: &str = "com.docker.compose.project";
pub const SERVICE_LABEL: &str = "com.docker.compose.service";
pub const WORKDIR_LABEL: &str = "com.docker.compose.project.working_dir";
pub const PROTECT_LABEL: &str = "tsmonitor.protected";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLite {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub project: Option<String>,
    pub service: Option<String>,
    /// Only `start` is allowed on protected containers.
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectView {
    pub name: String,
    pub working_dir: Option<String>,
    pub services: Vec<String>,
    pub containers: Vec<String>,
    pub running: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageView {
    pub id: String,
    pub tags: Vec<String>,
    pub size: i64,
    pub created: i64,
    /// Containers using the image (-1 when the engine did not compute it).
    pub containers: i64,
    pub dangling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeView {
    pub name: String,
    pub driver: String,
    pub project: Option<String>,
    pub in_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkView {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub internal: bool,
}

/// Containers that must never be stopped from the dashboard: the socket proxy, TServerMonitor
/// itself, anything labelled `tsmonitor.protected=true`, and names listed in the helper config.
pub fn is_protected(
    name: &str,
    image: &str,
    labels: &HashMap<String, String>,
    extra: &[String],
) -> bool {
    labels.get(PROTECT_LABEL).is_some_and(|v| v == "true")
        || extra.iter().any(|n| n == name)
        || image.contains("docker-socket-proxy")
        || image.contains("tsmonitor")
        || name == "tsmonitor"
}

pub fn short_id(id: &str) -> String {
    id.trim_start_matches("sha256:").chars().take(12).collect()
}

pub async fn containers(d: &Docker, protected: &[String]) -> anyhow::Result<Vec<ContainerLite>> {
    let list = d
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await?;
    Ok(list
        .into_iter()
        .map(|c| {
            let labels = c.labels.unwrap_or_default();
            let name = c
                .names
                .unwrap_or_default()
                .first()
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_default();
            let image = c.image.unwrap_or_default();
            ContainerLite {
                id: short_id(&c.id.unwrap_or_default()),
                protected: is_protected(&name, &image, &labels, protected),
                name,
                image,
                state: c.state.map(|s| s.to_string()).unwrap_or_default(),
                status: c.status.unwrap_or_default(),
                project: labels.get(PROJECT_LABEL).cloned(),
                service: labels.get(SERVICE_LABEL).cloned(),
            }
        })
        .collect())
}

/// Compose projects, derived from container labels.
pub fn projects(list: &[ContainerLite], workdirs: &HashMap<String, String>) -> Vec<ProjectView> {
    let mut by: BTreeMap<String, ProjectView> = BTreeMap::new();
    for c in list {
        let Some(p) = &c.project else { continue };
        let e = by.entry(p.clone()).or_insert_with(|| ProjectView {
            name: p.clone(),
            working_dir: workdirs.get(p).cloned(),
            services: Vec::new(),
            containers: Vec::new(),
            running: 0,
            total: 0,
        });
        if let Some(s) = &c.service
            && !e.services.contains(s)
        {
            e.services.push(s.clone());
        }
        e.containers.push(c.id.clone());
        e.total += 1;
        if c.state == "running" {
            e.running += 1;
        }
    }
    by.into_values().collect()
}

pub async fn project_workdirs(d: &Docker) -> HashMap<String, String> {
    let Ok(list) = d
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await
    else {
        return HashMap::new();
    };
    list.into_iter()
        .filter_map(|c| {
            let l = c.labels?;
            Some((l.get(PROJECT_LABEL)?.clone(), l.get(WORKDIR_LABEL)?.clone()))
        })
        .collect()
}

pub async fn images(d: &Docker) -> anyhow::Result<Vec<ImageView>> {
    let list = d
        .list_images(Some(ListImagesOptionsBuilder::new().all(false).build()))
        .await?;
    let mut v: Vec<ImageView> = list
        .into_iter()
        .map(|i| {
            let tags: Vec<String> = i
                .repo_tags
                .into_iter()
                .filter(|t| t != "<none>:<none>")
                .collect();
            ImageView {
                id: short_id(&i.id),
                dangling: tags.is_empty(),
                tags,
                size: i.size,
                created: i.created * 1000,
                containers: i.containers,
            }
        })
        .collect();
    v.sort_by_key(|i| std::cmp::Reverse(i.created));
    Ok(v)
}

pub async fn volumes(d: &Docker) -> anyhow::Result<Vec<VolumeView>> {
    let res = d.list_volumes(None::<ListVolumesOptions>).await?;
    let used: HashSet<String> = d
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await
        .unwrap_or_default()
        .into_iter()
        .flat_map(|c| c.mounts.unwrap_or_default())
        .filter_map(|m| m.name)
        .collect();
    let mut v: Vec<VolumeView> = res
        .volumes
        .unwrap_or_default()
        .into_iter()
        .map(|x| VolumeView {
            in_use: used.contains(&x.name),
            project: x.labels.get(PROJECT_LABEL).cloned(),
            name: x.name,
            driver: x.driver,
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

pub async fn networks(d: &Docker) -> anyhow::Result<Vec<NetworkView>> {
    let list = d.list_networks(None::<ListNetworksOptions>).await?;
    let mut v: Vec<NetworkView> = list
        .into_iter()
        .map(|n| NetworkView {
            id: short_id(&n.id.unwrap_or_default()),
            name: n.name.unwrap_or_default(),
            driver: n.driver.unwrap_or_default(),
            scope: n.scope.unwrap_or_default(),
            internal: n.internal.unwrap_or(false),
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str, project: Option<&str>, state: &str) -> ContainerLite {
        ContainerLite {
            id: id.into(),
            name: id.into(),
            image: "x".into(),
            state: state.into(),
            status: String::new(),
            project: project.map(str::to_string),
            service: Some(format!("svc-{id}")),
            protected: false,
        }
    }

    #[test]
    fn projects_group_by_label_and_protection() {
        let list = vec![
            c("a", Some("shop"), "running"),
            c("b", Some("shop"), "exited"),
            c("c", None, "running"),
        ];
        let p = projects(&list, &HashMap::new());
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].running, p[0].total), (1, 2));
        let mut l = HashMap::new();
        assert!(is_protected(
            "proxy",
            "tecnativa/docker-socket-proxy:latest",
            &l,
            &[]
        ));
        assert!(!is_protected("web", "nginx", &l, &[]));
        assert!(is_protected("db", "postgres", &l, &["db".into()]));
        l.insert(PROTECT_LABEL.into(), "true".into());
        assert!(is_protected("web", "nginx", &l, &[]));
    }
}
