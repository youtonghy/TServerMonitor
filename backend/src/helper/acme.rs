//! ACME (RFC 8555) client used by the helper to issue certificates with HTTP-01 challenges.
//! Behind the [`Issuer`] trait so the issuance flow can be tested without a CA.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};

use super::Log;
use super::config::AcmeConfig;
use super::fsutil;
use crate::ops::proto::{OpError, OpResult};

/// One HTTP-01 challenge: serve `key_auth` at `/.well-known/acme-challenge/<token>`.
pub struct Challenge {
    pub domain: String,
    pub token: String,
    pub key_auth: String,
}

pub struct Issued {
    pub chain_pem: String,
    pub key_pem: String,
}

pub struct IssueRequest<'a> {
    pub domains: &'a [String],
    /// Makes a challenge answerable; called before the CA is told to validate it.
    pub publish: &'a (dyn Fn(&Challenge) -> OpResult<()> + Send + Sync),
    pub log: &'a Log,
}

pub trait Issuer: Send + Sync {
    fn issue<'a>(&'a self, req: IssueRequest<'a>) -> BoxFuture<'a, OpResult<Issued>>;
}

/// The real client.
pub struct AcmeClient {
    cfg: AcmeConfig,
    dir: PathBuf,
}

impl AcmeClient {
    pub fn new(cfg: AcmeConfig, state_dir: &Path) -> Self {
        Self {
            cfg,
            dir: state_dir.join("acme"),
        }
    }

    fn builder(&self) -> OpResult<instant_acme::AccountBuilder> {
        match &self.cfg.ca_file {
            Some(ca) => Account::builder_with_root(ca),
            None => Account::builder(),
        }
        .map_err(acme_err)
    }

    /// Loads the stored account for the configured directory or registers a new one.
    async fn account(&self, log: &Log) -> OpResult<Account> {
        let url = self.cfg.directory_url().to_string();
        let path = self.dir.join(format!(
            "account-{}.json",
            &fsutil::sha256_hex(url.as_bytes())[..12]
        ));
        if let Ok(data) = std::fs::read(&path) {
            let creds: AccountCredentials = serde_json::from_slice(&data)
                .map_err(|e| OpError::failed(format!("ACME 账户文件损坏：{e}")))?;
            return self
                .builder()?
                .from_credentials(creds)
                .await
                .map_err(acme_err);
        }
        log.line(format!("在 {url} 注册 ACME 账户"));
        let contact = self
            .cfg
            .email
            .as_ref()
            .map(|e| format!("mailto:{e}"))
            .into_iter()
            .collect::<Vec<_>>();
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, creds) = self
            .builder()?
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url,
                None,
            )
            .await
            .map_err(acme_err)?;
        std::fs::create_dir_all(&self.dir).map_err(|e| OpError::failed(e.to_string()))?;
        let data = serde_json::to_vec(&creds).map_err(|e| OpError::failed(e.to_string()))?;
        fsutil::atomic_write_mode(&path, &data, 0o600)?;
        Ok(account)
    }
}

fn acme_err(e: instant_acme::Error) -> OpError {
    OpError::failed(format!("ACME：{e}"))
}

impl Issuer for AcmeClient {
    fn issue<'a>(&'a self, req: IssueRequest<'a>) -> BoxFuture<'a, OpResult<Issued>> {
        Box::pin(async move {
            let account = self.account(req.log).await?;
            let ids: Vec<Identifier> = req
                .domains
                .iter()
                .map(|d| Identifier::Dns(d.clone()))
                .collect();
            let mut order = account
                .new_order(&NewOrder::new(&ids))
                .await
                .map_err(acme_err)?;
            {
                let mut auths = order.authorizations();
                while let Some(a) = auths.next().await {
                    let mut authz = a.map_err(acme_err)?;
                    let domain = authz.identifier().to_string();
                    match authz.status {
                        AuthorizationStatus::Valid => {
                            req.log
                                .line(format!("{domain} 已通过验证（沿用之前的授权）"));
                            continue;
                        }
                        AuthorizationStatus::Pending => {}
                        s => {
                            return Err(OpError::failed(format!(
                                "{domain} 的授权状态为 {s:?}，无法继续"
                            )));
                        }
                    }
                    let mut ch = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                        OpError::failed(format!("CA 没有为 {domain} 提供 HTTP-01 验证"))
                    })?;
                    (req.publish)(&Challenge {
                        domain: domain.clone(),
                        token: ch.token.clone(),
                        key_auth: ch.key_authorization().as_str().to_string(),
                    })?;
                    req.log.line(format!("请求 CA 验证 {domain}"));
                    ch.set_ready().await.map_err(acme_err)?;
                }
            }
            let status = order
                .poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(120)))
                .await
                .map_err(acme_err)?;
            if status != OrderStatus::Ready {
                let mut why = Vec::new();
                let mut auths = order.authorizations();
                while let Some(Ok(a)) = auths.next().await {
                    for c in &a.challenges {
                        if let Some(e) = &c.error {
                            why.push(format!("{}：{e}", a.identifier()));
                        }
                    }
                }
                return Err(OpError::failed(format!(
                    "域名验证未通过（{status:?}）{}",
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!("：{}", why.join("；"))
                    }
                )));
            }
            req.log.line("验证通过，生成私钥并签发证书");
            let key_pem = order.finalize().await.map_err(acme_err)?;
            let chain_pem = order
                .poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(90)))
                .await
                .map_err(acme_err)?;
            Ok(Issued { chain_pem, key_pem })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Publishes one challenge per domain, checks it was served from `challenge_dir`, then
    /// returns a self-signed certificate. `fail` makes validation fail instead.
    pub(crate) struct FakeIssuer {
        pub challenge_dir: PathBuf,
        pub fail: Mutex<bool>,
        pub calls: Mutex<u32>,
    }

    impl Issuer for FakeIssuer {
        fn issue<'a>(&'a self, req: IssueRequest<'a>) -> BoxFuture<'a, OpResult<Issued>> {
            Box::pin(async move {
                *self.calls.lock().unwrap() += 1;
                for d in req.domains {
                    let c = Challenge {
                        domain: d.clone(),
                        token: format!("tok-{}", d.replace('.', "_")),
                        key_auth: format!("auth-{d}"),
                    };
                    (req.publish)(&c)?;
                    let served = std::fs::read_to_string(self.challenge_dir.join(&c.token))
                        .map_err(|e| OpError::failed(format!("challenge not served: {e}")))?;
                    assert_eq!(served, c.key_auth);
                }
                if *self.fail.lock().unwrap() {
                    return Err(OpError::failed("域名验证未通过（Invalid）"));
                }
                let names: Vec<&str> = req.domains.iter().map(String::as_str).collect();
                let (chain_pem, key_pem) = crate::helper::nginx_cert::tests::self_signed(&names);
                Ok(Issued { chain_pem, key_pem })
            })
        }
    }
}
