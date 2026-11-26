//! Daemon side of the helper protocol: one call per connection.

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::proto::{Actor, ErrorCode, OpError, OpResult, Reply, Request, VERSION};

/// Upper bound for one call (an image pull can take a while).
const CALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Sends one request and calls `on_log` for each log line; returns the terminal result.
pub async fn call_raw(
    socket: &Path,
    secret: &str,
    call: &str,
    args: Value,
    dry_run: bool,
    actor: Actor,
    mut on_log: impl FnMut(String),
) -> OpResult<Value> {
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::UnixStream::connect(socket),
    )
    .await
    .map_err(|_| OpError::new(ErrorCode::Unsupported, "连接运维助手超时"))?
    .map_err(|e| {
        OpError::new(
            ErrorCode::Unsupported,
            format!("无法连接运维助手（{}）：{e}", socket.display()),
        )
    })?;
    let (r, mut w) = stream.into_split();
    let req = Request {
        v: VERSION,
        auth: secret.to_string(),
        call: call.to_string(),
        args,
        dry_run,
        actor,
    };
    let mut line = serde_json::to_string(&req).map_err(|e| OpError::failed(e.to_string()))?;
    line.push('\n');
    w.write_all(line.as_bytes())
        .await
        .map_err(|e| OpError::failed(format!("发送请求失败：{e}")))?;
    let fut = async {
        let mut lines = BufReader::new(r).lines();
        while let Some(l) = lines
            .next_line()
            .await
            .map_err(|e| OpError::failed(format!("读取助手响应失败：{e}")))?
        {
            match serde_json::from_str::<Reply>(&l) {
                Ok(Reply::Log { line }) => on_log(line),
                Ok(Reply::Result { data }) => return Ok(data),
                Ok(Reply::Error { code, message }) => return Err(OpError::new(code, message)),
                // tolerate unknown lines from a newer helper
                Err(_) => {}
            }
        }
        Err(OpError::failed("运维助手未返回结果就断开了连接"))
    };
    tokio::time::timeout(CALL_TIMEOUT, fut)
        .await
        .map_err(|_| OpError::failed("运维助手调用超时"))?
}
