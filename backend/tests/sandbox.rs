//! Runs real Python through the `tsmonitor __sandbox-exec` launcher.

use std::path::{Path, PathBuf};

use tsmonitor::config::SandboxConfig;
use tsmonitor::sandbox::{Sandbox, probe, which};

fn sandbox(dir: &Path) -> Sandbox {
    let cfg = SandboxConfig {
        timeout_secs: 3,
        max_output_bytes: 1024,
        ..Default::default()
    };
    Sandbox::init(dir, cfg)
        .unwrap()
        .with_launcher(PathBuf::from(env!("CARGO_BIN_EXE_tsmonitor")))
}

#[tokio::test]
async fn runs_python_with_timeout_and_output_cap() {
    if which("python3").is_none() {
        eprintln!("python3 not available, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let s = sandbox(dir.path());
    s.write_script("hello.py", "import os, sys\nprint('cwd', os.getcwd())\nprint('key', os.environ.get('TSM_LLM_API_KEY'))\nprint(sys.argv[1])")
        .unwrap();
    // SAFETY: set before any other thread of this test reads the environment.
    unsafe { std::env::set_var("TSM_LLM_API_KEY", "should-not-leak") };
    let out = s
        .run_python("scripts/hello.py", &["arg1".into()])
        .await
        .unwrap();
    assert_eq!(out.exit_code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stdout.contains("arg1"));
    assert!(
        out.stdout.contains("key None"),
        "env must be cleared: {}",
        out.stdout
    );

    s.write_script("spin.py", "while True: pass").unwrap();
    let out = s.run_python("scripts/spin.py", &[]).await.unwrap();
    assert!(out.timed_out);

    s.write_script("loud.py", "print('x' * 100000)").unwrap();
    let out = s.run_python("scripts/loud.py", &[]).await.unwrap();
    assert!(out.truncated);
    assert!(out.stdout.len() <= 1100);

    assert!(s.run_python("samples/x.py", &[]).await.is_err());
    assert!(s.run_python("../x.py", &[]).await.is_err());
}

/// Landlock enforcement needs a Linux kernel with Landlock enabled (run in the Linux CI job
/// or `docker run` on a 5.13+ kernel). Skips elsewhere.
#[tokio::test]
async fn landlock_blocks_outside_access() {
    if !cfg!(target_os = "linux") || which("python3").is_none() {
        eprintln!("not linux or no python3, skipping");
        return;
    }
    let level = probe().await;
    if level == "unsupported" || level == "not_enforced" || level == "error" || level == "unknown" {
        // probe() runs current_exe (the test binary); re-probe with the real launcher
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tsmonitor"))
            .args(["__sandbox-exec", "--probe"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        if !text.contains("enforced\"") || text.contains("not_enforced") {
            eprintln!("landlock not available ({text}), skipping");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let s = sandbox(dir.path());
    let outside = dir.path().join("outside.txt");
    s.write_script(
        "escape.py",
        &format!(
            "import socket\ntry:\n  open({:?}, 'w').write('x'); print('WROTE')\nexcept OSError as e: print('blocked-fs', e.errno)\ntry:\n  open('/etc/hostname').read(); print('READ-ETC')\nexcept OSError: print('blocked-etc')\ntry:\n  socket.create_connection(('1.1.1.1', 80), timeout=2); print('NET')\nexcept OSError: print('blocked-net')\nopen('cache/ok.txt','w').write('ok'); print('ws-ok')",
            outside.display().to_string()
        ),
    )
    .unwrap();
    let out = s.run_python("scripts/escape.py", &[]).await.unwrap();
    assert!(out.stdout.contains("blocked-fs"), "{out:?}");
    assert!(out.stdout.contains("blocked-etc"), "{out:?}");
    assert!(out.stdout.contains("ws-ok"), "{out:?}");
    assert!(!outside.exists());
    eprintln!(
        "network: {}",
        if out.stdout.contains("blocked-net") {
            "blocked"
        } else {
            "allowed (kernel < 6.7)"
        }
    );
}
