//! HLX-108: shell script places a call end-to-end and asserts on printed outcome.
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn resolve_uat_node(uat_bin: &Path, workspace_root: &Path) -> PathBuf {
    let sibling = uat_bin
        .parent()
        .expect("uat parent")
        .join("uat-node");
    if sibling.is_file() {
        return sibling;
    }
    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "uat-node", "--bin", "uat-node"])
        .current_dir(workspace_root)
        .status()
        .expect("cargo build uat-node");
    assert!(status.success(), "failed to build uat-node for e2e");
    assert!(
        sibling.is_file(),
        "uat-node missing after build at {}",
        sibling.display()
    );
    sibling
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_call_shell_script_asserts_completed() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.join("../..");
    let script = workspace_root
        .join("scripts/e2e-call.sh")
        .canonicalize()
        .expect("scripts/e2e-call.sh");

    let uat = PathBuf::from(env!("CARGO_BIN_EXE_uat"));
    let uat_node = resolve_uat_node(&uat, &workspace_root);

    let output = tokio::process::Command::new(&script)
        .env("UAT_BIN", &uat)
        .env("UAT_NODE_BIN", &uat_node)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run e2e-call.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "e2e-call.sh failed status={} stdout={stdout} stderr={stderr}",
        output.status
    );
    assert!(
        stdout.contains("outcome=Completed"),
        "missing Completed in stdout={stdout}"
    );
    assert!(
        stdout.contains("e2e-call: ok"),
        "missing ok banner in stdout={stdout}"
    );
}
