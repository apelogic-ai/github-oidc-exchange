use std::process::Command;

#[test]
fn enabled_workload_exchange_rejects_partial_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!(
        "CARGO_BIN_EXE_github-oidc-exchange-integration-fixture"
    ))
    .arg("serve")
    .env_clear()
    .env("ISSUER_URL", "https://identity.fixture.local")
    .env("OUTPUT_AUDIENCE", "steward-task-api")
    .env("LISTEN_ADDRESS", "127.0.0.1:18080")
    .env("WORKLOAD_EXCHANGE_ENABLED", "true")
    .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("WORKLOAD_OUTPUT_AUDIENCE"));
    Ok(())
}
