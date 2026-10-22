use std::{fs, process::Command};

use github_oidc_exchange::policy::Policy;

#[test]
fn rendered_policy_configmaps_are_accepted_by_runtime_parser()
-> Result<(), Box<dyn std::error::Error>> {
    for (source_path, contract, config_map_name) in [
        (
            "docs/policy-contract.example.json",
            "github-oidc-exchange.apelogic.io/v5",
            "github-oidc-exchange-policy",
        ),
        (
            "docs/policy-contract-v6.example.json",
            "github-oidc-exchange.apelogic.io/v6",
            "github-oidc-exchange-policy-v6",
        ),
    ] {
        let source = fs::read_to_string(source_path)?;
        let document: serde_json::Value = serde_json::from_str(&source)?;
        let inline_document = serde_json::to_string(&document)?;
        let set_contract = format!("config.policyContract={contract}");
        let set_config_map_name = format!("config.policyConfigMapName={config_map_name}");
        let set_document = format!("policyConfigMap.document={inline_document}");
        let output = Command::new("helm")
            .args([
                "template",
                "policy-parser",
                "charts/github-oidc-exchange",
                "--show-only",
                "templates/policy-configmap.yaml",
                "-f",
                "charts/github-oidc-exchange/ci/test-values.yaml",
                "--set-string",
                &set_contract,
                "--set-string",
                &set_config_map_name,
                "--set",
                "policyConfigMap.create=true",
                "--set-json",
                &set_document,
            ])
            .output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }

        let rendered = String::from_utf8(output.stdout)?;
        let (_, literal) = rendered
            .split_once("  policy.json: |\n")
            .ok_or("rendered ConfigMap must contain policy.json")?;
        let policy_json = literal
            .lines()
            .map(|line| line.strip_prefix("    ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        let rendered_document: serde_json::Value = serde_json::from_str(&policy_json)?;
        assert_eq!(rendered_document, document);

        let file = tempfile::NamedTempFile::new()?;
        fs::write(file.path(), policy_json)?;
        Policy::load(file.path())?;
    }
    Ok(())
}
