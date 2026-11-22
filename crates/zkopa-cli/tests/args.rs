//! Command lines a user gets wrong are refused with exit code 2 before anything runs.

use std::{fs, path::Path, process::Command};

const USAGE_EXIT: i32 = 2;

const POLICY: &str = r#"
package transfers.create

allow if {
    input.request.amount <= input.subject.income * 3 / 10
}
"#;

/// Runs `zkopa` in `dir` and returns its exit code, stdout and stderr.
fn zkopa(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_zkopa"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn assert_usage_error(dir: &Path, args: &[&str], message: &str) {
    let (code, stdout, stderr) = zkopa(dir, args);
    assert_eq!(code, Some(USAGE_EXIT), "zkopa {args:?}: {stderr}");
    assert_eq!(stdout, "");
    assert!(
        stderr.starts_with(&format!("error: {message}")),
        "zkopa {args:?}: {stderr}"
    );
}

#[test]
fn an_unknown_flag_is_refused_before_the_command_runs() {
    let temp = tempfile::tempdir().unwrap();
    assert_usage_error(
        temp.path(),
        &["keygen", "--out", "keys", "--colour", "red"],
        "unknown flag --colour",
    );
    assert!(!temp.path().join("keys").exists());
}

#[test]
fn a_missing_required_flag_is_named() {
    let temp = tempfile::tempdir().unwrap();
    assert_usage_error(
        temp.path(),
        &[
            "build",
            "policy.rego",
            "--schema",
            "income",
            "--issuer",
            "issuer.pub",
            "--out",
            "bundle.bin",
            "--prover-out",
            "prover.bin",
        ],
        "missing required flag --root-key",
    );
}

#[test]
fn a_number_that_does_not_parse_or_fit_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    // A credential id is a u32 leaf index, so one past its maximum must not wrap or widen.
    for id in ["seven", "-1", "4294967296"] {
        assert_usage_error(
            temp.path(),
            &[
                "issue",
                "--issuer-key",
                "issuer.key",
                "--schema",
                "income",
                "--id",
                id,
                "--attr",
                "income=1",
                "--exp",
                "50",
                "--out",
                "cred.bin",
            ],
            &format!("invalid value '{id}' for --id"),
        );
    }
}

#[test]
fn name_equals_value_means_the_same_as_name_then_value() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    fs::write(dir.join("policy.rego"), POLICY).unwrap();
    fs::write(dir.join("input.json"), r#"{"request.amount": 3000}"#).unwrap();
    let eval = |args: &[&str]| {
        let (code, stdout, stderr) = zkopa(dir, args);
        assert_eq!(code, Some(0), "zkopa {args:?}: {stderr}");
        stdout
    };

    let spaced = eval(&[
        "eval",
        "--policy-file",
        "policy.rego",
        "--schema",
        "income",
        "--policy",
        "transfers/create/allow",
        "--input",
        "input.json",
        "--attr",
        "income=10000",
    ]);
    // Only the first `=` separates the flag from its value: `--attr`'s value has its own.
    let joined = eval(&[
        "eval",
        "--policy-file=policy.rego",
        "--schema=income",
        "--policy=transfers/create/allow",
        "--input=input.json",
        "--attr=income=10000",
    ]);
    assert_eq!(spaced, "true\n");
    assert_eq!(joined, spaced);
}
