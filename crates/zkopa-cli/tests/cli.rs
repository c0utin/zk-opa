//! The whole flow through the `zkopa` binary: keys, bundle, credential, feed, proof, decision.

use std::{fs, path::Path, process::Command};

const NOW: &str = "1700000000000";
const PATH: &str = "transfers/create/allow";

const POLICY: &str = r#"
package transfers.create

allow if {
    input.request.amount <= input.subject.income * 3 / 10
    input.subject.kyc_level >= 2
}
"#;

/// Runs `zkopa` in `dir` and returns whether it succeeded and its stdout.
fn zkopa(dir: &Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_zkopa"))
        .current_dir(dir)
        .args(args)
        .args(["--now-ms", NOW])
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

/// Runs `zkopa` in `dir`, requires success and returns its stdout.
fn ok(dir: &Path, args: &[&str]) -> String {
    let (success, stdout) = zkopa(dir, args);
    assert!(success, "zkopa {args:?} failed: {stdout}");
    stdout
}

fn feed(dir: &Path, sequence: &str, revoke: &[&str], out: &str) {
    let mut args = vec![
        "feed",
        "--root-key",
        "keys/root.key",
        "--sequence",
        sequence,
        "--epoch",
        "40",
        "--session-epochs",
        "2",
        "--min-bundle-version",
        "1",
        "--out",
        out,
    ];
    for id in revoke {
        args.extend(["--revoke-id", id]);
    }
    ok(dir, &args);
}

fn verify(dir: &Path, feed: &str, input: &str) -> (bool, String) {
    zkopa(
        dir,
        &[
            "verify",
            "--bundle",
            "bundle.bin",
            "--root-pub",
            "keys/root.pub",
            "--feed",
            feed,
            "--audience",
            "transfers",
            "--policy",
            PATH,
            "--input",
            input,
            "token.bin",
        ],
    )
}

fn eval(dir: &Path, input: &str) -> String {
    ok(
        dir,
        &[
            "eval",
            "--policy-file",
            "policy.rego",
            "--schema",
            "income,kyc_level",
            "--policy",
            PATH,
            "--input",
            input,
            "--attr",
            "income=10000",
            "--attr",
            "kyc_level=2",
        ],
    )
}

#[test]
fn a_token_is_allowed_for_its_input_and_denied_for_another_input_or_after_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    fs::write(dir.join("policy.rego"), POLICY).unwrap();
    fs::write(dir.join("input.json"), r#"{"request.amount": 3000}"#).unwrap();
    fs::write(dir.join("changed.json"), r#"{"request.amount": 2999}"#).unwrap();
    fs::write(dir.join("over.json"), r#"{"request.amount": 3001}"#).unwrap();

    ok(dir, &["keygen", "--out", "keys"]);
    ok(
        dir,
        &[
            "build",
            "policy.rego",
            "--schema",
            "income,kyc_level",
            "--root-key",
            "keys/root.key",
            "--issuer",
            "keys/issuer.pub",
            "--out",
            "bundle.bin",
            "--prover-out",
            "prover.bin",
        ],
    );
    assert_eq!(
        ok(dir, &["inspect", "bundle.bin"]),
        "version 1, window 30000 ms, stale after 3600000 ms, sessions last 2 epochs\n\
         transfers/create/allow\n  request.amount u64\n"
    );
    ok(
        dir,
        &[
            "issue",
            "--issuer-key",
            "keys/issuer.key",
            "--schema",
            "income,kyc_level",
            "--id",
            "7",
            "--attr",
            "kyc_level=2",
            "--attr",
            "income=10000",
            "--exp",
            "50",
            "--out",
            "cred.bin",
        ],
    );
    feed(dir, "1", &[], "feed-1.bin");
    ok(
        dir,
        &[
            "prove",
            "--prover",
            "prover.bin",
            "--cred",
            "cred.bin",
            "--epoch",
            "40",
            "--audience",
            "transfers",
            "--policy",
            PATH,
            "--input",
            "input.json",
            "--out",
            "token.bin",
        ],
    );

    let (allowed, stdout) = verify(dir, "feed-1.bin", "input.json");
    assert!(allowed, "{stdout}");
    assert_eq!(stdout, "allow\n  request.amount = 3000\n");

    let (allowed, stdout) = verify(dir, "feed-1.bin", "changed.json");
    assert!(!allowed);
    assert!(
        stdout.starts_with("deny: the request proof does not verify\n"),
        "{stdout}"
    );

    feed(dir, "2", &["7"], "feed-2.bin");
    let (allowed, stdout) = verify(dir, "feed-2.bin", "input.json");
    assert!(!allowed);
    assert!(
        stdout.starts_with("deny: the revocation tag is revoked\n"),
        "{stdout}"
    );

    // 30% of 10000 is exactly 3000.
    assert_eq!(eval(dir, "input.json"), "true\n");
    assert_eq!(eval(dir, "over.json"), "false\n");
}
