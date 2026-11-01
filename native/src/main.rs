//! buoy-update-helper: the detached installer started by `install::handoff`,
//! plus maintenance commands for transactions. It never invokes a shell and
//! never requests elevation.
use buoy_updatekit::install::{self, HelperRequest, Process};
use std::{path::PathBuf, process::ExitCode};

const USAGE: &str = "usage:
  buoy-update-helper apply <transaction> --seal <hex> --nonce <hex> --parent <pid>:<identity>
  buoy-update-helper rollback <transaction>
  buoy-update-helper confirm <transaction>
  buoy-update-helper recover <target>
  buoy-update-helper status <transaction>
  buoy-update-helper --version";

fn run(args: &[String]) -> Result<String, String> {
    let path = |i: usize| {
        args.get(i)
            .map(PathBuf::from)
            .ok_or_else(|| USAGE.to_string())
    };
    match args.first().map(String::as_str) {
        Some("--version") if args.len() == 1 => {
            Ok(format!("buoy-update-helper {}", env!("CARGO_PKG_VERSION")))
        }
        Some("apply") if args.len() == 8 => {
            let mut seal = None;
            let mut nonce = None;
            let mut parent = None;
            for pair in args[2..].chunks(2) {
                match pair[0].as_str() {
                    "--seal" if seal.is_none() => seal = Some(pair[1].clone()),
                    "--nonce" if nonce.is_none() => nonce = Some(pair[1].clone()),
                    "--parent" if parent.is_none() => parent = Some(Process::parse(&pair[1])?),
                    _ => return Err(USAGE.into()),
                }
            }
            let request = HelperRequest {
                transaction: path(1)?,
                seal: seal.ok_or(USAGE)?,
                nonce: nonce.ok_or(USAGE)?,
                parent: parent.ok_or(USAGE)?,
            };
            install::run_helper(&request).map(|_| "applied".into())
        }
        Some("rollback") if args.len() == 2 => {
            install::rollback(&path(1)?).map(|_| "rolled_back".into())
        }
        Some("confirm") if args.len() == 2 => {
            install::confirm(&path(1)?).map(|_| "confirmed".into())
        }
        Some("recover") if args.len() == 2 => {
            install::recover(&path(1)?).map(|n| format!("recovered {n} interrupted transaction(s)"))
        }
        Some("status") if args.len() == 2 => install::status(&path(1)?).map(|(state, error)| {
            if error.is_empty() {
                state
            } else {
                format!("{state}: {error}")
            }
        }),
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    // Paths and arguments must be Unicode, matching the transaction journal.
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().ok())
        .collect();
    let result = args
        .ok_or_else(|| "arguments must be valid Unicode".to_string())
        .and_then(|a| run(&a));
    // When detached, these streams are null; the journal records the outcome.
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("buoy-update-helper: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rejects_malformed_invocations() {
        assert!(run(&args(&[])).is_err());
        assert!(run(&args(&["apply", "/tmp/x"])).is_err());
        assert!(run(&args(&[
            "apply", "/tmp/x", "--seal", "a", "--seal", "b", "--parent", "1:2"
        ]))
        .is_err());
        assert!(run(&args(&[
            "apply", "/tmp/x", "--seal", "a", "--nonce", "b", "--parent", "nope"
        ]))
        .is_err());
        assert!(run(&args(&["rollback"])).is_err());
        assert!(run(&args(&["--version"]))
            .unwrap()
            .starts_with("buoy-update-helper"));
    }

    #[test]
    fn maintenance_commands_reject_foreign_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_str().unwrap();
        assert!(run(&args(&["status", path])).is_err());
        assert!(run(&args(&["confirm", "relative"])).is_err());
        assert!(run(&args(&["recover", "relative"])).is_err());
    }
}
