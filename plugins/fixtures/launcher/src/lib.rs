//! A `vm-plugin` that misbehaves on request, so the tests can show what pm refuses
//! from one.
//!
//! What it does is picked by the machine's title, which pm sets to
//! `pm run: <entrypoint>`, so a test chooses the behaviour by naming the entrypoint.
//! Its launchers include a name pm must refuse to keep, beside two it keeps.

wit_bindgen::generate!({ path: "../../../wit", world: "vm-plugin" });

use pm::plugin::types::LaunchFile;

struct Launcher;

impl Guest for Launcher {
    fn describe() -> Manifest {
        Manifest {
            name: "launcher-fixture".into(),
            version: "0.1.0".into(),
            summary: "Launches machines, some of them badly".into(),
            hooks: Vec::new(),
            grants_at_most: Vec::new(),
            source_extensions: Vec::new(),
            symbols: Vec::new(),
        }
    }

    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }

    fn launchers() -> Vec<String> {
        vec!["true".into(), "env".into(), "/bin/sh".into()]
    }

    fn launch_machine(machine: Machine) -> Result<Option<Launch>, String> {
        let launch = |program: &str, args: Vec<String>| Launch {
            program: program.into(),
            args,
            files: vec![LaunchFile {
                name: "note".into(),
                contents: machine.name.clone(),
            }],
        };
        match machine.title.rsplit('/').next().unwrap_or_default() {
            "pass" => Ok(None),
            "refuse" => Err("this fixture refuses".into()),
            "unlisted" => Ok(Some(launch("sh", Vec::new()))),
            "path" => Ok(Some(launch("/bin/sh", Vec::new()))),
            "nul" => Ok(Some(launch("env", vec!["a\0b".into()]))),
            _ => Ok(Some(launch("true", vec![machine.directory]))),
        }
    }
}

export!(Launcher);
