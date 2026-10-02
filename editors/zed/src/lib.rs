use zed_extension_api::{self as zed, Result};

struct PmExtension;

impl zed::Extension for PmExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        if language_server_id.as_ref() != "pm-lsp" {
            return Err(format!("unknown language server ID {language_server_id}"));
        }

        let command = worktree.which("pm-lsp").ok_or_else(|| {
            "pm-lsp was not found in PATH. Build or install pm-lsp and ensure Zed can find it."
                .to_string()
        })?;

        Ok(zed::Command {
            command,
            args: vec![],
            env: Default::default(),
        })
    }
}

zed::register_extension!(PmExtension);
