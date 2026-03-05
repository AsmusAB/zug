use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub enum Command {
    Encrypt {
        password: String,
        hint: Option<String>,
        paths: Vec<PathBuf>,
    },
    Decrypt {
        password: String,
        paths: Vec<PathBuf>,
    },
    Hint {
        path: PathBuf,
    },
}

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Encrypt one or more files
    Encrypt {
        /// Password
        #[arg(long)]
        password: Option<String>,
        /// Optional hint embedded in the encrypted file
        #[arg(long)]
        hint: Option<String>,
        /// Files to encrypt
        paths: Vec<PathBuf>,
    },
    /// Decrypt one or more files
    Decrypt {
        /// Password
        #[arg(long)]
        password: Option<String>,
        /// Files to decrypt
        paths: Vec<PathBuf>,
    },
    /// Show the hint stored in an encrypted file
    Hint {
        /// Encrypted file
        path: PathBuf,
    },
}

pub fn parse() -> Command {
    let cli = Cli::parse();
    match cli.command {
        CliCommand::Encrypt {
            password,
            hint,
            paths,
        } => Command::Encrypt {
            password: resolve_password(password, "Encryption password: "),
            hint,
            paths,
        },
        CliCommand::Decrypt { password, paths } => Command::Decrypt {
            password: resolve_password(password, "Decryption password: "),
            paths,
        },
        CliCommand::Hint { path } => Command::Hint { path },
    }
}

fn resolve_password(password: Option<String>, prompt: &str) -> String {
    match password {
        Some(pw) => pw,
        None => rpassword::prompt_password(prompt).unwrap_or_else(|e| {
            eprintln!("Error: could not read password: {e}");
            std::process::exit(1);
        }),
    }
}
