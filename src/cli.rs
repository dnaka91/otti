use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::Shell;

#[derive(Parser)]
#[command(about, author, version, propagate_version = true)]
pub struct Opt {
    #[command(subcommand)]
    pub cmd: Option<Command>,
}

impl Opt {
    pub fn parse() -> Self {
        <Opt as Parser>::parse()
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Import OTP accounts from another application.
    Import {
        /// Optional password if the file is protected.
        #[arg(short, long)]
        password: Option<String>,
        /// Provider/application that this file came from.
        #[arg(value_enum)]
        provider: Provider,
        /// The file to import.
        #[arg(value_hint = ValueHint::FilePath)]
        file: PathBuf,
    },
    /// Export OTP accounts to another application.
    Export {
        /// Optional password to protect the file.
        #[arg(short, long)]
        password: Option<String>,
        /// Provider/application that this file will be imported into.
        #[arg(value_enum)]
        provider: Provider,
        /// Target location of the file. Defaults to `<provider>-export.<ext>` in the current
        /// folder, where the extension depends on the provider's format.
        #[arg(value_hint = ValueHint::FilePath)]
        file: Option<PathBuf>,
    },
    /// Search for a single account and print the current OTP.
    Show {
        issuer: String,
        label: Option<String>,
    },
    /// Generate auto-completion scripts for various shells.
    Completions {
        /// Shell to generate an auto-completion script for.
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Generate man pages into the given directory.
    Manpages {
        /// Target directory, that must already exist and be empty. If the any file with the same
        /// name as any of the man pages already exist, it'll not be overwritten, but instead an
        /// error be returned.
        #[arg(value_hint = ValueHint::DirPath)]
        dir: PathBuf,
    },
}

/// Possible supported providers for data import/export.
#[derive(Clone, Copy, ValueEnum)]
pub enum Provider {
    /// Aegis authenticator.
    Aegis,
    /// Android OTP Authenticator.
    AndOtp,
    /// Authenticator Pro.
    AuthPro,
}

impl Provider {
    pub fn export_name(self, with_password: bool) -> &'static str {
        match self {
            Self::Aegis => {
                if with_password {
                    "aegis-export.json"
                } else {
                    "aegis-export-plain.json"
                }
            }
            Self::AndOtp => {
                if with_password {
                    "and-otp-export.json.aes"
                } else {
                    "and-otp-export.json"
                }
            }
            Self::AuthPro => {
                if with_password {
                    "auth-pro-export.authpro"
                } else {
                    "auth-pro-export.json"
                }
            }
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn completions(shell: Shell) -> Result<()> {
    clap_complete::generate(
        shell,
        &mut Opt::command(),
        env!("CARGO_PKG_NAME"),
        &mut io::stdout().lock(),
    );
    Ok(())
}

pub fn manpages(dir: &Path) -> Result<()> {
    fn print(dir: &Path, app: &clap::Command) -> Result<()> {
        let name = app.get_display_name().unwrap_or_else(|| app.get_name());
        let out = dir.join(format!("{name}.1"));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .with_context(|| format!("the file `{}` already exists", out.display()))?;

        clap_mangen::Man::new(app.clone()).render(&mut out)?;
        out.flush()?;

        for sub in app.get_subcommands() {
            print(dir, sub)?;
        }

        Ok(())
    }

    ensure!(dir.try_exists()?, "target directory doesn't exist");

    let mut app = Opt::command();
    app.build();

    print(dir, &app)
}
