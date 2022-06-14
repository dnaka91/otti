#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::single_match_else
)]

use std::{
    fs, io,
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::Result;
use arboard::Clipboard;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use crossbeam_channel::select;
use crossterm::event::KeyCode;
use secrecy::SecretString;
use tui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Gauge},
};
use widgets::CodeDialog;

use crate::widgets::{HelpDialog, List, ListState, ScrollBar};

mod terminal;
mod widgets;

#[derive(Parser)]
#[clap(about, author, version)]
struct Opt {
    #[structopt(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import OTP accounts from another application.
    Import {
        /// Optional password if the file is protected.
        #[clap(short, long, value_parser)]
        password: Option<String>,
        /// Provider/application that this file came from.
        #[clap(value_parser, value_enum)]
        provider: Provider,
        /// The file to import.
        #[clap(value_parser)]
        file: PathBuf,
    },
    /// Export OTP accounts to another application.
    Export {
        /// Optional password to protect the file.
        #[clap(short, long, value_parser)]
        password: Option<String>,
        /// Provider/application that this file will be imported into.
        #[clap(value_parser, value_enum)]
        provider: Provider,
        /// Target location of the file. Defaults to `<provider>-export.<ext>` in the current
        /// folder, where the extension depends on the provider's format.
        #[clap(value_parser)]
        file: Option<PathBuf>,
    },
    /// Search for a single account and print the current OTP.
    Show {
        #[clap(value_parser)]
        issuer: String,
        #[clap(value_parser)]
        label: Option<String>,
    },
    /// Generate auto-completion scripts for various shells.
    Completion {
        /// Shell to generate an auto-completion script for.
        #[clap(value_parser, value_enum)]
        shell: Shell,
    },
}

/// Possible supported providers for data import/export.
#[derive(Clone, Copy, ValueEnum)]
enum Provider {
    /// Aegis authenticator.
    Aegis,
    /// Android OTP Authenticator.
    AndOtp,
    /// Authenticator Pro.
    AuthPro,
}

impl Provider {
    fn export_name(self, with_password: bool) -> &'static str {
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

fn main() -> Result<()> {
    let opt = Opt::parse();

    opt.cmd.map_or_else(run, |cmd| match cmd {
        Command::Import {
            password,
            provider,
            file,
        } => import(password, provider, file),
        Command::Export {
            password,
            provider,
            file,
        } => export(password, provider, file),
        Command::Show { issuer, label } => show(&issuer, label.as_deref()),
        Command::Completion { shell } => completion(shell),
    })
}

fn import(password: Option<String>, provider: Provider, file: PathBuf) -> Result<()> {
    let file = fs::read(file)?;

    let accounts = match provider {
        Provider::Aegis => provider_aegis::load(&mut file.as_slice(), password)?,
        Provider::AndOtp => provider_andotp::load(&mut file.as_slice(), password)?,
        Provider::AuthPro => provider_authpro::load(&mut file.as_slice(), password)?,
    };

    println!("Opened backup file");

    if otti_store::exists()? {
        println!("An OTP store already exists");

        let resp = rprompt::prompt_reply_stdout("Overwrite? [yN] ")?;

        if !matches!(resp.as_str(), "y" | "Y") {
            println!("Import cancelled");
            return Ok(());
        }
    }

    println!("Imported {} accounts", accounts.len());

    let password = SecretString::new(rpassword::prompt_password("Store password:")?);

    otti_store::seal(&accounts, &password)?;

    Ok(())
}

fn export(file_password: Option<String>, provider: Provider, file: Option<PathBuf>) -> Result<()> {
    let password = SecretString::new(rpassword::prompt_password("Store password:")?);
    let accounts = otti_store::open(&password)?;
    let file = file.unwrap_or_else(|| PathBuf::from(provider.export_name(file_password.is_some())));

    let mut data = Vec::new();

    match provider {
        Provider::Aegis => provider_aegis::save(&mut data, &accounts, file_password)?,
        Provider::AndOtp => provider_andotp::save(&mut data, &accounts, file_password)?,
        Provider::AuthPro => provider_authpro::save(&mut data, &accounts, file_password)?,
    }

    fs::write(file, data)?;

    Ok(())
}

fn show(issuer: &str, label: Option<&str>) -> Result<()> {
    let password = SecretString::new(rpassword::prompt_password("Password:")?);

    let accounts = otti_store::open(&password)?;
    let issuer = issuer.to_lowercase();
    let label = label.map(str::to_lowercase);

    let acc = accounts.iter().find(|a| {
        a.issuer
            .as_deref()
            .map_or(false, |i| i.to_lowercase().contains(&issuer))
            && label
                .as_deref()
                .map_or(true, |l| a.label.to_lowercase().contains(&l))
    });

    match acc {
        Some(acc) => {
            let code =
                otti_gen::generate::<otti_gen::Sha1>(&acc.secret, &acc.otp, Some(acc.digits))?;

            println!(
                "{} ({})",
                acc.issuer.as_deref().unwrap_or_default(),
                acc.label
            );
            println!("{}", code);
        }
        None => {
            print!("no entry found containing issuer `{}`", issuer,);
            match label {
                Some(label) => println!(" and label `{}`.", label),
                None => println!("."),
            }
        }
    }

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn completion(shell: Shell) -> Result<()> {
    clap_complete::generate(
        shell,
        &mut Opt::command(),
        env!("CARGO_BIN_NAME"),
        &mut io::stdout().lock(),
    );
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum CurrentDialog {
    None,
    Help,
    Code,
}

fn run() -> Result<()> {
    let password = SecretString::new(rpassword::prompt_password("Password:")?);

    let accounts = otti_store::open(&password)?;

    let mut terminal = terminal::create()?;
    let events = terminal::create_event_listener();
    let ticker = crossbeam_channel::tick(Duration::from_millis(1000));
    let mut clipboard = Clipboard::new()?;

    let mut counter = 30 - (UNIX_EPOCH.elapsed()?.as_secs() % 30) as u16;
    let mut list_state = ListState::default();

    let mut showing = CurrentDialog::None;

    'draw: loop {
        let mut otp_code = String::new();
        if showing == CurrentDialog::Code {
            if let Some(acc) = accounts.get(list_state.selection()) {
                otp_code =
                    otti_gen::generate::<otti_gen::Sha1>(&acc.secret, &acc.otp, Some(acc.digits))?
                        .to_string();
            }
        } else if !otp_code.is_empty() {
            otp_code.clear();
        }

        terminal.draw(|f| {
            let area = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Percentage(100)])
                .split(area);

            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL))
                .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                .label(format!("{}s", counter))
                .percent(counter * 100 / 30);

            let list = List::new(&accounts)
                .block(Block::default().borders(Borders::ALL))
                .scrollbar(ScrollBar::default(), 2);

            f.render_widget(gauge, chunks[0]);
            f.render_stateful_widget(list, chunks[1], &mut list_state);

            match showing {
                CurrentDialog::None => {}
                CurrentDialog::Help => f.render_widget(HelpDialog, area),
                CurrentDialog::Code => f.render_widget(CodeDialog::new(&otp_code), area),
            }
        })?;

        let value = select! {
            recv(ticker) -> _ => {
                counter = 30 - (UNIX_EPOCH.elapsed()?.as_secs() % 30) as u16;
                None
            },
            recv(events) -> event => event.ok(),
        };

        if let Some(event) = value {
            match event.code {
                KeyCode::Esc | KeyCode::Char('q') => break 'draw,
                KeyCode::Up => list_state.up(&accounts),
                KeyCode::Down => list_state.down(&accounts),
                KeyCode::Char('h') => toggle_dialog(&mut showing, CurrentDialog::Help),
                KeyCode::Char('s') => toggle_dialog(&mut showing, CurrentDialog::Code),
                KeyCode::Char('c') => {
                    if let Some(acc) = accounts.get(list_state.selection()) {
                        clipboard.set_text(
                            otti_gen::generate::<otti_gen::Sha1>(
                                &acc.secret,
                                &acc.otp,
                                Some(acc.digits),
                            )?
                            .to_string(),
                        )?;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn toggle_dialog(showing: &mut CurrentDialog, dialog: CurrentDialog) {
    *showing = if *showing == dialog {
        CurrentDialog::None
    } else {
        dialog
    };
}
