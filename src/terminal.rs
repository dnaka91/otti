use std::{
    io::{self, Write},
    thread,
};

use anyhow::Result;
use crossbeam_channel::Receiver;
use crossterm::{
    event::{Event, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, SetTitle},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

pub fn create() -> Result<Terminal<impl Backend>> {
    let stdout = RawTerminal::new(io::stdout())?;
    let stdout = AlternateScreen::new(stdout)?;
    let mut backend = CrosstermBackend::new(stdout);

    execute!(&mut backend, SetTitle("Otti"))?;

    Terminal::new(backend).map_err(Into::into)
}

struct RawTerminal<W: Write> {
    output: W,
}

impl<W: Write> RawTerminal<W> {
    fn new(output: W) -> Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(Self { output })
    }
}

impl<W: Write> Drop for RawTerminal<W> {
    fn drop(&mut self) {
        crossterm::terminal::disable_raw_mode().expect("disable raw mode");
    }
}

impl<W: Write> Write for RawTerminal<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

struct AlternateScreen<W: Write> {
    output: W,
}

impl<W: Write> AlternateScreen<W> {
    fn new(mut output: W) -> Result<Self> {
        execute!(output, EnterAlternateScreen)?;
        Ok(Self { output })
    }
}

impl<W: Write> Drop for AlternateScreen<W> {
    fn drop(&mut self) {
        execute!(self.output, LeaveAlternateScreen).expect("switch to main screen");
    }
}

impl<W: Write> Write for AlternateScreen<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

pub fn create_event_listener() -> Receiver<KeyEvent> {
    let (tx, rx) = crossbeam_channel::bounded(0);

    thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            if let Event::Key(k) = event {
                if tx.send(k).is_err() {
                    break;
                }
            }
        }
    });

    rx
}
