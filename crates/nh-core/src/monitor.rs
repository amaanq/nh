use std::{
  env::{var, var_os},
  io::{ErrorKind, IsTerminal, Stderr, Write, stderr},
  time::{Duration, Instant},
};

use color_eyre::{
  Result,
  eyre::{Context, bail},
};
use rom::{
  cache::BuildReportCache,
  display::format_log,
  monitor::{FilesystemResolver, Output, Processed, StreamEngine},
  state::current_time,
  terminal::{Admission, LiveTerminal, admission},
  types::{EngineConfig, RenderConfig},
};
use subprocess::{Exec, ExitStatus, Redirection};
use tracing::{debug, warn};

const FRAME_INTERVAL: Duration = Duration::from_millis(50);

#[expect(clippy::missing_errors_doc, reason = "Internal execution adapter")]
pub fn run_monitored(
  command: Exec,
  mut stdout: impl Write,
  interrupted: impl Fn() -> bool,
) -> Result<ExitStatus> {
  let mut monitor = BuildMonitor::new()?;
  let configured = command.stdout(Redirection::Pipe).stderr(Redirection::Pipe);
  debug!(?configured);
  let mut job = configured
    .start()
    .wrap_err("Failed to start monitored build")?;

  let result = (|| {
    let mut communicator = job
      .communicate()?
      .limit_time(FRAME_INTERVAL)
      .limit_size(64 * 1024);
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut last_frame = Instant::now();
    let mut input_done = false;

    loop {
      if interrupted() {
        bail!("Operation interrupted by user");
      }

      if input_done {
        if let Some(status) = job.wait_timeout(FRAME_INTERVAL)? {
          monitor.finish()?;
          return Ok(status);
        }
      } else {
        stdout_bytes.clear();
        stderr_bytes.clear();
        let read_result =
          communicator.read_to(&mut stdout_bytes, &mut stderr_bytes);
        input_done = read_result.is_ok()
          && stdout_bytes.is_empty()
          && stderr_bytes.is_empty();
        stdout.write_all(&stdout_bytes)?;
        stdout.flush()?;
        monitor.push(&stderr_bytes)?;
        if let Err(error) = read_result
          && error.kind() != ErrorKind::TimedOut
        {
          return Err(error.into());
        }
      }

      if last_frame.elapsed() >= FRAME_INTERVAL {
        monitor.render(false)?;
        last_frame = Instant::now();
      }
    }
  })();

  if result.is_err() {
    if let Err(error) = job.kill() {
      warn!("Failed to stop monitored build, {error}");
    }
    job.wait().wrap_err("Failed to reap monitored build")?;
  }

  result
}

struct BuildMonitor {
  stream:   StreamEngine,
  terminal: LiveTerminal<Stderr>,
  render:   RenderConfig,
  history:  BuildReportCache,
}

impl BuildMonitor {
  fn new() -> Result<Self> {
    let history =
      BuildReportCache::new(BuildReportCache::default_cache_path()?);
    let mut stream = StreamEngine::new(EngineConfig::default());
    stream.engine_mut().set_resolver(FilesystemResolver);
    stream.engine_mut().load_history(&history);

    let ansi = stderr().is_terminal()
      && var_os("NO_COLOR").is_none()
      && var("TERM").as_deref() != Ok("dumb");
    let mut terminal = LiveTerminal::new(stderr());
    if !ansi || admission() != Admission::Live {
      terminal.retire()?;
    }

    Ok(Self {
      stream,
      terminal,
      render: RenderConfig {
        ansi,
        ..RenderConfig::default()
      },
      history,
    })
  }

  fn push(&mut self, bytes: &[u8]) -> Result<()> {
    let processed = self.stream.push_at(bytes, current_time())?;
    self.output(processed)
  }

  fn output(&mut self, processed: Processed) -> Result<()> {
    for output in processed.output {
      match output {
        Output::Passthrough(bytes) => {
          self.terminal.write_passthrough(&bytes)?;
        },
        Output::Log(line) => {
          let formatted = format_log(&line, &self.render);
          self.terminal.write_passthrough(formatted.as_bytes())?;
          self.terminal.write_passthrough(b"\n")?;
        },
      }
    }
    Ok(())
  }

  fn render(&mut self, final_render: bool) -> Result<()> {
    self.terminal.render(
      self.stream.engine().state(),
      &self.render,
      current_time(),
      final_render,
    )?;
    Ok(())
  }

  fn finish(&mut self) -> Result<()> {
    let processed = self.stream.finish_at(current_time())?;
    self.output(processed)?;
    self.render(true)?;
    if self.terminal.is_retired() {
      self.terminal.append_final(
        self.stream.engine().state(),
        &self.render,
        current_time(),
      )?;
    }
    self.terminal.finish()?;
    if let Err(error) = self.stream.engine().save_history(&self.history) {
      warn!("Failed to save rom build history, {error}");
    }
    Ok(())
  }
}
