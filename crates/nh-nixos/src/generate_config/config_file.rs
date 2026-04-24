//! Minimal INI-ish parser for `/etc/nixos-generate-config.conf`.
//!
//! Matches the upstream perl (`Config::IniFiles`) behavior for the keys we
//! actually care about: `[Defaults]` with `Directory`, `RootDirectory`,
//! `Kernel`, `Flake`. Values are trimmed; comments (`;` or `#`) and blank
//! lines are ignored; unknown sections/keys are silently skipped.

use std::path::Path;

use color_eyre::eyre::{Context, Result};

pub const DEFAULT_PATH: &str = "/etc/nixos-generate-config.conf";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigFile {
  pub directory:      Option<String>,
  pub root_directory: Option<String>,
  pub kernel:         Option<String>,
  pub flake:          Option<bool>,
}

impl ConfigFile {
  /// Read and parse the default config file if it exists. Returns a default
  /// (all-`None`) config when the file is missing.
  ///
  /// # Errors
  ///
  /// Returns an error when the file exists but cannot be read, or when it
  /// contains a malformed line.
  pub fn load_default() -> Result<Self> {
    Self::load(Path::new(DEFAULT_PATH))
  }

  /// Read and parse the config at an explicit path.
  ///
  /// # Errors
  ///
  /// As [`Self::load_default`].
  pub fn load(path: &Path) -> Result<Self> {
    match std::fs::read_to_string(path) {
      Ok(body) => {
        parse(&body)
          .wrap_err_with(|| format!("Failed to parse {}", path.display()))
      },
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
      Err(e) => {
        Err(e).wrap_err_with(|| format!("Failed to read {}", path.display()))
      },
    }
  }
}

fn parse(body: &str) -> Result<ConfigFile> {
  let mut cfg = ConfigFile::default();
  let mut in_defaults = false;
  for (lineno, raw) in body.lines().enumerate() {
    let line = strip_comment(raw).trim();
    if line.is_empty() {
      continue;
    }
    if let Some(section) =
      line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
      in_defaults = section.trim().eq_ignore_ascii_case("Defaults");
      continue;
    }
    if !in_defaults {
      continue;
    }
    let Some((key, value)) = line.split_once('=') else {
      color_eyre::eyre::bail!(
        "line {}: expected 'key = value', got {raw:?}",
        lineno + 1
      );
    };
    let key = key.trim();
    let value = value.trim().trim_matches('"').to_owned();
    match key {
      "Directory" => cfg.directory = Some(value),
      "RootDirectory" => cfg.root_directory = Some(value),
      "Kernel" => cfg.kernel = Some(value),
      "Flake" => cfg.flake = Some(parse_bool(&value)),
      _ => { /* ignore unknown keys */ },
    }
  }
  Ok(cfg)
}

fn strip_comment(line: &str) -> &str {
  // Perl's Config::IniFiles treats both `;` and `#` as comment starters.
  // Find the first unquoted one.
  let mut in_quotes = false;
  for (i, c) in line.char_indices() {
    match c {
      '"' => in_quotes = !in_quotes,
      ';' | '#' if !in_quotes => return &line[..i],
      _ => {},
    }
  }
  line
}

/// Boolean parsing for the INI's `Flake` key.
///
/// Recognized truthy values (case-insensitive): `1`, `true`, `yes`, `on`.
/// Everything else — including `0`, `false`, `no`, `off`, the empty
/// string, and any other word — is treated as falsy.
///
/// This is intentionally narrower than perl's `Config::IniFiles` reading
/// of arbitrary scalars (which inherits Perl's truthiness rules: any
/// non-empty, non-`"0"` string is true). `Flake = no` and `Flake = off`
/// would be true under perl but are false here. The values nixpkgs
/// actually sets in this file are `true`/`false`/`1`/`0`, all of which
/// match perl, so this should not affect normal configurations.
fn parse_bool(v: &str) -> bool {
  matches!(
    v.trim().to_ascii_lowercase().as_str(),
    "1" | "true" | "yes" | "on"
  )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests panic on failure")]
mod tests {
  use super::*;

  #[test]
  fn parses_all_keys() {
    let body = "[Defaults]\nDirectory = /custom/dir\nRootDirectory = \
                /mnt\nKernel = latest\nFlake = true\n";
    let cfg = parse(body).unwrap();
    assert_eq!(cfg.directory.as_deref(), Some("/custom/dir"));
    assert_eq!(cfg.root_directory.as_deref(), Some("/mnt"));
    assert_eq!(cfg.kernel.as_deref(), Some("latest"));
    assert_eq!(cfg.flake, Some(true));
  }

  #[test]
  fn strips_quotes_and_comments() {
    let body = "# top-level comment\n[Defaults]  ; inline\nDirectory = \
                \"/etc/nixos\"   # trailing\n";
    let cfg = parse(body).unwrap();
    assert_eq!(cfg.directory.as_deref(), Some("/etc/nixos"));
  }

  #[test]
  fn ignores_other_sections() {
    let body = "[Other]\nDirectory = /no\n[Defaults]\nKernel = lts\n";
    let cfg = parse(body).unwrap();
    assert_eq!(cfg.directory, None);
    assert_eq!(cfg.kernel.as_deref(), Some("lts"));
  }

  #[test]
  fn flake_bool_variants() {
    for (s, expected) in [
      ("1", true),
      ("true", true),
      ("True", true),
      ("yes", true),
      ("on", true),
      ("0", false),
      ("false", false),
      ("", false),
    ] {
      let cfg = parse(&format!("[Defaults]\nFlake = {s}\n")).unwrap();
      assert_eq!(cfg.flake, Some(expected), "input: {s:?}");
    }
  }

  #[test]
  fn empty_or_missing_is_default() {
    assert_eq!(parse("").unwrap(), ConfigFile::default());
    assert_eq!(parse("# just a comment\n").unwrap(), ConfigFile::default());
  }

  #[test]
  fn malformed_line_errors() {
    assert!(parse("[Defaults]\nno equals\n").is_err());
  }
}
