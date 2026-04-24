//! Native reimplementation of `nixos-generate-config`.

pub mod config_file;
pub mod mount;
pub mod scan;
pub mod template;

use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use color_eyre::eyre::{Context, Result, bail};
use nh_core::command::{Command, ElevationStrategy};
use tracing::{debug, info, warn};

use crate::args::OsGenerateConfigArgs;

const ELEVATED_SENTINEL: &str = "NH_GENCONFIG_ELEVATED";

impl OsGenerateConfigArgs {
  /// Run `nh os generate-config`: scan hardware, render configuration
  /// files, and either print to stdout (`--show-hardware-config`) or
  /// write the output tree.
  ///
  /// # Errors
  ///
  /// Returns an error when hardware scanning fails, when the target
  /// directory is unwritable, or when an elevated re-exec fails. Parse
  /// errors in `/etc/nixos-generate-config.conf` are also surfaced.
  pub fn generate_config(&self, elevation: &ElevationStrategy) -> Result<()> {
    // Config file defaults are merged with CLI args; CLI always wins.
    // Missing file is not an error.
    let file = config_file::ConfigFile::load_default()
      .wrap_err("loading /etc/nixos-generate-config.conf")?;

    let params = Params::from_args_and_file(self, &file)?;

    // Scan hardware and mounts. Both run unprivileged; stop here for
    // --show-hardware-config.
    let hw = scan::scan().wrap_err("hardware scan failed")?;
    let mount = if params.no_filesystems {
      mount::MountScan::default()
    } else {
      mount::scan_mounts(&params.root_dir)
        .wrap_err("parsing /proc/self/mountinfo")?
    };
    let swap_devices = if params.no_filesystems {
      vec![]
    } else {
      mount::scan_swap(&params.root_dir).wrap_err("reading /proc/swaps")?
    };

    let report = build_report(&hw, &mount, swap_devices, params.no_filesystems);

    let hw_config_body = template::render_hardware_config(&report);

    if params.show_hardware_config {
      print!("{hw_config_body}");
      return Ok(());
    }

    // The write path needs root for /etc/nixos. If we're not root, the
    // caller didn't bypass the check, and the target isn't writable by
    // the current user, re-exec under the chosen elevation strategy.
    if !nix::unistd::Uid::effective().is_root()
      && !params.bypass_root_check
      && !matches!(elevation, ElevationStrategy::None)
      && std::env::var(ELEVATED_SENTINEL).is_err()
      && !can_write_to(&params.out_dir)
    {
      return reexec_elevated(elevation);
    }

    write_outputs(&params, &hw_config_body, &hw)?;
    Ok(())
  }
}

/// Collected configuration after CLI + file merge.
#[derive(Debug)]
struct Params {
  out_dir:              PathBuf,
  root_dir:             mount::RootDir,
  force:                bool,
  dry:                  bool,
  no_filesystems:       bool,
  show_hardware_config: bool,
  flake:                bool,
  kernel:               template::Kernel,
  bypass_root_check:    bool,
}

impl Params {
  fn from_args_and_file(
    args: &OsGenerateConfigArgs,
    file: &config_file::ConfigFile,
  ) -> Result<Self> {
    // Directory: CLI > file > "/etc/nixos"
    let out_dir_raw = args
      .dir
      .clone()
      .or_else(|| file.directory.as_deref().map(PathBuf::from))
      .unwrap_or_else(|| PathBuf::from("/etc/nixos"));

    // Root: CLI > file > (none)
    let root_dir_raw: Option<PathBuf> = args
      .root
      .clone()
      .or_else(|| file.root_directory.as_deref().map(PathBuf::from));
    if let Some(ref r) = root_dir_raw
      && r == Path::new("/")
    {
      bail!("no need to specify `/` with `--root`, it is the default");
    }
    let root_dir = mount::RootDir::new(root_dir_raw.as_deref());

    // out_dir gets root_dir prefix only when out_dir is the default; an
    // explicit --dir is absolutified (matches perl's `File::Spec->rel2abs`
    // call). Falling back to `std::path::absolute` makes this work even
    // when the directory doesn't exist yet, which matters for elevated
    // re-execs whose CWD may not be preserved by sudo and for the
    // log line that reports the target path.
    let out_dir = if out_dir_raw == Path::new("/etc/nixos") {
      PathBuf::from(format!("{}/etc/nixos", root_dir.as_str()))
    } else {
      out_dir_raw
        .canonicalize()
        .or_else(|_| std::path::absolute(&out_dir_raw))
        .unwrap_or(out_dir_raw)
    };

    // Kernel: CLI override is flags-based; flag-less means fall back to
    // file, then "lts".
    let kernel_source = args
      .kernel
      .as_deref()
      .or(file.kernel.as_deref())
      .unwrap_or("lts");
    let kernel = match kernel_source {
      "lts" => template::Kernel::Lts,
      "latest" => template::Kernel::Latest,
      other => bail!("invalid --kernel {other:?}: must be 'lts' or 'latest'"),
    };

    // Flake: CLI true > file > false.
    let flake = args.flake || file.flake.unwrap_or(false);

    Ok(Self {
      out_dir,
      root_dir,
      force: args.force,
      dry: args.dry,
      no_filesystems: args.no_filesystems,
      show_hardware_config: args.show_hardware_config,
      flake,
      kernel,
      bypass_root_check: args.bypass_root_check,
    })
  }
}

fn build_report(
  hw: &scan::HwScan,
  mount: &mount::MountScan,
  swap_devices: Vec<String>,
  no_filesystems: bool,
) -> template::HardwareReport {
  let mut attrs = hw.attrs.clone();
  attrs.extend(mount.extra_attrs.iter().cloned());

  template::HardwareReport {
    imports: hw.imports.clone(),
    initrd_available_kernel_mods: hw.initrd_available.clone(),
    initrd_kernel_modules: hw.initrd_kmods.clone(),
    kernel_modules: hw.kmods.clone(),
    extra_module_packages: hw.module_packages.clone(),
    attrs,
    file_systems: mount.file_systems.clone(),
    swap_devices,
    no_filesystems,
  }
}

/// Walk up to the deepest existing ancestor of `path` and check whether
/// the current user has write+search permission there. If every ancestor
/// is missing, conservatively assume we cannot write.
///
/// Requires both `W_OK` (to create entries) and `X_OK` (to traverse the
/// directory). A directory writable but not searchable would let
/// `create_dir_all` fail with `EACCES` after we'd already decided to skip
/// elevation.
fn can_write_to(path: &Path) -> bool {
  use nix::unistd::{AccessFlags, access};

  let mut cur = path;
  loop {
    if cur.exists() {
      return access(cur, AccessFlags::W_OK | AccessFlags::X_OK).is_ok();
    }
    match cur.parent() {
      Some(p) if !p.as_os_str().is_empty() => cur = p,
      _ => return false,
    }
  }
}

fn reexec_elevated(elevation: &ElevationStrategy) -> Result<()> {
  let current_exe = std::env::current_exe()
    .wrap_err("locating current executable for re-exec")?;

  // Skip argv[0] because `--bypass-root-check` is already implied by the
  // re-exec itself, and we want to preserve every other flag the user
  // specified verbatim.
  let argv: Vec<OsString> = std::env::args_os().skip(1).collect();

  info!("Re-executing under elevation to write configuration files");

  Command::new(&current_exe)
    .args(argv)
    .arg("--bypass-root-check")
    .elevate(Some(elevation.clone()))
    .set_env(ELEVATED_SENTINEL, "1")
    .with_required_env()
    .show_output(true)
    .run()
    .wrap_err("elevated nh os generate-config failed")?;
  Ok(())
}

fn write_outputs(
  params: &Params,
  hw_config_body: &str,
  hw: &scan::HwScan,
) -> Result<()> {
  if params.dry {
    info!(
      "(dry-run) would create directory {}",
      params.out_dir.display()
    );
  } else {
    std::fs::create_dir_all(&params.out_dir).wrap_err_with(|| {
      format!("creating output directory {}", params.out_dir.display())
    })?;
  }

  // Always (re)write hardware-configuration.nix.
  let hw_path = params.out_dir.join("hardware-configuration.nix");
  write_or_dry(
    &hw_path,
    hw_config_body,
    // always overwrite
    true,
    params,
  )?;

  // flake.nix — only if --flake and (force || !exists).
  if params.flake {
    let flake_path = params.out_dir.join("flake.nix");
    if params.force || !flake_path.exists() {
      let body = template::render_flake(&template::FlakeCtx {
        hostname: gethostname(),
      });
      write_or_dry(&flake_path, &body, params.force, params)?;
    } else {
      warn!("not overwriting existing {}", flake_path.display());
    }
  }

  // configuration.nix — only if force || !exists.
  let cfg_path = params.out_dir.join("configuration.nix");
  if params.force || !cfg_path.exists() {
    let ctx = template::ConfigurationCtx {
      state_version:         detect_state_version(),
      boot_loader:           select_boot_loader(hw),
      kernel:                params.kernel,
      desktop_configuration: None,
    };
    let body = template::render_configuration(&ctx);
    write_or_dry(&cfg_path, &body, params.force, params)?;
    info!(
      "For more hardware-specific settings, see \
       https://github.com/NixOS/nixos-hardware."
    );
  } else {
    warn!("not overwriting existing {}", cfg_path.display());
  }

  Ok(())
}

fn write_or_dry(
  path: &Path,
  content: &str,
  keep_backup: bool,
  params: &Params,
) -> Result<()> {
  if params.dry {
    info!(
      "(dry-run) would write {} ({} bytes)",
      path.display(),
      content.len()
    );
    return Ok(());
  }
  write_atomic(path, content, keep_backup)?;
  info!("wrote {}", path.display());
  Ok(())
}

fn write_atomic(path: &Path, content: &str, keep_backup: bool) -> Result<()> {
  use std::io::Write as _;

  // Write the new content to a sibling tmp file FIRST, so that if the
  // write/fsync fails we haven't touched the existing target. Only once the
  // tmp is fully on disk do we move the old copy aside (if requested) and
  // rename the tmp into place. The window where neither the old nor the new
  // name points at valid data is bounded by the two renames, both atomic on
  // the same filesystem.
  let tmp = sibling(path, ".tmp");
  {
    let mut f = std::fs::OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .open(&tmp)
      .wrap_err_with(|| format!("opening {}", tmp.display()))?;
    f.write_all(content.as_bytes())
      .wrap_err_with(|| format!("writing {}", tmp.display()))?;
    f.sync_all()
      .wrap_err_with(|| format!("fsync {}", tmp.display()))?;
  }

  if keep_backup && path.exists() {
    let bak = sibling(path, ".bak");
    std::fs::rename(path, &bak).wrap_err_with(|| {
      format!("backing up {} to {}", path.display(), bak.display())
    })?;
    debug!("backed up {} -> {}", path.display(), bak.display());
  }

  std::fs::rename(&tmp, path).wrap_err_with(|| {
    format!("renaming {} -> {}", tmp.display(), path.display())
  })?;
  Ok(())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
  let mut out = path.to_path_buf();
  let mut name = path.file_name().unwrap_or_default().to_os_string();
  name.push(suffix);
  out.set_file_name(name);
  out
}

fn select_boot_loader(hw: &scan::HwScan) -> template::BootLoader {
  if hw.has_efi {
    template::BootLoader::SystemdBoot
  } else if hw.has_extlinux {
    template::BootLoader::Extlinux
  } else if hw.virt == scan::Virt::SystemdNspawn {
    template::BootLoader::Nspawn
  } else {
    template::BootLoader::Grub
  }
}

fn gethostname() -> String {
  nix::unistd::gethostname()
    .ok()
    .and_then(|h| h.into_string().ok())
    .filter(|h| !h.is_empty())
    .unwrap_or_else(|| "nixos".to_owned())
}

fn detect_state_version() -> String {
  // /run/current-system/nixos-version contains something like
  // "25.05.20240519.abcdef1". Take the first two dot-separated components.
  if let Ok(body) = std::fs::read_to_string("/run/current-system/nixos-version")
  {
    let v = body.trim();
    let parts: Vec<&str> = v.splitn(3, '.').collect();
    if parts.len() >= 2 {
      return format!("{}.{}", parts[0], parts[1]);
    }
  }
  // Fallback: the release of nixpkgs we were tested against. This is a
  // sensible default but should be kept current.
  "25.05".to_owned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn detect_state_version_parses_first_two_components() {
    // We can't override the file in a unit test trivially, but we can at
    // least confirm the fallback is well-formed.
    let v = detect_state_version();
    assert!(v.contains('.'), "state version should contain a dot: {v}");
  }

  #[test]
  fn select_boot_loader_priority() {
    let mut hw = scan::HwScan {
      has_efi: true,
      ..Default::default()
    };
    assert!(matches!(
      select_boot_loader(&hw),
      template::BootLoader::SystemdBoot
    ));

    hw.has_efi = false;
    hw.has_extlinux = true;
    assert!(matches!(
      select_boot_loader(&hw),
      template::BootLoader::Extlinux
    ));

    hw.has_extlinux = false;
    hw.virt = scan::Virt::SystemdNspawn;
    assert!(matches!(
      select_boot_loader(&hw),
      template::BootLoader::Nspawn
    ));

    hw.virt = scan::Virt::None;
    assert!(matches!(
      select_boot_loader(&hw),
      template::BootLoader::Grub
    ));
  }

  #[test]
  fn gethostname_never_empty() {
    // Always produces a usable string, worst case the fallback.
    assert!(!gethostname().is_empty());
  }
}
