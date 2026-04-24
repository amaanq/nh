//! Hardware scanner. Walks `/proc` and `/sys` to collect kernel modules,
//! imports, and attribute lines for the generated hardware config.
//!
//! This mirrors the scanning logic of `nixos-generate-config.pl`, minus the
//! explicitly-dropped bits (ancient Intel wifi firmware attrs, nvidia video
//! driver guess) and with LVM detection done via sysfs instead of shelling
//! out to `lsblk`.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Context, Result};
use nh_core::command::Command;
use tracing::{debug, warn};

#[derive(Debug, Default, Clone)]
pub struct HwScan {
  pub initrd_available: Vec<String>,
  pub initrd_kmods:     Vec<String>,
  pub kmods:            Vec<String>,
  pub module_packages:  Vec<String>,
  pub imports:          Vec<String>,
  pub attrs:            Vec<String>,
  pub virt:             Virt,
  pub has_efi:          bool,
  pub has_extlinux:     bool,
  pub has_lvm:          bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Virt {
  #[default]
  None,
  Oracle,
  Parallels,
  Qemu,
  Kvm,
  Bochs,
  Microsoft,
  SystemdNspawn,
  Other,
}

impl Virt {
  fn parse(s: &str) -> Self {
    match s.trim() {
      "none" => Self::None,
      "oracle" => Self::Oracle,
      "parallels" => Self::Parallels,
      "qemu" => Self::Qemu,
      "kvm" => Self::Kvm,
      "bochs" => Self::Bochs,
      "microsoft" => Self::Microsoft,
      "systemd-nspawn" => Self::SystemdNspawn,
      _ => Self::Other,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuVendor {
  Intel,
  Amd,
  Other,
}

/// Collect the hardware report for the running system.
///
/// # Errors
///
/// Returns an error if `/proc/cpuinfo` is unreadable, or if one of the
/// `/sys/bus/*` walks hits an unexpected IO failure.
pub fn scan() -> Result<HwScan> {
  let mut scan = HwScan::default();
  let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
    .wrap_err("reading /proc/cpuinfo")?;
  let vendor = cpu_vendor(&cpuinfo);

  // Host platform. Upstream substitutes this at nixpkgs build time; we
  // detect it at runtime. The generated hardware-configuration.nix is the
  // only place flake-based nixosSystem calls learn the target system, so
  // this attribute must be present or `nix flake check` on a fresh install
  // will fail with a missing-arg evaluation error.
  scan.attrs.push(format!(
    "nixpkgs.hostPlatform = lib.mkDefault \"{}\";",
    host_platform()
  ));

  // KVM modules from CPU features.
  if cpu_has_feature(&cpuinfo, "vmx") {
    push_unique(&mut scan.kmods, "kvm-intel");
    debug!("added kernel module kvm-intel: CPU has vmx flag");
  }
  if cpu_has_feature(&cpuinfo, "svm") {
    push_unique(&mut scan.kmods, "kvm-amd");
    debug!("added kernel module kvm-amd: CPU has svm flag");
  }

  // PCI walk.
  walk_dir("/sys/bus/pci/devices", |path| {
    pci_check(&path, &mut scan);
    Ok(())
  })?;

  // USB walk.
  walk_dir("/sys/bus/usb/devices", |path| {
    if path.join("bInterfaceClass").exists() {
      usb_check(&path, &mut scan);
    }
    Ok(())
  })?;

  // Driver modules for block devices and MMC hosts.
  for dir in ["/sys/class/block", "/sys/class/mmc_host"] {
    walk_dir(dir, |path| {
      if let Some(module) = driver_module(&path.join("device")) {
        debug!("added initrd module {module} from {}", path.display());
        push_unique(&mut scan.initrd_available, &module);
      }
      Ok(())
    })?;
  }

  // bcache detection (excluding bcachefs).
  if has_bcache_devices() {
    push_unique(&mut scan.initrd_available, "bcache");
    debug!("added initrd module bcache: /dev/bcache* present");
  }

  // LVM detection via sysfs: any dm device with a CRYPT-LVM or LVM- uuid
  // implies dm-snapshot is needed.
  if has_lvm_device() {
    push_unique(&mut scan.initrd_kmods, "dm-snapshot");
    scan.has_lvm = true;
    debug!("added initrd kernel module dm-snapshot: LVM device present");
  }

  scan.virt = detect_virt();
  debug!("systemd-detect-virt -> {:?}", scan.virt);

  match scan.virt {
    Virt::Oracle => {
      scan
        .attrs
        .push("virtualisation.virtualbox.guest.enable = true;".to_owned());
    },
    Virt::Parallels => {
      scan
        .attrs
        .push("hardware.parallels.enable = true;".to_owned());
      scan.attrs.push(
        "nixpkgs.config.allowUnfreePackages = [ \"prl-tools\" ];".to_owned(),
      );
    },
    Virt::Qemu | Virt::Kvm | Virt::Bochs => {
      push_unique(
        &mut scan.imports,
        "(modulesPath + \"/profiles/qemu-guest.nix\")",
      );
    },
    Virt::Microsoft => {
      scan
        .attrs
        .push("virtualisation.hypervGuest.enable = true;".to_owned());
    },
    Virt::SystemdNspawn => {
      scan.attrs.push("boot.isNspawnContainer = true;".to_owned());
    },
    Virt::None => {
      // Bare metal: import the firmware fallback and add microcode attrs.
      push_unique(
        &mut scan.imports,
        "(modulesPath + \"/installer/scan/not-detected.nix\")",
      );
      if vendor == CpuVendor::Amd {
        scan.attrs.push(
          "hardware.cpu.amd.updateMicrocode = lib.mkDefault \
           config.hardware.enableRedistributableFirmware;"
            .to_owned(),
        );
      } else if vendor == CpuVendor::Intel {
        scan.attrs.push(
          "hardware.cpu.intel.updateMicrocode = lib.mkDefault \
           config.hardware.enableRedistributableFirmware;"
            .to_owned(),
        );
      }
    },
    Virt::Other => {
      debug!(
        "unrecognized virtualization flavor, no virt-specific config added"
      );
    },
  }

  scan.has_efi = Path::new("/sys/firmware/efi/efivars").exists();
  scan.has_extlinux = Path::new("/boot/extlinux").exists();

  Ok(scan)
}

/// Nix-style host-platform string (e.g. `x86_64-linux`, `armv6l-linux`,
/// `powerpc64le-linux`). `nh os` runs only on Linux, so the OS half is
/// always `-linux`.
///
/// We prefer `uname -m` because it is the only authoritative source for
/// distinctions the kernel makes that the Rust target triple does not —
/// most importantly `armv6l` vs `armv7l` (Rust's `target_arch = "arm"`
/// covers both), and the `ppc64`/`ppc64le` little-endian split. Falls
/// back to `cfg!(target_arch)` + endianness if `uname` is unavailable.
fn host_platform() -> String {
  if let Some(m) = read_uname_machine() {
    return format!("{}-linux", uname_machine_to_nix(&m));
  }
  format!("{}-linux", compile_time_arch_fallback())
}

fn read_uname_machine() -> Option<String> {
  let out = std::process::Command::new("uname")
    .arg("-m")
    .stderr(std::process::Stdio::null())
    .output()
    .ok()?;
  if !out.status.success() {
    return None;
  }
  let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
  if s.is_empty() { None } else { Some(s) }
}

fn uname_machine_to_nix(m: &str) -> &str {
  // The values not listed here pass through unchanged: `x86_64`, `aarch64`,
  // `armv6l`, `armv7l`, `riscv64`, `loongarch64`, `s390x`, `mips`, `mipsel`.
  match m {
    "ppc" => "powerpc",
    "ppc64" => "powerpc64",
    "ppc64le" => "powerpc64le",
    "i386" | "i486" | "i586" | "i686" => "i686",
    other => other,
  }
}

const fn compile_time_arch_fallback() -> &'static str {
  if cfg!(target_arch = "x86_64") {
    "x86_64"
  } else if cfg!(target_arch = "x86") {
    "i686"
  } else if cfg!(target_arch = "aarch64") {
    "aarch64"
  } else if cfg!(target_arch = "arm") {
    // No way to distinguish armv6 from armv7 here without runtime probing
    // — armv7l is the more common modern default. Hosts on armv6l should
    // hand-edit `nixpkgs.hostPlatform` after generation.
    "armv7l"
  } else if cfg!(all(target_arch = "powerpc64", target_endian = "little")) {
    "powerpc64le"
  } else if cfg!(target_arch = "powerpc64") {
    "powerpc64"
  } else if cfg!(target_arch = "powerpc") {
    "powerpc"
  } else if cfg!(all(target_arch = "mips", target_endian = "little")) {
    "mipsel"
  } else if cfg!(target_arch = "mips") {
    "mips"
  } else if cfg!(all(target_arch = "mips64", target_endian = "little")) {
    "mips64el"
  } else if cfg!(target_arch = "mips64") {
    "mips64"
  } else if cfg!(target_arch = "riscv64") {
    "riscv64"
  } else if cfg!(target_arch = "riscv32") {
    "riscv32"
  } else if cfg!(target_arch = "loongarch64") {
    "loongarch64"
  } else if cfg!(target_arch = "s390x") {
    "s390x"
  } else {
    std::env::consts::ARCH
  }
}

fn cpu_has_feature(cpuinfo: &str, feature: &str) -> bool {
  cpuinfo.lines().filter(|l| l.starts_with("flags")).any(|l| {
    let after = l.split(':').nth(1).unwrap_or("");
    after.split_ascii_whitespace().any(|f| f == feature)
  })
}

fn cpu_vendor(cpuinfo: &str) -> CpuVendor {
  for line in cpuinfo.lines() {
    let mut parts = line.splitn(2, ':');
    if parts.next().map(str::trim) == Some("vendor_id") {
      return match parts.next().unwrap_or("").trim() {
        "GenuineIntel" => CpuVendor::Intel,
        "AuthenticAMD" => CpuVendor::Amd,
        _ => CpuVendor::Other,
      };
    }
  }
  CpuVendor::Other
}

fn pci_check(path: &Path, scan: &mut HwScan) {
  let Some(vendor) = read_trim(path.join("vendor")) else {
    return;
  };
  let Some(device) = read_trim(path.join("device")) else {
    return;
  };
  let Some(class) = read_trim(path.join("class")) else {
    return;
  };
  let module = driver_module(path);

  debug!(
    "{}: vendor={vendor} device={device} class={class} module={module:?}",
    path.display()
  );

  if let Some(ref m) = module {
    let is_mass_storage = class.starts_with("0x01");
    let is_firewire = class.starts_with("0x0c00");
    let is_usb = class.starts_with("0x0c03");
    if is_mass_storage || is_firewire || is_usb {
      push_unique(&mut scan.initrd_available, m);
      debug!("added initrd module {m} from PCI class {class}");
    }
  }

  // Broadcom FullMac brcmfmac device list.
  if vendor == "0x14e4"
    && matches!(
      device.as_str(),
      "0x43a3"
        | "0x43df"
        | "0x43ec"
        | "0x43d3"
        | "0x43d9"
        | "0x43e9"
        | "0x43ba"
        | "0x43bb"
        | "0x43bc"
        | "0xaa52"
        | "0x43ca"
        | "0x43cb"
        | "0x43cc"
        | "0x43c3"
        | "0x43c4"
        | "0x43c5"
    )
  {
    push_unique(
      &mut scan.imports,
      "(modulesPath + \"/hardware/network/broadcom-43xx.nix\")",
    );
    debug!("broadcom brcmfmac match: {vendor}:{device}");
  }

  // virtio-scsi: the module isn't autoloaded on all configurations.
  if vendor == "0x1af4" && (device == "0x1004" || device == "0x1048") {
    push_unique(&mut scan.initrd_available, "virtio_scsi");
    debug!("added virtio_scsi from PCI match {vendor}:{device}");
  }

  // Intel NPU.
  if vendor == "0x8086"
    && matches!(
      device.as_str(),
      "0xfd3e" | "0x7d1d" | "0xad1d" | "0x643e" | "0xb03e"
    )
  {
    push_unique(
      &mut scan.imports,
      "(modulesPath + \"/hardware/cpu/intel-npu.nix\")",
    );
    push_unique(&mut scan.attrs, "hardware.cpu.intel.npu.enable = true;");
    debug!("Intel NPU match {vendor}:{device}");
  }
}

fn usb_check(path: &Path, scan: &mut HwScan) {
  let Some(class) = read_trim(path.join("bInterfaceClass")) else {
    return;
  };
  let protocol = read_trim(path.join("bInterfaceProtocol")).unwrap_or_default();
  let Some(module) = driver_module(path) else {
    return;
  };

  let is_mass_storage = class == "08";
  let is_keyboard_boot = class == "03" && protocol == "01";
  if is_mass_storage || is_keyboard_boot {
    push_unique(&mut scan.initrd_available, &module);
    debug!(
      "added initrd module {module} from USB {} (class={class} \
       proto={protocol})",
      path.display()
    );
  }
}

fn driver_module(base: &Path) -> Option<String> {
  let link = base.join("driver/module");
  let canon = std::fs::canonicalize(&link).ok()?;
  canon.file_name().map(|s| s.to_string_lossy().into_owned())
}

fn has_bcache_devices() -> bool {
  std::fs::read_dir("/dev").is_ok_and(|iter| {
    iter.filter_map(Result::ok).any(|e| {
      let name = e.file_name();
      let n = name.to_string_lossy();
      n.starts_with("bcache") && !n.starts_with("bcachefs")
    })
  })
}

fn has_lvm_device() -> bool {
  let Ok(iter) = std::fs::read_dir("/sys/class/block") else {
    return false;
  };
  iter.filter_map(Result::ok).any(|entry| {
    read_trim(entry.path().join("dm/uuid"))
      .is_some_and(|u| u.starts_with("LVM-"))
  })
}

fn detect_virt() -> Virt {
  match Command::new("systemd-detect-virt")
    .with_required_env()
    .run_capture()
  {
    Ok(Some(out)) => Virt::parse(&out),
    Ok(None) => Virt::None,
    Err(e) => {
      // systemd-detect-virt exits non-zero when no virtualization detected.
      // nh_core's run_capture maps non-zero exit codes to Err — treat that
      // the same as "none" and log for debugging.
      debug!("systemd-detect-virt failed: {e:#}; treating as `none`");
      Virt::None
    },
  }
}

fn walk_dir<F: FnMut(PathBuf) -> Result<()>>(
  dir: &str,
  mut f: F,
) -> Result<()> {
  let iter = match std::fs::read_dir(dir) {
    Ok(i) => i,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      warn!("{dir} missing; skipping scan");
      return Ok(());
    },
    Err(e) => return Err(e).wrap_err_with(|| format!("reading {dir}")),
  };
  for entry in iter {
    let entry = match entry {
      Ok(e) => e,
      Err(e) => {
        warn!("read_dir({dir}) entry error: {e}");
        continue;
      },
    };
    f(entry.path())?;
  }
  Ok(())
}

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
  std::fs::read_to_string(path)
    .ok()
    .map(|s| s.trim().to_owned())
}

fn push_unique(vec: &mut Vec<String>, val: impl Into<String>) {
  let val = val.into();
  if !vec.iter().any(|x| x == &val) {
    vec.push(val);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn host_platform_is_arch_dash_linux() {
    let p = host_platform();
    assert!(p.ends_with("-linux"), "unexpected: {p}");
    assert!(!p.contains(' '));
  }

  #[test]
  fn uname_machine_maps_ppc_and_x86_variants() {
    assert_eq!(uname_machine_to_nix("ppc64le"), "powerpc64le");
    assert_eq!(uname_machine_to_nix("ppc64"), "powerpc64");
    assert_eq!(uname_machine_to_nix("ppc"), "powerpc");
    assert_eq!(uname_machine_to_nix("i386"), "i686");
    assert_eq!(uname_machine_to_nix("i686"), "i686");
    // Pass-through for already-correct values.
    assert_eq!(uname_machine_to_nix("x86_64"), "x86_64");
    assert_eq!(uname_machine_to_nix("aarch64"), "aarch64");
    assert_eq!(uname_machine_to_nix("armv6l"), "armv6l");
    assert_eq!(uname_machine_to_nix("armv7l"), "armv7l");
  }

  #[test]
  fn cpu_has_feature_matches_on_flags_line() {
    let s = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme de \
             pse tsc msr pae mce vmx smep ept\n";
    assert!(cpu_has_feature(s, "vmx"));
    assert!(cpu_has_feature(s, "smep"));
    assert!(!cpu_has_feature(s, "svm"));
  }

  #[test]
  fn cpu_has_feature_ignores_partial_matches() {
    // "vmxx" is not "vmx".
    let s = "flags\t\t: vmxx xxx\n";
    assert!(!cpu_has_feature(s, "vmx"));
  }

  #[test]
  fn cpu_vendor_detects_intel_amd_other() {
    let intel = "vendor_id\t: GenuineIntel\n";
    let amd = "vendor_id\t: AuthenticAMD\n";
    let other = "vendor_id\t: Unknown\n";
    assert_eq!(cpu_vendor(intel), CpuVendor::Intel);
    assert_eq!(cpu_vendor(amd), CpuVendor::Amd);
    assert_eq!(cpu_vendor(other), CpuVendor::Other);
  }

  #[test]
  fn virt_parse_known_and_other() {
    assert_eq!(Virt::parse("none"), Virt::None);
    assert_eq!(Virt::parse("qemu"), Virt::Qemu);
    assert_eq!(Virt::parse("kvm"), Virt::Kvm);
    assert_eq!(Virt::parse("systemd-nspawn"), Virt::SystemdNspawn);
    assert_eq!(Virt::parse("wsl"), Virt::Other);
  }

  #[test]
  fn push_unique_is_order_preserving() {
    let mut v: Vec<String> = vec![];
    push_unique(&mut v, "a");
    push_unique(&mut v, "b");
    push_unique(&mut v, "a");
    push_unique(&mut v, "c");
    assert_eq!(v, ["a", "b", "c"]);
  }

  #[test]
  fn push_unique_no_op_on_all_duplicates() {
    let mut v: Vec<String> = vec!["x".to_owned()];
    push_unique(&mut v, "x");
    push_unique(&mut v, "x");
    assert_eq!(v, ["x"]);
  }
}
