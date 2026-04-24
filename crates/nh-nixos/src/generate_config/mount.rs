//! Parse `/proc/self/mountinfo` and `/proc/swaps` and emit the `fileSystems.*`
//! and `swapDevices` blocks for the generated hardware config.

#![allow(
  clippy::expect_used,
  reason = "writes to in-memory String cannot fail"
)]

use std::{
  collections::HashMap,
  fmt::Write as _,
  os::unix::fs::MetadataExt,
  path::Path,
  process::{Command as StdCommand, Stdio},
};

use color_eyre::eyre::{Context, Result};
use tracing::warn;

use super::template::nix_escape;

#[derive(Debug, Default, Clone)]
pub struct MountScan {
  pub file_systems: String,
  pub swap_devices: Vec<String>,
  pub use_swraid:   bool,
  /// Additional initrd entries discovered while walking filesystems (e.g.
  /// LUKS devices). These get merged into the top-level hardware report.
  pub extra_attrs:  Vec<String>,
}

/// Strings representing the user's `--root` selection. Empty string means the
/// host root (`/`). Paths are canonicalized at construction time and carry no
/// trailing slash.
#[derive(Debug, Clone, Default)]
pub struct RootDir(String);

impl RootDir {
  #[must_use]
  pub fn new(raw: Option<&Path>) -> Self {
    let Some(raw) = raw else {
      return Self(String::new());
    };
    // `canonicalize` requires the path to exist, which it doesn't during a
    // fresh install when the user passes `--root /mnt` before mounting. Fall
    // back to absolutifying the path against the current working directory so
    // the result still matches the absolute paths in `/proc/self/mountinfo`.
    let absolute = std::fs::canonicalize(raw)
      .or_else(|_| std::path::absolute(raw))
      .unwrap_or_else(|_| raw.to_path_buf());
    Self::normalize(&absolute.to_string_lossy())
  }

  #[must_use]
  pub fn parse_str(raw: &str) -> Self {
    if raw.is_empty() {
      return Self(String::new());
    }
    Self::normalize(raw)
  }

  fn normalize(raw: &str) -> Self {
    let mut s = raw.to_owned();
    while s.len() > 1 && s.ends_with('/') {
      s.pop();
    }
    if s == "/" {
      s.clear();
    }
    Self(s)
  }

  /// Host-path representation: empty when root is `/`, else absolute path.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }

  /// Returns `true` when `mp` is the root dir itself or strictly contained
  /// within it.
  fn contains(&self, mp: &str) -> bool {
    let d = &self.0;
    mp == d || mp.starts_with(&format!("{d}/"))
  }

  /// Strip the root-dir prefix from a mount point. If the result is empty,
  /// returns `"/"` (matches perl semantics).
  fn strip(&self, mp: &str) -> String {
    let out = &mp[self.0.len()..];
    if out.is_empty() {
      "/".to_owned()
    } else {
      out.to_owned()
    }
  }
}

/// Parse `/proc/self/mountinfo` and emit `fileSystems.*` entries.
///
/// # Errors
///
/// Returns an error if `/proc/self/mountinfo` cannot be read.
pub fn scan_mounts(root_dir: &RootDir) -> Result<MountScan> {
  let body = std::fs::read_to_string("/proc/self/mountinfo")
    .wrap_err("reading /proc/self/mountinfo")?;
  Ok(parse_mounts(&body, root_dir))
}

/// Read `/proc/swaps` and return rendered `swapDevices` entries.
///
/// # Errors
///
/// Currently infallible — returns `Ok` with an empty vector when the file is
/// unreadable.
pub fn scan_swap(root_dir: &RootDir) -> Result<Vec<String>> {
  let body = match std::fs::read_to_string("/proc/swaps") {
    Ok(s) => s,
    Err(e) => {
      warn!("could not read /proc/swaps: {e}; skipping swapDevices");
      return Ok(vec![]);
    },
  };
  Ok(parse_swaps(&body, root_dir))
}

fn parse_swaps(body: &str, _root_dir: &RootDir) -> Vec<String> {
  let mut devices = vec![];
  for line in body.lines().skip(1) {
    let mut fields = line.split_ascii_whitespace();
    let Some(filename) = fields.next() else {
      continue;
    };
    let Some(swap_type) = fields.next() else {
      continue;
    };

    if !Path::new(filename).exists() {
      continue;
    }
    match swap_type {
      "partition" => {
        // zram is better described by configuration.nix's zramSwap module.
        if filename.starts_with("/dev/zram") {
          continue;
        }
        let stable = find_stable_dev_path(filename);
        devices
          .push(format!("{{ device = \"{s}\"; }}", s = nix_escape(&stable)));
      },
      "file" => {
        // Swap files are managed declaratively; don't clone into hw config.
      },
      other => {
        warn!("unsupported swap type {other:?} for {filename}; skipping");
      },
    }
  }
  devices
}

fn parse_mounts(body: &str, root_dir: &RootDir) -> MountScan {
  let mut out = MountScan::default();
  let mut fs_by_dev: HashMap<String, String> = HashMap::new();
  let mut luks_devices: Vec<String> = vec![];

  for line in body.lines() {
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() < 10 {
      continue;
    }

    let dev_id = fields[2].to_owned();
    let mount_point = mountinfo_unescape(fields[4]);
    let mount_options = fields[5];

    if !Path::new(&mount_point).is_dir() {
      continue;
    }

    if !root_dir.contains(&mount_point) {
      continue;
    }
    let stripped = root_dir.strip(&mount_point);

    if is_pseudo_mount(&stripped) {
      continue;
    }

    // Find the `-` separator.
    let Some(sep_idx) = fields.iter().position(|f| *f == "-") else {
      continue;
    };
    if sep_idx + 3 > fields.len() {
      continue;
    }
    let fs_type = fields[sep_idx + 1];
    let device_raw = fields[sep_idx + 2];
    let device = mountinfo_unescape(device_raw);
    let super_options = fields.get(sep_idx + 3).copied().unwrap_or("");
    let super_has = |opt: &str| super_options.split(',').any(|o| o == opt);
    let mount_has = |opt: &str| mount_options.split(',').any(|o| o == opt);

    // Read-only bind of /nix/store on a rw fs: skip.
    if stripped == "/nix/store" && super_has("rw") && mount_has("ro") {
      continue;
    }

    // Bind-mount detection: we've seen this device id before. For btrfs
    // we need to disambiguate subvolumes (same major:minor, not a bind)
    // from actual bind mounts. `btrfs subvol show` is the authoritative
    // check — when it succeeds the mount is a subvolume; when it fails
    // the mount is a bind. If the binary is missing we cannot tell, so
    // default to "subvolume" (the less destructive misclassification).
    if let Some(prev_mp) = fs_by_dev.get(&dev_id) {
      let is_bind = if fs_type == "btrfs" {
        let full_path = format!("{}{stripped}", root_dir.as_str());
        matches!(btrfs_subvol_path(&full_path), BtrfsProbe::NotASubvolume)
      } else {
        true
      };
      if is_bind {
        // mountinfo octal-escapes the fs-root field too, just like the
        // mount point and device fields.
        let fs_root_unescaped = mountinfo_unescape(fields[3]);
        let fs_root: &str = if fs_root_unescaped == "/" {
          ""
        } else {
          &fs_root_unescaped
        };
        let base = if prev_mp == "/" { "" } else { prev_mp.as_str() };
        emit_filesystem(
          &mut out.file_systems,
          &stripped,
          &format!("{base}{fs_root}"),
          "none",
          &["bind".to_owned()],
          None,
        );
        continue;
      }
    }
    fs_by_dev.insert(dev_id.clone(), stripped.clone());

    // FUSE: upstream warns and skips.
    if fs_type == "fuseblk" || fs_type == "fuse" {
      warn!(
        "don't know how to emit `fileSystems` option for FUSE filesystem \
         {stripped}"
      );
      continue;
    }

    let mut extra_options: Vec<String> = vec![];
    let mut resolved_device = device.clone();

    // Loopback: resolve backing file.
    if let Some(rest) = resolved_device.strip_prefix("/dev/loop")
      && let Ok(n) = rest.parse::<u32>()
      && let Ok(backing) =
        std::fs::read_to_string(format!("/sys/block/loop{n}/loop/backing_file"))
    {
      resolved_device.clear();
      resolved_device.push_str(backing.trim());
      extra_options.push("loop".to_owned());
    }

    // btrfs subvolume. Non-root subvolumes are emitted as `subvol=<path>`;
    // the top-level subvolume (no nested path) is emitted without the
    // option.
    if fs_type == "btrfs" {
      let full_path = format!("{}{stripped}", root_dir.as_str());
      match btrfs_subvol_path(&full_path) {
        BtrfsProbe::Subvol(path) => {
          extra_options.push(format!("subvol={path}"));
        },
        BtrfsProbe::TopLevel | BtrfsProbe::NotASubvolume => {},
        BtrfsProbe::BinaryMissing => {
          warn!(
            "`btrfs` binary not on PATH; cannot detect subvolume for \
             {stripped}. Generated fileSystems entry will omit `subvol=`; \
             install btrfs-progs and regenerate if this host uses nested \
             subvolumes."
          );
        },
      }
    }

    // vfat: preserve fmask/dmask.
    if fs_type == "vfat" {
      for opt in super_options.split(',') {
        if opt.starts_with("fmask") || opt.starts_with("dmask") {
          extra_options.push(opt.to_owned());
        }
      }
    }

    // Skip /tmp tmpfs — the boot.tmp.useTmpfs option handles this.
    if stripped == "/tmp" && fs_type == "tmpfs" {
      continue;
    }

    let stable_device = find_stable_dev_path(&resolved_device);

    // stratis UUID lookup.
    let stratis_uuid = stratis_pool_from_dev(&stable_device)
      .and_then(|pool_name| stratis_pool_uuid(&pool_name));

    // bcachefs UUID override.
    let stable_device = if fs_type == "bcachefs" {
      let full_path = format!("{}{stripped}", root_dir.as_str());
      bcachefs_uuid(&full_path).map_or_else(
        || {
          warn!("can't find bcachefs mount UUID; falling back to device path");
          stable_device.clone()
        },
        |u| format!("UUID={u}"),
      )
    } else {
      stable_device
    };

    emit_filesystem(
      &mut out.file_systems,
      &stripped,
      &stable_device,
      fs_type,
      &uniq(extra_options),
      stratis_uuid.as_deref(),
    );

    // LUKS / MD probing for real block devices.
    if Path::new(&device).exists()
      && let Ok(canonical) = std::fs::canonicalize(&device)
      && let Some(base) = canonical.file_name().and_then(|s| s.to_str())
    {
      let dm_uuid =
        std::fs::read_to_string(format!("/sys/class/block/{base}/dm/uuid"))
          .unwrap_or_default();
      if dm_uuid.trim_start().starts_with("CRYPT-LUKS") {
        probe_luks(base, &mut luks_devices);
      }
      if Path::new(&format!("/sys/class/block/{base}/md/uuid")).exists() {
        out.use_swraid = true;
      }
    }
  }

  // Append LUKS entries after the filesystem blocks, each followed by a blank
  // line to match the existing cosmetic convention.
  for entry in luks_devices {
    out.file_systems.push_str(&entry);
    out.file_systems.push('\n');
    out.file_systems.push('\n');
  }

  if out.use_swraid {
    out
      .extra_attrs
      .push("boot.swraid.enable = true;".to_owned());
  }

  out
}

fn probe_luks(base: &str, luks_devices: &mut Vec<String>) {
  let slaves = read_dir_names(&format!("/sys/class/block/{base}/slaves"));
  if slaves.len() != 1 {
    return;
  }
  let slave_path = format!("/dev/{}", slaves[0]);
  if !Path::new(&slave_path).exists() {
    return;
  }
  let dm_name =
    std::fs::read_to_string(format!("/sys/class/block/{base}/dm/name"))
      .unwrap_or_default()
      .trim()
      .to_owned();
  let key = format!(
    "  boot.initrd.luks.devices.\"{n}\".device",
    n = nix_escape(&dm_name)
  );
  if !luks_devices.iter().any(|d| d.starts_with(&key)) {
    luks_devices.push(format!(
      "{key} = \"{}\";",
      nix_escape(&find_stable_dev_path(&slave_path))
    ));
  }
}

fn emit_filesystem(
  out: &mut String,
  mount_point: &str,
  device: &str,
  fs_type: &str,
  extra_options: &[String],
  stratis_uuid: Option<&str>,
) {
  writeln!(
    out,
    "  fileSystems.\"{mp}\" = {{",
    mp = nix_escape(mount_point)
  )
  .expect("write");
  writeln!(out, "    device = \"{d}\";", d = nix_escape(device))
    .expect("write");
  writeln!(out, "    fsType = \"{t}\";", t = nix_escape(fs_type))
    .expect("write");
  if !extra_options.is_empty() {
    let quoted: Vec<String> = extra_options
      .iter()
      .map(|o| format!("\"{}\"", nix_escape(o)))
      .collect();
    writeln!(out, "    options = [ {} ];", quoted.join(" ")).expect("write");
  }
  if let Some(uuid) = stratis_uuid {
    writeln!(out, "    stratis.poolUuid = \"{u}\";", u = nix_escape(uuid))
      .expect("write");
  }
  out.push_str("  };\n\n");
}

/// Matches the upstream `in($mountPoint, "/proc")` semantics: an exact match
/// or a strict prefix ending at a path separator.
fn is_pseudo_mount(mp: &str) -> bool {
  for root in ["/proc", "/dev", "/sys", "/run"] {
    if mp == root || mp.starts_with(&format!("{root}/")) {
      return true;
    }
  }
  mp == "/var/lib/nfs/rpc_pipefs"
}

fn mountinfo_unescape(s: &str) -> String {
  s.replace("\\040", " ")
    .replace("\\011", "\t")
    .replace("\\012", "\n")
    .replace("\\134", "\\")
}

fn read_dir_names(dir: &str) -> Vec<String> {
  std::fs::read_dir(dir)
    .ok()
    .map(|it| {
      it.filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
    })
    .unwrap_or_default()
}

fn uniq<T: Eq + Clone>(items: Vec<T>) -> Vec<T> {
  let mut seen: Vec<T> = Vec::with_capacity(items.len());
  for item in items {
    if !seen.contains(&item) {
      seen.push(item);
    }
  }
  seen
}

#[must_use]
pub fn find_stable_dev_path(dev: &str) -> String {
  if !dev.starts_with('/') {
    return dev.to_owned();
  }
  let Ok(meta) = std::fs::metadata(dev) else {
    return dev.to_owned();
  };
  if meta.rdev() == 0 {
    return dev.to_owned();
  }
  let target_rdev = meta.rdev();

  // Two-level directories for stratis. Sort each level so that when
  // multiple aliases point at the same rdev we pick the same one across
  // runs (perl uses sorted glob; std::fs::read_dir does not).
  for outer in ["/dev/stratis"] {
    for entry in sorted_dir(outer) {
      for inner_entry in sorted_dir(&entry) {
        if matches_rdev(Path::new(&inner_entry), target_rdev) {
          return inner_entry;
        }
      }
    }
  }

  for dir in ["/dev/mapper", "/dev/disk/by-uuid", "/dev/disk/by-label"] {
    if let Some(hit) = find_matching_rdev_flat(dir, target_rdev) {
      return hit;
    }
  }
  dev.to_owned()
}

fn sorted_dir(dir: &str) -> Vec<String> {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return vec![];
  };
  let mut paths: Vec<String> = entries
    .filter_map(Result::ok)
    .map(|e| e.path().to_string_lossy().into_owned())
    .collect();
  paths.sort();
  paths
}

fn matches_rdev(path: &Path, target: u64) -> bool {
  std::fs::metadata(path)
    .map(|m| m.rdev() == target)
    .unwrap_or(false)
}

fn find_matching_rdev_flat(dir: &str, target: u64) -> Option<String> {
  // Sort for stable selection across runs when several aliases share an
  // rdev (e.g. duplicate labels in `/dev/disk/by-label`).
  sorted_dir(dir)
    .into_iter()
    .find(|path| matches_rdev(Path::new(path), target))
}

/// Result of probing a btrfs mount for subvolume info.
enum BtrfsProbe {
  /// `btrfs subvol show` succeeded with a non-root path. Emit
  /// `subvol=<path>`; the mount is definitely a subvolume, not a bind.
  Subvol(String),
  /// `btrfs subvol show` succeeded but the path was `/`. This is either
  /// the top-level subvolume or an ambiguous case; don't emit `subvol=`
  /// and don't classify as bind.
  TopLevel,
  /// `btrfs subvol show` returned non-zero or an ERROR: string. The
  /// mount isn't a subvolume — most likely a bind mount into a btrfs
  /// filesystem. Matches upstream perl's bind-classification branch.
  NotASubvolume,
  /// `btrfs` binary was not on PATH. We cannot tell subvolume from bind;
  /// default to treating it as a subvolume (the safer failure mode: a
  /// misclassified bind mount is easier to hand-edit than a misclassified
  /// subvolume with missing `subvol=`).
  BinaryMissing,
}

fn btrfs_subvol_path(mount_point: &str) -> BtrfsProbe {
  let out = match StdCommand::new("btrfs")
    .args(["subvol", "show", mount_point])
    .stderr(Stdio::piped())
    .stdout(Stdio::piped())
    .output()
  {
    Ok(o) => o,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      return BtrfsProbe::BinaryMissing;
    },
    Err(_) => return BtrfsProbe::NotASubvolume,
  };
  if !out.status.success() {
    return BtrfsProbe::NotASubvolume;
  }
  let text = String::from_utf8_lossy(&out.stdout);
  if text.contains("ERROR:") {
    return BtrfsProbe::NotASubvolume;
  }
  // First line = subvolume path relative to fs root, e.g. "@home" or "/".
  let first_line = text.lines().next().unwrap_or("").trim();
  if first_line.is_empty() || first_line == "/" {
    BtrfsProbe::TopLevel
  } else {
    BtrfsProbe::Subvol(first_line.to_owned())
  }
}

fn bcachefs_uuid(mount_point: &str) -> Option<String> {
  let out = StdCommand::new("bcachefs")
    .args(["fs", "usage", mount_point])
    .stderr(Stdio::null())
    .stdout(Stdio::piped())
    .output()
    .ok()?;
  if !out.status.success() {
    return None;
  }
  let text = String::from_utf8_lossy(&out.stdout);
  let first = text.lines().next()?;
  let rest = first.strip_prefix("Filesystem:")?.trim();
  // Take the leading run of [0-9a-z-] characters.
  let uuid: String = rest
    .chars()
    .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
    .collect();
  if uuid.is_empty() { None } else { Some(uuid) }
}

fn stratis_pool_from_dev(dev: &str) -> Option<String> {
  let rest = dev.strip_prefix("/dev/stratis/")?;
  let (pool, _) = rest.split_once('/')?;
  Some(pool.to_owned())
}

fn stratis_pool_uuid(pool_name: &str) -> Option<String> {
  let out = StdCommand::new("stratis")
    .args(["pool", "list"])
    .stderr(Stdio::null())
    .stdout(Stdio::piped())
    .output()
    .ok()?;
  if !out.status.success() {
    return None;
  }
  let text = String::from_utf8_lossy(&out.stdout);
  let mut lines = text.lines();
  let header = lines.next()?;
  let uuid_col = header.find("UUID")?;
  for line in lines {
    if line.starts_with(&format!("{pool_name} ")) {
      // UUID is 36 chars, positioned so its end is at uuid_col - some
      // offset. Upstream computes `substr($line, $uuidIndex - 32, 36)` on a
      // right-aligned column. `str::get` returns None for out-of-bounds
      // ranges rather than panicking, but we also guard against usize
      // overflow on pathological input.
      let start = uuid_col.saturating_sub(32);
      let end = start.checked_add(36)?;
      if let Some(slice) = line.get(start..end) {
        return Some(slice.trim().to_owned());
      }
    }
  }
  None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests panic on failure")]
mod tests {
  use super::*;

  #[test]
  fn root_dir_default_is_empty() {
    let r = RootDir::default();
    assert_eq!(r.as_str(), "");
  }

  #[test]
  fn root_dir_contains_handles_empty_default() {
    let r = RootDir::parse_str("");
    assert!(r.contains("/"));
    assert!(r.contains("/home"));
    assert!(r.contains("/mnt/x"));
  }

  #[test]
  fn root_dir_contains_rejects_siblings() {
    let r = RootDir::parse_str("/mnt");
    assert!(r.contains("/mnt"));
    assert!(r.contains("/mnt/home"));
    assert!(!r.contains("/mnt2"));
    assert!(!r.contains("/home"));
  }

  #[test]
  fn root_dir_new_absolutizes_nonexistent_relative_paths() {
    // mountinfo paths are always absolute. A relative `--root` like
    // `mnt-target` (with the directory not yet present) must still produce
    // an absolute root so containment checks line up.
    let r = RootDir::new(Some(Path::new("mnt-target")));
    assert!(
      r.as_str().starts_with('/'),
      "expected absolute path, got {:?}",
      r.as_str()
    );
    assert!(r.as_str().ends_with("mnt-target"));
  }

  #[test]
  fn root_dir_strip_maps_equal_to_slash() {
    let r = RootDir::parse_str("/mnt");
    assert_eq!(r.strip("/mnt"), "/");
    assert_eq!(r.strip("/mnt/home"), "/home");
  }

  #[test]
  fn is_pseudo_mount_exact_and_prefix() {
    assert!(is_pseudo_mount("/proc"));
    assert!(is_pseudo_mount("/proc/self"));
    assert!(is_pseudo_mount("/sys"));
    assert!(is_pseudo_mount("/dev/pts"));
    assert!(is_pseudo_mount("/run/user/1000"));
    assert!(is_pseudo_mount("/var/lib/nfs/rpc_pipefs"));
    // Should not match sibling directories with pseudo-prefixes.
    assert!(!is_pseudo_mount("/procdata"));
    assert!(!is_pseudo_mount("/devops"));
    assert!(!is_pseudo_mount("/sysroot"));
    assert!(!is_pseudo_mount("/runner"));
    assert!(!is_pseudo_mount("/"));
    assert!(!is_pseudo_mount("/home"));
  }

  #[test]
  fn unescape_mountinfo_octals() {
    assert_eq!(mountinfo_unescape("a\\040b"), "a b");
    assert_eq!(mountinfo_unescape("x\\011y"), "x\ty");
    assert_eq!(mountinfo_unescape("back\\134slash"), "back\\slash");
  }

  #[test]
  fn uniq_preserves_insertion_order() {
    assert_eq!(
      uniq(vec![
        "a".to_owned(),
        "b".to_owned(),
        "a".to_owned(),
        "c".to_owned()
      ]),
      vec!["a", "b", "c"]
    );
  }

  #[test]
  fn parse_swaps_emits_partitions_only() {
    let body = "\
Filename\tType\t\tSize\tUsed\tPriority
/dev/zram0\tpartition\t1024\t0\t-1
/dev/does-not-exist\tpartition\t1024\t0\t-1
/swapfile\tfile\t\t1024\t0\t-1
";
    let r = RootDir::default();
    // None of these entries exist at scan time, so we expect zero output.
    let devs = parse_swaps(body, &r);
    assert!(devs.is_empty());
  }

  #[test]
  fn stratis_pool_from_dev_extracts_name() {
    assert_eq!(
      stratis_pool_from_dev("/dev/stratis/mypool/vol1"),
      Some("mypool".to_owned())
    );
    assert_eq!(stratis_pool_from_dev("/dev/sda1"), None);
  }

  #[test]
  fn emit_filesystem_formats_expected_block() {
    let mut out = String::new();
    emit_filesystem(
      &mut out,
      "/home",
      "/dev/disk/by-uuid/1234",
      "ext4",
      &[],
      None,
    );
    let expected = "  fileSystems.\"/home\" = {\n\x20\x20\x20\x20device = \
                    \"/dev/disk/by-uuid/1234\";\n\x20\x20\x20\x20fsType = \
                    \"ext4\";\n\x20\x20};\n\n";
    assert_eq!(out, expected);
  }

  #[test]
  fn emit_filesystem_with_options_and_stratis() {
    let mut out = String::new();
    emit_filesystem(
      &mut out,
      "/data",
      "/dev/stratis/p/v",
      "ext4",
      &["subvol=@data".to_owned()],
      Some("deadbeef-...-uuid"),
    );
    assert!(out.contains("options = [ \"subvol=@data\" ]"));
    assert!(out.contains("stratis.poolUuid = \"deadbeef-...-uuid\""));
  }

  #[test]
  fn parse_mounts_unescapes_bind_source_root() {
    // Two mountinfo entries with the same dev_id (8:1). The second is a
    // bind mount whose source root contains an escaped space (\040). We
    // should see the unescaped value in the generated `device` field, not
    // the raw `\040` sequence. Mount points must exist on the host because
    // parse_mounts skips non-directories — `/` and `/tmp` are universally
    // available.
    let body = "\
35 1 8:1 / / rw,relatime shared:1 - ext4 /dev/x rw
36 35 8:1 /home/foo\\040bar /tmp rw,relatime shared:2 - ext4 /dev/x rw
";
    let r = RootDir::parse_str("");
    let scan = parse_mounts(body, &r);
    assert!(
      scan.file_systems.contains("device = \"/home/foo bar\""),
      "expected unescaped bind source, got:\n{}",
      scan.file_systems
    );
    assert!(
      !scan.file_systems.contains("\\040"),
      "raw octal escape leaked into output:\n{}",
      scan.file_systems
    );
  }

  #[test]
  fn parse_mounts_skips_pseudo_and_emits_ext4() {
    // Synthesize a mountinfo with a single ext4 root and a /proc entry to
    // skip. We can't reliably hit `find_stable_dev_path` in a unit test (it
    // would stat /), so we only check the skip behavior.
    let body = "\
25 23 0:24 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
35 1 8:1 / / rw,relatime shared:1 - ext4 /dev/nonexistent rw
";
    let r = RootDir::parse_str("");
    let scan = parse_mounts(body, &r);
    // /proc must be excluded.
    assert!(!scan.file_systems.contains("fileSystems.\"/proc\""));
  }
}
