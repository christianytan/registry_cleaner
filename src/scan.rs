//! Reads every "Add / Remove Programs" (Uninstall) registry location and decides
//! which entries are real installs and which are leftovers.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use winreg::enums::*;
use winreg::RegKey;

use crate::sys;

// ------------------------------------------------------------------ verdicts

/// How confident we are that an entry is junk. Ordered least -> most severe.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Verdict {
    Ok,
    Hidden,
    Suspect,
    Orphan,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::Hidden => "HIDDEN",
            Verdict::Suspect => "SUSPECT",
            Verdict::Orphan => "ORPHAN",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PathState {
    /// The value is not present at all.
    Absent,
    /// The value is present and the file/folder really exists.
    Present,
    /// The value is present and absolute, but the file/folder is gone.
    Missing,
    /// A relative path we cannot resolve reliably (some installers write these).
    Relative,
    /// Not a filesystem path we can judge (bare exe name, shell verb, ...).
    Unresolvable,
}

impl PathState {
    pub fn label(&self) -> &'static str {
        match self {
            PathState::Absent => "-",
            PathState::Present => "exists",
            PathState::Missing => "MISSING",
            PathState::Relative => "relative",
            PathState::Unresolvable => "n/a",
        }
    }
    pub fn broken(&self) -> bool {
        *self == PathState::Missing
    }
    pub fn resolves(&self) -> bool {
        *self == PathState::Present
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hive {
    Hklm64,
    Hklm32,
    Hkcu,
    Hkcu32,
}

impl Hive {
    pub const ALL: [Hive; 4] = [Hive::Hklm64, Hive::Hklm32, Hive::Hkcu, Hive::Hkcu32];

    pub fn label(self) -> &'static str {
        match self {
            Hive::Hklm64 => "HKLM 64-bit",
            Hive::Hklm32 => "HKLM 32-bit",
            Hive::Hkcu => "HKCU",
            Hive::Hkcu32 => "HKCU 32-bit",
        }
    }

    /// The real registry path, used for display, for `reg.exe` and for backups.
    pub fn reg_path(self) -> &'static str {
        match self {
            Hive::Hklm64 => r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            Hive::Hklm32 => r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            Hive::Hkcu => r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            Hive::Hkcu32 => r"HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        }
    }

    /// Path under the predefined hive that we actually open. The WOW64 view is
    /// selected with an access flag rather than with the WOW6432Node literal,
    /// which is how Windows itself reads it.
    fn open_path(self) -> &'static str {
        match self {
            Hive::Hklm64 | Hive::Hklm32 => r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            Hive::Hkcu | Hive::Hkcu32 => r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        }
    }

    fn view_flag(self) -> u32 {
        match self {
            Hive::Hklm64 | Hive::Hkcu => KEY_WOW64_64KEY,
            Hive::Hklm32 | Hive::Hkcu32 => KEY_WOW64_32KEY,
        }
    }

    pub fn is_machine(self) -> bool {
        matches!(self, Hive::Hklm64 | Hive::Hklm32)
    }
}

// ------------------------------------------------------------------ entry

#[derive(Clone, Debug)]
pub struct Entry {
    pub hive: Hive,
    pub key: String,

    pub name: String,
    pub has_display_name: bool,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
    pub size_kb: u64,

    pub uninstall: Option<String>,
    pub quiet_uninstall: Option<String>,
    pub location: Option<String>,

    pub product_code: Option<String>,
    pub is_msi: bool,
    pub system_component: bool,
    pub no_remove: bool,
    pub parent_display: Option<String>,

    pub uninstall_state: PathState,
    pub quiet_state: PathState,
    pub location_state: PathState,
    pub msi_installed: Option<bool>,
    pub steam_gone: bool,

    pub duplicate: bool,
    pub duplicate_benign: bool,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

impl Entry {
    pub fn full_key_path(&self) -> String {
        format!(r"{}\{}", self.hive.reg_path(), self.key)
    }

    /// True when removing this entry cannot break anything that is still installed.
    pub fn safe_to_remove(&self) -> bool {
        self.verdict == Verdict::Orphan && !self.system_component
    }
}

// ------------------------------------------------------------------ path parsing

/// Expand `%VAR%` (including `%ProgramFiles(x86)%`) the way the shell would.
fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find('%') {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                let plausible = !name.is_empty() && !name.chars().any(|c| c.is_whitespace());
                if plausible {
                    match env::var(name) {
                        Ok(val) => out.push_str(&val),
                        Err(_) => {
                            out.push('%');
                            out.push_str(name);
                            out.push('%');
                        }
                    }
                } else {
                    out.push('%');
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':') || p.starts_with(r"\\")
}

/// Pull the executable / MSI out of an UninstallString command line.
/// Registry command lines are frequently unquoted *and* contain spaces, so we
/// locate the executable by its extension rather than by the first space.
fn extract_target(command: &str) -> Option<String> {
    let c = command.trim();
    if c.is_empty() {
        return None;
    }

    // 1. A quoted path is unambiguous.
    if c.starts_with('"') {
        if let Some(end) = c[1..].find('"') {
            let inner = c[1..1 + end].trim();
            if !inner.is_empty() {
                return Some(inner.to_string());
            }
        }
    }

    // 2. Otherwise scan for the first extension boundary followed by
    //    whitespace / an operator / end of string.
    let lower = c.to_ascii_lowercase();
    for ext in [".exe", ".msi", ".com", ".bat", ".cmd"] {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(ext) {
            let end = from + rel + ext.len();
            let terminated = end >= c.len()
                || matches!(
                    c.as_bytes()[end],
                    b' ' | b'\t' | b'|' | b'&' | b';' | b'"'
                );
            if terminated {
                let path = c[..end].trim();
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
            from = end;
        }
    }

    // 3. Fall back to the first whitespace-delimited token.
    let first = c.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

/// `{00000000-0000-0000-0000-000000000000}` inside a command line.
fn find_guid(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = command[i..].find('}') {
                let inner = &command[i..i + rel + 1];
                let body = &inner[1..inner.len() - 1];
                let ok = body.len() == 36
                    && body.chars().enumerate().all(|(k, ch)| {
                        if k == 8 || k == 13 || k == 18 || k == 23 {
                            ch == '-'
                        } else {
                            ch.is_ascii_hexdigit()
                        }
                    });
                if ok {
                    return Some(inner.to_string());
                }
            }
        }
        i += 1;
    }
    None
}

fn judge_path(raw: &str) -> PathState {
    let expanded = expand_env(raw).trim().trim_matches('"').to_string();
    let expanded = expanded.trim_end_matches('\\');
    if expanded.is_empty() {
        return PathState::Absent;
    }
    if !is_absolute(&expanded) {
        if expanded.contains('/') || expanded.contains('\\') {
            return PathState::Relative;
        }
        return PathState::Unresolvable;
    }
    if Path::new(expanded).exists() {
        PathState::Present
    } else {
        PathState::Missing
    }
}

/// Judge an UninstallString / QuietUninstallString command line.
/// MSI command lines are judged by the Windows Installer database, not by the
/// path of msiexec.exe (which always exists and would hide a dead product).
fn judge_command(cmd: Option<&String>, is_msi: bool, msi_installed: Option<bool>) -> PathState {
    let Some(cmd) = cmd else { return PathState::Absent };
    if is_msi || cmd.to_ascii_lowercase().contains("msiexec") {
        return match msi_installed {
            Some(false) => PathState::Missing,
            Some(true) => PathState::Present,
            None => PathState::Unresolvable,
        };
    }
    match extract_target(cmd) {
        Some(target) => judge_path(&target),
        None => PathState::Unresolvable,
    }
}

// ------------------------------------------------------------------ steam

/// Every Steam library folder on the machine (Steam's own plus any the user added).
fn steam_libraries() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for hive in [Hive::Hklm32, Hive::Hklm64] {
        let flags = KEY_READ | hive.view_flag();
        if let Ok(k) = hklm.open_subkey_with_flags(r"SOFTWARE\Valve\Steam", flags) {
            if let Ok(path) = k.get_value::<String, _>("InstallPath") {
                let path = path.trim().to_string();
                if !path.is_empty() {
                    roots.push(PathBuf::from(path));
                    break;
                }
            }
        }
    }

    let mut libs = roots.clone();
    for root in &roots {
        let vdf = root.join("steamapps").join("libraryfolders.vdf");
        let content = match fs::read_to_string(&vdf) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let content = content.trim_start_matches('\u{feff}').to_string();
        for line in content.lines() {
            let line = line.trim();
            if !line.starts_with("\"path\"") {
                continue;
            }
            let rest = &line[6..];
            let Some(start) = rest.find('"') else { continue };
            let Some(end) = rest[start + 1..].find('"') else { continue };
            let raw = rest[start + 1..start + 1 + end].replace("\\\\", "\\");
            let p = PathBuf::from(raw);
            if !libs.iter().any(|x| *x == p) {
                libs.push(p);
            }
        }
    }
    libs
}

/// True when a `Steam App <id>` uninstall key has no matching appmanifest anywhere.
fn steam_app_gone(key_name: &str, libs: &[PathBuf]) -> bool {
    let id = match key_name.strip_prefix("Steam App ") {
        Some(rest) => rest.trim(),
        None => return false,
    };
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if libs.is_empty() {
        return false; // cannot tell -> never accuse
    }
    let file = format!("appmanifest_{}.acf", id);
    !libs.iter().any(|l| l.join("steamapps").join(&file).exists())
}

// ------------------------------------------------------------------ reading

fn get_str(k: &RegKey, name: &str) -> Option<String> {
    k.get_value::<String, _>(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn get_u32(k: &RegKey, name: &str) -> Option<u32> {
    k.get_value::<u32, _>(name).ok()
}

fn read_entry(hive: Hive, key: &str, k: &RegKey, steam: &[PathBuf]) -> Entry {
    let declared = get_str(k, "DisplayName");
    let uninstall = get_str(k, "UninstallString");
    let quiet_uninstall = get_str(k, "QuietUninstallString");
    let location = get_str(k, "InstallLocation");

    let has_display_name = declared.is_some();
    let name = declared.clone().unwrap_or_else(|| key.to_string());

    let product_code = uninstall
        .as_deref()
        .and_then(find_guid)
        .or_else(|| quiet_uninstall.as_deref().and_then(find_guid));

    let installer_flag = get_u32(k, "WindowsInstaller").unwrap_or(0) == 1;
    let msi_command = uninstall
        .as_deref()
        .map(|u| u.to_ascii_lowercase().contains("msiexec"))
        .unwrap_or(false)
        || quiet_uninstall
            .as_deref()
            .map(|u| u.to_ascii_lowercase().contains("msiexec"))
            .unwrap_or(false);
    let is_msi = installer_flag || (msi_command && product_code.is_some());

    let msi_installed = product_code
        .as_deref()
        .and_then(|pc| sys::msi_product_installed(pc));

    let uninstall_state = judge_command(uninstall.as_ref(), is_msi, msi_installed);
    let quiet_state = judge_command(quiet_uninstall.as_ref(), is_msi, msi_installed);
    let location_state = match &location {
        Some(l) => judge_path(l),
        None => PathState::Absent,
    };

    Entry {
        hive,
        key: key.to_string(),
        name,
        has_display_name,
        version: get_str(k, "DisplayVersion").unwrap_or_default(),
        publisher: get_str(k, "Publisher").unwrap_or_default(),
        install_date: get_str(k, "InstallDate").unwrap_or_default(),
        size_kb: get_u32(k, "EstimatedSize").unwrap_or(0) as u64,
        uninstall_state,
        quiet_state,
        location_state,
        product_code,
        is_msi,
        system_component: get_u32(k, "SystemComponent").unwrap_or(0) == 1,
        no_remove: get_u32(k, "NoRemove").unwrap_or(0) == 1,
        parent_display: get_str(k, "ParentDisplayName"),
        msi_installed,
        steam_gone: steam_app_gone(key, steam),
        uninstall,
        quiet_uninstall,
        location,
        duplicate: false,
        duplicate_benign: false,
        verdict: Verdict::Ok,
        reasons: Vec::new(),
    }
}

// ------------------------------------------------------------------ scan

/// Read every uninstall location and classify each entry, worst first.
pub fn scan() -> Vec<Entry> {
    let steam = steam_libraries();
    let mut entries: Vec<Entry> = Vec::new();

    for hive in Hive::ALL {
        let root = if hive.is_machine() {
            RegKey::predef(HKEY_LOCAL_MACHINE)
        } else {
            RegKey::predef(HKEY_CURRENT_USER)
        };
        let parent = match root.open_subkey_with_flags(hive.open_path(), KEY_READ | hive.view_flag())
        {
            Ok(p) => p,
            Err(_) => continue,
        };
        for key in parent.enum_keys().flatten() {
            let ok = match parent.open_subkey_with_flags(&key, KEY_READ) {
                Ok(k) => k,
                Err(_) => continue,
            };
            entries.push(read_entry(hive, &key, &ok, &steam));
        }
    }

    mark_duplicates(&mut entries);
    for e in entries.iter_mut() {
        classify(e);
    }
    entries.sort_by(|a, b| {
        b.verdict
            .cmp(&a.verdict)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    entries
}

fn normalize_name(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn mark_duplicates(entries: &mut [Entry]) {
    let mut groups: std::collections::HashMap<String, Vec<usize>> = Default::default();
    for (i, e) in entries.iter().enumerate() {
        if !e.has_display_name {
            continue;
        }
        let key = normalize_name(&e.name);
        if !key.is_empty() {
            groups.entry(key).or_default().push(i);
        }
    }

    for (_, idx) in groups {
        if idx.len() < 2 {
            continue;
        }
        // One MSI product code appearing in both WOW64 views is normal Windows
        // behaviour, not a duplicate to clean up.
        let codes: Vec<Option<&String>> =
            idx.iter().map(|i| entries[*i].product_code.as_ref()).collect();
        let same_msi = match codes.first().and_then(|c| *c) {
            Some(first) => codes.iter().all(|c| matches!(c, Some(x) if *x == first)),
            None => false,
        };
        // A repeated name is only worth worrying about when one copy is broken.
        // Shared components legitimately register the same name in several places
        // (Windows SDK pieces, driver components, runtimes), so if every copy has
        // a working uninstaller this is normal and must not be flagged as a problem.
        let all_healthy = idx.iter().all(|i| {
            entries[*i].uninstall_state.resolves() || entries[*i].quiet_state.resolves()
        });
        for i in idx {
            entries[i].duplicate = true;
            entries[i].duplicate_benign = same_msi || all_healthy;
        }
    }
}

// ------------------------------------------------------------------ classify

fn classify(e: &mut Entry) {
    let mut reasons: Vec<String> = Vec::new();
    let mut verdict = Verdict::Ok;

    /// Only ever escalate. Never downgrade a proven ghost, and never overwrite the
    /// much more specific "Hidden" verdict with a vague "Suspect".
    fn bump(v: Verdict, verdict: &mut Verdict) {
        if *verdict != Verdict::Hidden && v > *verdict {
            *verdict = v;
        }
    }

    if !e.has_display_name {
        verdict = Verdict::Hidden;
        reasons.push(
            "This key has no DisplayName value, so Apps & Features never shows it. It is \
             registry clutter (usually an orphaned Windows Installer component stub), but it \
             is not what you are seeing in the list."
                .to_string(),
        );
    }

    if e.is_msi && e.msi_installed == Some(false) {
        let pc = e.product_code.clone().unwrap_or_default();
        reasons.push(format!(
            "CONFIRMED GHOST: MSI product {pc} is no longer registered in the Windows \
             Installer database. The product was removed but this uninstall key survived."
        ));
        verdict = Verdict::Orphan;
    }

    if e.steam_gone {
        reasons.push(
            "CONFIRMED GHOST: no Steam appmanifest exists for this AppID in any Steam \
             library on this machine. The game was removed from Steam but the key remained."
                .to_string(),
        );
        verdict = Verdict::Orphan;
    }

    let uninst_broken = e.uninstall_state.broken();
    let quiet_broken = e.quiet_state.broken();
    let loc_broken = e.location_state.broken();
    // A working uninstaller is the strongest evidence that a program is really installed.
    let uninstaller_works = e.uninstall_state.resolves() || e.quiet_state.resolves();
    let folder_exists = e.location_state.resolves();
    let has_uninstaller_value = e.uninstall.is_some() || e.quiet_uninstall.is_some();

    if uninst_broken {
        reasons.push(format!(
            "UninstallString points at a file that no longer exists: {}",
            e.uninstall.clone().unwrap_or_default()
        ));
    }
    if quiet_broken {
        reasons.push(format!(
            "QuietUninstallString points at a file that no longer exists: {}",
            e.quiet_uninstall.clone().unwrap_or_default()
        ));
    }
    if loc_broken {
        reasons.push(format!(
            "InstallLocation folder no longer exists: {}",
            e.location.clone().unwrap_or_default()
        ));
    }

    if uninstaller_works {
        // The program is installed and can still be uninstalled properly.
        if loc_broken {
            reasons.push(
                "Only the InstallLocation value is stale. The uninstaller itself still works, \
                 so this entry is fine - do NOT remove it."
                    .to_string(),
            );
        }
    } else if (uninst_broken || quiet_broken) && !folder_exists {
        reasons.push(
            "CONFIRMED GHOST: nothing this key points to exists any more - no uninstaller and \
             no install folder. This is exactly why Uninstall fails or appears to do nothing."
                .to_string(),
        );
        verdict = Verdict::Orphan;
    } else if uninst_broken || quiet_broken {
        reasons.push(
            "The uninstaller is gone but the install folder is still on disk, so the program \
             is still installed. Removing this key would hide it from Apps & Features without \
             uninstalling it - delete the folder instead, or reinstall to repair the key."
                .to_string(),
        );
        bump(Verdict::Suspect, &mut verdict);
    } else if !has_uninstaller_value && e.location.is_some() && !folder_exists {
        reasons.push(
            "CONFIRMED GHOST: the recorded install folder no longer exists and there is no \
             uninstaller at all."
                .to_string(),
        );
        verdict = Verdict::Orphan;
    } else if !has_uninstaller_value && !folder_exists {
        reasons.push(
            "INFORMATIONAL: this entry has no UninstallString and no InstallLocation, which is \
             why Apps & Features shows no Uninstall button for it. That is normal for shared \
             components and is not evidence that anything is missing - leave it alone unless \
             you know what installed it."
                .to_string(),
        );
    }

    if e.duplicate {
        if e.duplicate_benign {
            reasons.push(
                "INFORMATIONAL: other keys share this exact name. That is normal for \
                 components that register in more than one place, and every copy still has a \
                 working uninstaller - do not remove them."
                    .to_string(),
            );
        } else {
            reasons.push(
                "INFORMATIONAL: the same name appears under more than one Uninstall key and at \
                 least one of them does not have a working uninstaller. If you remove one, \
                 remove the broken one."
                    .to_string(),
            );
        }
    }

    if let Some(parent) = &e.parent_display {
        reasons.push(format!(
            "Child component of \"{parent}\". Deleting this key on its own can break the \
             parent product's uninstaller."
        ));
        if verdict == Verdict::Orphan {
            verdict = Verdict::Suspect;
        }
    }

    if e.no_remove {
        reasons.push(
            "NoRemove is set, so Windows deliberately hides the Uninstall button for this \
             entry. That is by design, not corruption."
                .to_string(),
        );
    }
    if e.system_component {
        reasons.push(
            "SystemComponent=1: this entry is hidden from Apps & Features by design. It only \
             appears here because you asked to include system components."
                .to_string(),
        );
    }

    e.reasons = reasons;
    e.verdict = verdict;
}

// ------------------------------------------------------------------ reporting

impl Entry {
    /// Long-form text for the detail pane.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Verdict:   {}\n", self.verdict.label()));
        s.push_str(&format!("Name:      {}\n", if self.has_display_name { self.name.clone() } else { "(no DisplayName)".into() }));
        if !self.version.is_empty() {
            s.push_str(&format!("Version:   {}\n", self.version));
        }
        if !self.publisher.is_empty() {
            s.push_str(&format!("Publisher: {}\n", self.publisher));
        }
        if !self.install_date.is_empty() {
            s.push_str(&format!("Installed: {}\n", self.install_date));
        }
        if self.size_kb > 0 {
            s.push_str(&format!("Size:      {}\n", human_kb(self.size_kb)));
        }
        s.push_str(&format!("Key:       {}\n", self.full_key_path()));
        s.push('\n');

        s.push_str(&format!("UninstallString      [{}] {}\n", self.uninstall_state.label(), self.uninstall.clone().unwrap_or_else(|| "-".into())));
        s.push_str(&format!("QuietUninstallString [{}] {}\n", self.quiet_state.label(), self.quiet_uninstall.clone().unwrap_or_else(|| "-".into())));
        s.push_str(&format!("InstallLocation      [{}] {}\n", self.location_state.label(), self.location.clone().unwrap_or_else(|| "-".into())));
        if let Some(pc) = &self.product_code {
            let state = match self.msi_installed {
                Some(true) => "registered",
                Some(false) => "NOT REGISTERED",
                None => "unknown",
            };
            s.push_str(&format!("MSI product code: {} ({})\n", pc, state));
        }
        s.push('\n');

        if self.reasons.is_empty() {
            s.push_str("Nothing looks wrong with this entry.\n");
        } else {
            s.push_str("WHY THIS IS FLAGGED\n");
            for r in &self.reasons {
                s.push_str(&format!("  - {}\n", r));
            }
        }
        s
    }
}

pub fn human_kb(kb: u64) -> String {
    if kb == 0 {
        return "-".into();
    }
    let mb = kb as f64 / 1024.0;
    if mb < 1024.0 {
        format!("{mb:.1} MB")
    } else {
        format!("{:.2} GB", mb / 1024.0)
    }
}

fn csv_cell(s: &str) -> String {
    let needs = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    let escaped = s.replace('"', "\"\"");
    if needs {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// Machine-readable report of everything found.
pub fn to_csv(entries: &[Entry]) -> String {
    let header = [
        "verdict", "name", "version", "publisher", "hive", "key_name", "registry_path",
        "uninstall_state", "uninstall_string", "quiet_state", "quiet_uninstall",
        "location_state", "install_location", "msi_product_code", "msi_registered",
        "steam_manifest_gone", "duplicate", "system_component", "size_kb", "reasons",
    ];
    let mut out = header.join(",");
    out.push('\n');
    for e in entries {
        let msi = match e.msi_installed {
            Some(true) => "installed",
            Some(false) => "gone",
            None => "",
        };
        let row = [
            e.verdict.label().to_string(),
            e.name.clone(),
            e.version.clone(),
            e.publisher.clone(),
            e.hive.label().to_string(),
            e.key.clone(),
            e.full_key_path(),
            e.uninstall_state.label().to_string(),
            e.uninstall.clone().unwrap_or_default(),
            e.quiet_state.label().to_string(),
            e.quiet_uninstall.clone().unwrap_or_default(),
            e.location_state.label().to_string(),
            e.location.clone().unwrap_or_default(),
            e.product_code.clone().unwrap_or_default(),
            msi.to_string(),
            e.steam_gone.to_string(),
            e.duplicate.to_string(),
            e.system_component.to_string(),
            e.size_kb.to_string(),
            e.reasons.join(" | "),
        ];
        out.push_str(&row.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

// ------------------------------------------------------------------ actions

use std::process::Command;

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// Write the key out as a .reg file so a removal is always undoable.
pub fn export_backup(entry: &Entry, backup_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(backup_dir)
        .map_err(|e| format!("Could not create the backup folder: {e}"))?;

    let safe: String = entry
        .key
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let file = backup_dir.join(format!("{safe}-{}-{stamp}.reg", entry.hive.label().replace(' ', "")));

    let target = file.to_string_lossy().to_string();
    let out = Command::new("reg")
        .args(["export", &entry.full_key_path(), &target, "/y"])
        .output()
        .map_err(|e| format!("Could not run reg.exe: {e}"))?;

    if !out.status.success() {
        return Err(lossy(&out.stderr));
    }
    Ok(file)
}

/// Delete just the Uninstall key. This never touches program files.
pub fn delete_key(entry: &Entry) -> Result<(), String> {
    let out = Command::new("reg")
        .args(["delete", &entry.full_key_path(), "/f"])
        .output()
        .map_err(|e| format!("Could not run reg.exe: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = lossy(&out.stderr);
        if err.is_empty() {
            Err("Access denied - HKLM keys need an elevated (Administrator) run.".into())
        } else {
            Err(err)
        }
    }
}

/// The install folder for an entry, falling back to the uninstaller's own folder.
pub fn folder_for(entry: &Entry) -> Option<String> {
    if let Some(loc) = &entry.location {
        let cleaned = expand_env(loc)
            .trim()
            .trim_matches('"')
            .trim_end_matches('\\')
            .to_string();
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }
    let cmd = entry.uninstall.as_ref().or(entry.quiet_uninstall.as_ref())?;
    let target = extract_target(cmd)?;
    let target = expand_env(&target);
    Path::new(&target)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|p| !p.is_empty())
}

/// Open a folder in Explorer, if it exists.
pub fn open_in_explorer(path: &str) -> Result<(), String> {
    let expanded = expand_env(path);
    let expanded = expanded.trim().trim_matches('"').trim_end_matches('\\').to_string();
    if expanded.is_empty() || !Path::new(&expanded).exists() {
        return Err("That folder does not exist.".into());
    }
    Command::new("explorer")
        .arg(&expanded)
        .spawn()
        .map_err(|e| format!("Could not open Explorer: {e}"))?;
    Ok(())
}

/// Launch the program's own uninstaller so the user can remove it properly first.
pub fn run_uninstaller(entry: &Entry) -> Result<(), String> {
    let cmd = entry
        .uninstall
        .clone()
        .or_else(|| entry.quiet_uninstall.clone())
        .ok_or("This entry has no UninstallString to run.")?;

    let target = extract_target(&cmd).ok_or("Could not work out which program to run.")?;
    if !Path::new(&target).exists() {
        return Err(format!("The uninstaller is gone, which is why Uninstall does nothing:\n{target}"));
    }

    // Pass the original arguments on to the executable we identified.
    let args: String = match cmd.find(&target) {
        Some(at) => cmd[at + target.len()..].trim().to_string(),
        None => String::new(),
    };

    let mut c = Command::new(&target);
    if !args.is_empty() {
        c.arg(args);
    }
    c.spawn().map_err(|e| format!("Could not start {target}: {e}"))?;
    Ok(())
}

/// `.reg` files written by reg.exe are UTF-16LE with a BOM (older Windows writes
/// ANSI), so a plain UTF-8 read fails. Decode properly.
fn read_reg_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("the backup file could not be read: {e}"))?;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some(u16::from_le_bytes([c[0], c[1]]))
                } else {
                    None
                }
            })
            .collect();
        Ok(String::from_utf16_lossy(&units))
    } else {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// End-to-end check of the whole pipeline against a throwaway key, so nothing
/// real is touched: create -> get detected as a ghost -> back up -> delete -> gone.
/// This exercises the exact `reg.exe` calls the Remove buttons use, including a
/// key name containing both spaces and braces.
pub fn self_test() -> Result<String, String> {
    const PROBE: &str = "AppCleaner selftest probe {1b2a3c4d-0000-4000-8000-000000000001}";

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let parent = hkcu
        .create_subkey_with_flags(Hive::Hkcu.open_path(), KEY_READ | KEY_WOW64_64KEY)
        .map_err(|e| format!("could not open the HKCU uninstall key: {e}"))?
        .0;
    let probe_key = parent
        .create_subkey_with_flags(PROBE, KEY_ALL_ACCESS | KEY_WOW64_64KEY)
        .map_err(|e| format!("could not create the probe key: {e}"))?
        .0;
    probe_key
        .set_value("DisplayName", &"AppCleaner selftest probe")
        .map_err(|e| format!("could not write DisplayName: {e}"))?;
    probe_key
        .set_value(
            "UninstallString",
            &"\"C:\\AppCleaner-does-not-exist\\unins000.exe\" /SILENT",
        )
        .map_err(|e| format!("could not write UninstallString: {e}"))?;
    drop(probe_key);
    drop(parent);

    let mut steps: Vec<String> = Vec::new();

    let outcome = (|| -> Result<(), String> {
        // 1. the scanner must see the probe and call it a ghost
        let found = scan().into_iter().find(|e| e.key == PROBE);
        let entry = found.ok_or("the scanner did not see the probe key at all")?;
        if entry.verdict != Verdict::Orphan {
            return Err(format!(
                "expected the probe to be classified ORPHAN, got {}",
                entry.verdict.label()
            ));
        }
        steps.push("scanner read all 4 views, found the probe key and classified it ORPHAN".into());

        // 2. the backup must be a real, restorable .reg file
        let dir = {
            let mut d = env::temp_dir();
            d.push("AppCleaner-selftest");
            d
        };
        let backup = export_backup(&entry, &dir)?;
        let text = read_reg_file(&backup)?;
        if !text.contains("DisplayName") || !text.contains("unins000.exe") {
            return Err("the backup file does not contain the key's values".to_string());
        }
        steps.push(format!(
            "reg export wrote a restorable backup containing the key's values ({})",
            backup.display()
        ));

        // 3. the delete must really remove it
        delete_key(&entry)?;
        let after = scan();
        if after.iter().any(|e| e.key == PROBE) {
            return Err("the probe key is still present after the delete".to_string());
        }
        steps.push("reg delete removed the key and a re-scan confirms it is gone".into());
        let _ = fs::remove_file(&backup);
        Ok(())
    })();

    // Always clean the probe up, even if a step failed part way through.
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(parent) = hkcu.open_subkey_with_flags(Hive::Hkcu.open_path(), KEY_READ | KEY_WOW64_64KEY)
    {
        let _ = parent.delete_subkey_with_flags(PROBE, KEY_WOW64_64KEY);
    }

    match outcome {
        Ok(()) => Ok(steps.join("\n  ok - ")),
        Err(e) => Err(format!("{}  FAILED: {e}", steps.join("\n  ok - "))),
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_path_with_spaces_and_args() {
        let t = extract_target(r#""E:\Games\Cyberpunk 2077\Uninstall\unins000.exe" /SILENT"#).unwrap();
        assert_eq!(t, r"E:\Games\Cyberpunk 2077\Uninstall\unins000.exe");
    }

    #[test]
    fn unquoted_path_with_spaces_is_found_by_extension() {
        // Very common in the registry and the reason naive splitting fails.
        let t = extract_target(r"C:\Program Files\Fake App\unins000.exe /SILENT").unwrap();
        assert_eq!(t, r"C:\Program Files\Fake App\unins000.exe");
    }

    #[test]
    fn msi_command_line_yields_the_msiexec_path() {
        let t = extract_target(r#"MsiExec.exe /X{2F7EDC46-15DE-4B05-9C7F-0D036CC96D77}"#).unwrap();
        assert_eq!(t, "MsiExec.exe");
    }

    #[test]
    fn finds_product_codes() {
        let g = find_guid(r#"MsiExec.exe /X{2F7EDC46-15DE-4B05-9C7F-0D036CC96D77}"#).unwrap();
        assert_eq!(g, "{2F7EDC46-15DE-4B05-9C7F-0D036CC96D77}");
        assert!(find_guid(r#""C:\a\unins000.exe" /SILENT"#).is_none());
        assert!(find_guid("{not-a-guid}").is_none());
    }

    #[test]
    fn expands_environment_variables_including_parenthesised_names() {
        let root = std::env::var("SystemRoot").unwrap();
        let out = expand_env(r"%SystemRoot%\System32\cmd.exe");
        assert_eq!(out, format!(r"{root}\System32\cmd.exe"));

        // An unknown variable is left alone rather than silently dropped.
        assert_eq!(expand_env(r"%NOT_A_REAL_VAR_XYZ%\x.exe"), r"%NOT_A_REAL_VAR_XYZ%\x.exe");
    }

    #[test]
    fn classifies_paths_by_what_actually_exists() {
        assert_eq!(judge_path(r"C:\Windows"), PathState::Present);
        assert_eq!(judge_path(r"C:\Windows\\"), PathState::Present);
        assert_eq!(
            judge_path(r"C:\Users\definitely\not\here\unins000.exe"),
            PathState::Missing
        );
        // Relative paths cannot be resolved reliably, so they must never be
        // reported as missing.
        assert_eq!(judge_path("Files/Strinova/unins000.exe"), PathState::Relative);
        assert_eq!(judge_path("AnyDesk.exe"), PathState::Unresolvable);
        assert_eq!(judge_path("   "), PathState::Absent);
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn verdict_ordering_is_severity_ascending() {
        assert!(Verdict::Ok < Verdict::Hidden);
        assert!(Verdict::Hidden < Verdict::Suspect);
        assert!(Verdict::Suspect < Verdict::Orphan);
    }

    #[test]
    fn every_hive_maps_to_a_real_registry_path() {
        for h in Hive::ALL {
            assert!(h.reg_path().starts_with("HKLM\\") || h.reg_path().starts_with("HKCU\\"));
            assert!(h.open_path().contains("CurrentVersion\\Uninstall"));
        }
    }

    /// A minimal entry whose on-disk states we control directly.
    fn probe(uninstall: PathState, location: PathState) -> Entry {
        Entry {
            hive: Hive::Hkcu,
            key: "SomeApp".into(),
            name: "SomeApp".into(),
            has_display_name: true,
            version: String::new(),
            publisher: String::new(),
            install_date: String::new(),
            size_kb: 0,
            uninstall: Some(r"C:\SomeApp\unins000.exe".into()),
            quiet_uninstall: None,
            location: Some(r"C:\SomeApp".into()),
            product_code: None,
            is_msi: false,
            system_component: false,
            no_remove: false,
            parent_display: None,
            uninstall_state: uninstall,
            quiet_state: PathState::Absent,
            location_state: location,
            msi_installed: None,
            steam_gone: false,
            duplicate: false,
            duplicate_benign: false,
            verdict: Verdict::Ok,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn gone_uninstaller_and_gone_folder_is_a_confirmed_ghost() {
        let mut e = probe(PathState::Missing, PathState::Missing);
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Orphan);
        assert!(e.safe_to_remove());
    }

    #[test]
    fn gone_uninstaller_but_folder_still_there_is_only_a_suspect() {
        let mut e = probe(PathState::Missing, PathState::Present);
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Suspect);
        assert!(!e.safe_to_remove(), "must not be auto-removable");
    }

    #[test]
    fn working_uninstaller_with_a_stale_location_stays_ok() {
        // This is the rule that keeps the list short: if it can still be
        // uninstalled, it is not junk.
        let mut e = probe(PathState::Present, PathState::Missing);
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Ok);
        assert!(e
            .reasons
            .iter()
            .any(|r| r.contains("InstallLocation") && r.contains("do NOT remove")));
    }

    #[test]
    fn unresolvable_paths_are_never_treated_as_missing() {
        let mut e = probe(PathState::Relative, PathState::Absent);
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Ok);

        let mut e2 = probe(PathState::Unresolvable, PathState::Absent);
        classify(&mut e2);
        assert_eq!(e2.verdict, Verdict::Ok);
    }

    #[test]
    fn msi_product_no_longer_registered_is_a_ghost() {
        let mut e = probe(PathState::Present, PathState::Absent);
        e.is_msi = true;
        e.product_code = Some("{2F7EDC46-15DE-4B05-9C7F-0D036CC96D77}".into());
        e.msi_installed = Some(false);
        e.uninstall_state = PathState::Missing;
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Orphan);
    }

    #[test]
    fn steam_key_with_no_appmanifest_is_a_ghost() {
        let mut e = probe(PathState::Present, PathState::Present);
        e.steam_gone = true;
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Orphan);
    }

    #[test]
    fn child_of_a_parent_product_is_downgraded_from_ghost() {
        let mut e = probe(PathState::Missing, PathState::Missing);
        e.parent_display = Some("Some Suite".into());
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Suspect);
    }

    #[test]
    fn duplicate_names_alone_never_change_the_verdict() {
        let mut entries = vec![
            probe(PathState::Present, PathState::Present),
            probe(PathState::Present, PathState::Present),
        ];
        mark_duplicates(&mut entries);
        assert!(entries[0].duplicate && entries[1].duplicate);
        assert!(entries[0].duplicate_benign, "both work, so this is normal");
        classify(&mut entries[0]);
        assert_eq!(entries[0].verdict, Verdict::Ok);
    }

    #[test]
    fn missing_display_name_is_reported_as_hidden_not_removed() {
        let mut e = probe(PathState::Absent, PathState::Absent);
        e.has_display_name = false;
        e.name = "SomeApp".into();
        e.uninstall = None;
        e.location = None;
        classify(&mut e);
        assert_eq!(e.verdict, Verdict::Hidden);
        assert!(!e.safe_to_remove());
    }
}









