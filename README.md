# Registry Cleaner

*Find and remove the ghost entries left behind in the Windows Apps & Features
(Uninstall) registry.*

A small Windows tool for fixing the thing where **an app shows up in Apps &
Features, you press Uninstall, and nothing happens** — because the app was
already deleted (or its uninstaller was), but its registry key stayed behind.

It reads every "Add / Remove Programs" registry location, checks what each entry
actually points at on disk, and sorts the list by how confident it is that an
entry is a leftover. Nothing is ever removed without you asking, and every
removal writes a `.reg` backup first.

```
target\release\registry_cleaner.exe        # open the window
target\release\registry_cleaner.exe --cli  # same analysis, no window
```

418 KB executable, ~14 MB RAM at idle, no installer and no runtime needed.

## What the three verdicts mean

| Verdict | Meaning | Safe to delete? |
| --- | --- | --- |
| **ORPHAN** | A *confirmed* ghost. Nothing the key points at exists any more: the uninstaller file is gone **and** the install folder is gone. For MSI entries, the product code is no longer registered in the Windows Installer database. | Yes |
| **SUSPECT** | Something is demonstrably broken, but the program is probably still installed — e.g. the uninstaller is missing while the install folder is still on disk. | Look first |
| **HIDDEN** | The key has no `DisplayName`, so Apps & Features never shows it. Registry clutter, not what you are seeing in the list. | Usually leave alone |

Anything whose uninstaller still resolves is reported **OK**, even if its
`InstallLocation` value is stale — because it can still be uninstalled normally.
That rule is deliberate: it keeps the list short enough to act on. On a machine
with 559 registered keys it produces 36 confirmed ghosts rather than hundreds of
"maybe" entries.

## How an entry is judged

For each key in all four views (`HKLM` 64-bit, `HKLM` 32-bit, `HKCU` 64-bit,
`HKCU` 32-bit) the app:

1. Pulls the executable out of `UninstallString` / `QuietUninstallString`.
   Registry command lines are frequently *unquoted and contain spaces*, so the
   executable is located by its extension rather than by the first space.
   `%VAR%` (including `%ProgramFiles(x86)%`) is expanded first.
2. Checks whether that file exists.
3. Checks whether `InstallLocation` exists.
4. For MSI entries, asks the Windows Installer database whether the product code
   is still registered — `msiexec.exe` always exists, so the path alone would
   hide a dead product.
5. For `Steam App <id>` keys, looks for `appmanifest_<id>.acf` in **every**
   Steam library folder (Steam's own plus any added in `libraryfolders.vdf`).
   This is where most game ghosts come from.
6. Notes duplicate names, but only treats them as a problem if one copy is
   broken — shared components legitimately register the same name in several
   places, so a repeated name on its own is not flagged.

Relative uninstall paths and bare executable names are never reported as
missing, because they cannot be resolved reliably.

## Safety

- Nothing is deleted until you press a button, and a confirmation dialog lists
  exactly what is about to happen.
- Every removal runs `reg export` first. Backups go to
  `%TEMP%\registry_cleaner\` and are restorable by double-clicking
  them.
- Deleting a key never touches program files.
- `HKLM` keys need an elevated process. The status bar says when you are not
  elevated, and **Restart as admin** relaunches the app elevated.
- Entries with `SystemComponent=1` are hidden by default, which is what keeps
  the Windows SDK / redistributable noise out of the way.

## Using it

1. Open the app. The default view is **Ghost entries (definite)** — the ones
   that are provably junk.
2. Click a row. The detail pane explains, in plain language, exactly why that
   entry is flagged and what it points at.
3. Select rows (Ctrl/Shift click for multiple) and press **Remove selected**, or
   press **Remove all definite ghosts** to clear the whole confirmed list at once.
4. If an entry is *not* a ghost, **Run real uninstaller** launches the program's
   own uninstaller instead of deleting the key — usually the better move.

### Command line

```
registry_cleaner.exe                     # GUI
registry_cleaner.exe --cli               # print ghosts + suspects to stdout
registry_cleaner.exe --cli --all         # include system components
registry_cleaner.exe --cli --csv out.csv # full machine-readable report
registry_cleaner.exe --selftest          # end-to-end check on a throwaway key
```

`--selftest` creates a temporary key under `HKCU`, confirms the scanner sees it
and classifies it as a ghost, backs it up, deletes it, and confirms it is gone —
so the `reg.exe` plumbing (including key names containing spaces and braces) is
verified without touching anything real. It cleans the probe up even if a step
fails.

## Building

```
cargo build --release   # -> target\release\registry_cleaner.exe
cargo test              # 18 unit tests for the parsing + classification rules
```

Windows-only. Dependencies are `native-windows-gui` (native Win32 controls — no
GPU, no runtime, no bundled toolkit) and `winreg`. The Win32 calls needed for
elevation checking (`GetTokenInformation`) and MSI lookups
(`MsiGetProductInfoW`) are declared directly in `src/sys.rs` rather than pulling
in a bindings crate.

`Cargo.lock` is committed on purpose: this is a binary crate, so a lockfile
gives reproducible builds.

## Project layout

```
src/main.rs   window, filters, layout, action buttons, CLI entry point
src/scan.rs   registry reading, classification, backups, CSV, unit tests
src/sys.rs    Win32 FFI: elevation check + Windows Installer product lookup
```

## Known limitations

- The table is sorted by verdict, then name. Clicking a column header does not
  re-sort.
- Folder sizes are not measured; the `EstimatedSize` value from the registry is
  shown where an app provides it. Disk-level bloat (leftover folders, the
  `C:\Windows\Installer` cache, dead startup and scheduled-task entries) is out
  of scope — this tool only cleans the Uninstall hive.
- A relative or unresolvable uninstall path is reported as unknown rather than
  guessed at, so a few genuine ghosts stay in the OK column.
- UAC registry virtualisation (`VirtualStore`) is not consulted.
- Removing an `ORPHAN` key fixes the list entry, not the disk. If the program
  left a folder behind, delete that separately.

