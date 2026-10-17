//! Uninstall Registry Ghosts - find and clean up the ghost entries that are
//! left behind in Windows "Apps & Features" / "Installed apps".
//!
//! The app never removes anything by itself: it ranks every uninstall registry
//! key by how confident it is that the key is a leftover, explains *why*, and
//! then lets you delete the ones you agree with - after exporting a .reg backup.

mod scan;
mod sys;

use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use native_windows_derive as nwd;
use native_windows_gui as nwg;
use nwd::NwgUi;
use nwg::NativeUi;

use scan::{Entry, Verdict};

const TITLE: &str = "Uninstall Registry Ghosts - clean up Apps & Features";

const FILTERS: [&str; 6] = [
    "Ghost entries (definite)",
    "Likely suspects",
    "Duplicated names",
    "Hidden keys (no DisplayName)",
    "Problem entries only",
    "Everything",
];

const COLUMNS: [(&str, i32); 8] = [
    ("Verdict", 120),
    ("Name", 300),
    ("Version", 110),
    ("Publisher", 190),
    ("Registry view", 110),
    ("Uninstaller", 100),
    ("Install folder", 110),
    ("Registry key name", 260),
];

#[derive(Default, NwgUi)]
pub struct App {
    #[nwg_control(size: (1280, 820), position: (50, 40), title: TITLE,
                  flags: "WINDOW|VISIBLE|RESIZABLE|MAXIMIZE_BOX")]
    #[nwg_events(
        OnInit: [App::startup],
        OnWindowClose: [App::exit],
        OnResize: [App::relayout]
    )]
    window: nwg::Window,

    #[nwg_resource(family: "Segoe UI", size: 9)]
    font: nwg::Font,

    // ---- filters ----
    #[nwg_control(collection: FILTERS.to_vec(), selected_index: Some(0))]
    #[nwg_events(OnComboxBoxSelection: [App::refresh])]
    filter: nwg::ComboBox<&'static str>,

    #[nwg_control(placeholder_text: Some("Search name, publisher or key..."))]
    #[nwg_events(OnTextInput: [App::refresh])]
    search: nwg::TextInput,

    #[nwg_control(text: "Include system components")]
    #[nwg_events(OnButtonClick: [App::refresh])]
    show_system: nwg::CheckBox,

    #[nwg_control(text: "Rescan")]
    #[nwg_events(OnButtonClick: [App::rescan])]
    btn_rescan: nwg::Button,

    // ---- main views ----
    #[nwg_control(list_style: nwg::ListViewStyle::Detailed,
                  ex_flags: nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT,
                  item_count: 800, focus: true)]
    #[nwg_events(
        OnListViewItemChanged: [App::on_select],
        OnListViewDoubleClick: [App::on_activate]
    )]
    list: nwg::ListView,

    #[nwg_control(readonly: true,
                  flags: "VISIBLE|VSCROLL|HSCROLL|AUTOVSCROLL|TAB_STOP",
                  text: "Select a row to see exactly why an entry is there and what is wrong with it.")]
    detail: nwg::TextBox,

    // ---- actions ----
    #[nwg_control(text: "Remove selected")]
    #[nwg_events(OnButtonClick: [App::remove_selected])]
    btn_remove: nwg::Button,

    #[nwg_control(text: "Remove all definite ghosts")]
    #[nwg_events(OnButtonClick: [App::remove_all_ghosts])]
    btn_remove_all: nwg::Button,

    #[nwg_control(text: "Run real uninstaller")]
    #[nwg_events(OnButtonClick: [App::run_uninstaller])]
    btn_uninstall: nwg::Button,

    #[nwg_control(text: "Open folder")]
    #[nwg_events(OnButtonClick: [App::open_folder])]
    btn_folder: nwg::Button,

    #[nwg_control(text: "Export report (.csv)")]
    #[nwg_events(OnButtonClick: [App::export_report])]
    btn_export: nwg::Button,

    #[nwg_control(text: "Backup selected (.reg)")]
    #[nwg_events(OnButtonClick: [App::backup_selected])]
    btn_backup: nwg::Button,

    #[nwg_control(text: "Restart as admin")]
    #[nwg_events(OnButtonClick: [App::relaunch_as_admin])]
    btn_admin: nwg::Button,

    #[nwg_control(text: "Starting...")]
    status: nwg::StatusBar,

    // ---- state (not controls) ----
    all: RefCell<Vec<Entry>>,
    visible: RefCell<Vec<usize>>,
    selected: RefCell<Option<usize>>,
    busy: Cell<bool>,
}

impl App {
    // ---------------------------------------------------------------- lifecycle

    fn startup(&self) {
        self.list.set_headers_enabled(true);
        for (text, width) in COLUMNS {
            self.list.insert_column(nwg::InsertListViewColumn {
                index: None,
                fmt: Some(nwg::ListViewColumnFlags::LEFT),
                width: Some(width),
                text: Some(text.to_string()),
            });
        }
        self.relayout();
        self.rescan();
    }

    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }

    // ---------------------------------------------------------------- layout

    fn relayout(&self) {
        let (w, h) = self.window.size();
        let (w, h) = (w as i32, h as i32);
        let m = 10i32;
        let gap = 8i32;

        // --- top filter bar ---
        // A Win32 combo box's height includes its dropped-down list, so it is
        // deliberately much taller than the visible field.
        self.filter.set_position(m, m);
        self.filter.set_size(230, u(240));

        let rescan_w = 90;
        let check_w = 215;
        let right = w - m;

        self.btn_rescan.set_position(right - rescan_w, m + 2);
        self.btn_rescan.set_size(u(rescan_w), u(26));

        self.show_system.set_position(right - rescan_w - gap - check_w, m + 4);
        self.show_system.set_size(u(check_w), u(22));

        let search_x = m + 230 + gap;
        let search_w = right - rescan_w - gap - check_w - gap - search_x;
        self.search.set_position(search_x, m + 2);
        self.search.set_size(u(search_w), u(26));

        // --- bottom action bar ---
        let buttons: [&nwg::Button; 7] = [
            &self.btn_remove,
            &self.btn_remove_all,
            &self.btn_uninstall,
            &self.btn_folder,
            &self.btn_export,
            &self.btn_backup,
            &self.btn_admin,
        ];
        let bar_h = 30;
        let bar_y = h - bar_h - 36; // leave room for the status bar
        let bw = (w - 2 * m - gap * (buttons.len() as i32 - 1)) / buttons.len() as i32;
        for (i, b) in buttons.iter().enumerate() {
            b.set_position(m + (bw + gap) * i as i32, bar_y);
            b.set_size(u(bw), u(bar_h));
        }

        // --- middle: table + detail ---
        let top = m + 30 + gap;
        let detail_w = 440;
        let list_h = bar_y - gap - top;
        let list_w = w - 2 * m - detail_w - gap;

        self.list.set_position(m, top);
        self.list.set_size(u(list_w), u(list_h));
        self.detail.set_position(m + list_w + gap, top);
        self.detail.set_size(u(detail_w), u(list_h));
    }

    // ---------------------------------------------------------------- data

    fn rescan(&self) {
        self.status.set_text(0, "Reading the registry, please wait...");
        let entries = scan::scan();
        self.all.replace(entries);
        self.refresh();
    }

    fn refresh(&self) {
        let which = self.filter.selection().unwrap_or(0);
        let needle = self.search.text().to_lowercase();
        let include_system = self.show_system.check_state() == nwg::CheckBoxState::Checked;

        let mut visible: Vec<usize> = Vec::new();
        let (total, ghosts, suspects, hidden) = {
            let all = self.all.borrow();
            let mut counts = (all.len(), 0usize, 0usize, 0usize);
            for (i, e) in all.iter().enumerate() {
                match e.verdict {
                    Verdict::Orphan => counts.1 += 1,
                    Verdict::Suspect => counts.2 += 1,
                    Verdict::Hidden => counts.3 += 1,
                    Verdict::Ok => {}
                }

                if e.system_component && !include_system {
                    continue;
                }
                let keep = match which {
                    0 => e.verdict == Verdict::Orphan,
                    1 => e.verdict == Verdict::Suspect,
                    2 => e.duplicate && !e.duplicate_benign,
                    3 => e.verdict == Verdict::Hidden,
                    4 => e.verdict != Verdict::Ok,
                    _ => true,
                };
                if !keep {
                    continue;
                }
                if !needle.is_empty() {
                    let hay =
                        format!("{} {} {} {}", e.name, e.publisher, e.key, e.version).to_lowercase();
                    if !hay.contains(&needle) {
                        continue;
                    }
                }
                visible.push(i);
            }
            counts
        };

        self.busy.set(true);
        self.list.set_redraw(false);
        self.list.clear();
        self.list.set_item_count(visible.len() as u32);
        {
            let all = self.all.borrow();
            for i in &visible {
                let e = match all.get(*i) {
                    Some(e) => e,
                    None => continue,
                };
                self.list.insert_items_row(
                    None,
                    &[
                        e.verdict.label(),
                        e.name.as_str(),
                        e.version.as_str(),
                        e.publisher.as_str(),
                        e.hive.label(),
                        e.uninstall_state.label(),
                        e.location_state.label(),
                        e.key.as_str(),
                    ],
                );
            }
        }
        self.list.set_redraw(true);
        self.list.invalidate();
        let shown = visible.len();
        self.visible.replace(visible);
        *self.selected.borrow_mut() = None;
        self.busy.set(false);

        let mut status = format!(
            "{total} uninstall keys read - {ghosts} definite ghosts, {suspects} likely suspects, \
             {hidden} keys with no DisplayName.   Showing {shown}."
        );
        if !include_system {
            status.push_str("  System components are hidden.");
        }
        if !sys::is_elevated() {
            status.push_str("   NOT ELEVATED - press \"Restart as admin\" to delete HKLM keys.");
        }
        self.status.set_text(0, &status);

        self.detail.set_text(
            "Select a row to see exactly what this key is, what it points at, and whether it \
             is safe to delete.\n\n\
             ORPHAN  - confirmed leftover. Nothing the key points to exists any more, which is \
             why Uninstall does nothing or errors out.\n\
             SUSPECT - partly stale. Something still resolves, so check it before removing.\n\
             HIDDEN  - the key has no DisplayName, so Apps & Features never shows it.\n\n\
             Nothing is ever removed until you press a button, and every removal writes a .reg \
             backup first that you can double-click to undo.",
        );
    }

    fn on_select(&self) {
        if self.busy.get() {
            return;
        }
        let row = match self.list.selected_item() {
            Some(r) => r,
            None => return,
        };
        let idx = match self.visible.borrow().get(row).copied() {
            Some(i) => i,
            None => return,
        };
        *self.selected.borrow_mut() = Some(idx);
        let text = match self.all.borrow().get(idx) {
            Some(e) => e.describe(),
            None => return,
        };
        self.detail.set_text_unix2dos(&text);
    }

    fn on_activate(&self) {
        self.run_uninstaller();
    }

    fn selected_entries(&self) -> Vec<usize> {
        let rows = self.list.selected_items();
        let vis = self.visible.borrow();
        rows.iter().filter_map(|r| vis.get(*r).copied()).collect()
    }

    fn current(&self) -> Option<usize> {
        *self.selected.borrow()
    }

    // ---------------------------------------------------------------- actions

    fn confirm(&self, title: &str, body: &str) -> bool {
        let choice = nwg::modal_message(
            &self.window,
            &nwg::MessageParams {
                title,
                content: body,
                buttons: nwg::MessageButtons::YesNo,
                icons: nwg::MessageIcons::Warning,
            },
        );
        choice == nwg::MessageChoice::Yes
    }

    fn work_dir(&self) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push("uninstall-registry-ghosts");
        dir
    }

    fn remove_selected(&self) {
        let idxs = self.selected_entries();
        self.remove_entries(idxs);
    }

    fn remove_all_ghosts(&self) {
        let idxs: Vec<usize> = {
            let all = self.all.borrow();
            all.iter()
                .enumerate()
                .filter(|(_, e)| e.verdict == Verdict::Orphan && !e.system_component)
                .map(|(i, _)| i)
                .collect()
        };

        if idxs.is_empty() {
            nwg::modal_info_message(
                &self.window,
                "Nothing to remove",
                "No entry is currently marked as a definite ghost.\n\nSwitch to \"Likely \
                 suspects\" and review those by hand - they are often fine to remove too, but \
                 something about them still resolves, so this app will not promise it for you.",
            );
            return;
        }

        let names: Vec<String> = {
            let all = self.all.borrow();
            idxs.iter()
                .filter_map(|i| all.get(*i))
                .take(20)
                .map(|e| format!("  - {}   [{}]", e.name, e.hive.label()))
                .collect()
        };
        let mut body = format!(
            "These {} entries point only at files and folders that no longer exist, which is \
             exactly why they cannot be uninstalled. Deleting the keys takes them out of Apps & \
             Features.\n\n",
            idxs.len()
        );
        body.push_str(&names.join("\n"));
        if idxs.len() > 20 {
            body.push_str(&format!("\n  ... and {} more", idxs.len() - 20));
        }
        body.push_str(
            "\n\nEvery key is exported to a .reg backup first. No program files are touched.",
        );

        if self.confirm("Remove all definite ghosts?", &body) {
            self.remove_entries(idxs);
        }
    }

    fn remove_entries(&self, idxs: Vec<usize>) {
        if idxs.is_empty() {
            nwg::modal_info_message(
                &self.window,
                "Nothing selected",
                "Click a row first. Ctrl+click or Shift+click selects several.",
            );
            return;
        }

        let risky: Vec<String> = {
            let all = self.all.borrow();
            idxs.iter()
                .filter_map(|i| all.get(*i))
                .filter(|e| !e.safe_to_remove())
                .map(|e| e.name.clone())
                .collect()
        };

        let mut body = format!(
            "Delete {} uninstall key(s) from the registry?\n\nEach key is exported to a .reg \
             file first, so you can undo this by double-clicking that file. No program files \
             are deleted.\n",
            idxs.len()
        );
        if !risky.is_empty() {
            body.push_str(&format!(
                "\n{} of these are NOT confirmed leftovers - they are suspects, duplicates or \
                 system components, and one of them may still be a working uninstaller:\n",
                risky.len()
            ));
            for r in risky.iter().take(15) {
                body.push_str(&format!("  - {r}\n"));
            }
            if risky.len() > 15 {
                body.push_str(&format!("  ... and {} more\n", risky.len() - 15));
            }
        }

        if !self.confirm("Delete registry keys?", &body) {
            return;
        }

        let dir = self.work_dir();
        let mut removed = 0usize;
        let mut errors: Vec<String> = Vec::new();
        {
            let all = self.all.borrow();
            for i in &idxs {
                let e = match all.get(*i) {
                    Some(e) => e,
                    None => continue,
                };
                // Never delete without a backup on disk first.
                if let Err(err) = scan::export_backup(e, &dir) {
                    errors.push(format!("{}: could not back up - {err}", e.name));
                    continue;
                }
                match scan::delete_key(e) {
                    Ok(()) => removed += 1,
                    Err(err) => errors.push(format!("{}: {err}", e.name)),
                }
            }
        }

        self.rescan();

        let mut msg = format!("Removed {removed} key(s).\n\nBackups are in:\n  {}", dir.display());
        if !errors.is_empty() {
            msg.push_str(&format!("\n\n{} problem(s):\n{}", errors.len(), errors.join("\n")));
            if !sys::is_elevated() {
                msg.push_str("\n\nTip: HKLM keys need an elevated run - use \"Restart as admin\".");
            }
        }
        nwg::modal_info_message(&self.window, "Done", &msg);
    }

    fn run_uninstaller(&self) {
        let idx = match self.current() {
            Some(i) => i,
            None => {
                nwg::modal_info_message(&self.window, "Nothing selected", "Select a row first.");
                return;
            }
        };
        let entry = match self.all.borrow().get(idx).cloned() {
            Some(e) => e,
            None => return,
        };
        match scan::run_uninstaller(&entry) {
            Ok(()) => {
                self.status.set_text(
                    0,
                    &format!(
                        "Started {}'s own uninstaller. Press \"Rescan\" when it finishes.",
                        entry.name
                    ),
                );
            }
            Err(err) => {
                nwg::modal_error_message(
                    &self.window,
                    "Cannot run the uninstaller",
                    &format!("{}\n\n{err}", entry.name),
                );
            }
        }
    }

    fn open_folder(&self) {
        let idx = match self.current() {
            Some(i) => i,
            None => {
                nwg::modal_info_message(&self.window, "Nothing selected", "Select a row first.");
                return;
            }
        };
        let entry = match self.all.borrow().get(idx).cloned() {
            Some(e) => e,
            None => return,
        };
        match scan::folder_for(&entry) {
            Some(path) => {
                if let Err(err) = scan::open_in_explorer(&path) {
                    nwg::modal_error_message(
                        &self.window,
                        "Cannot open that folder",
                        &format!("{path}\n\n{err}"),
                    );
                }
            }
            None => {
                nwg::modal_info_message(
                    &self.window,
                    "No folder recorded",
                    "This key records no install location and its uninstaller path is unusable \
                     too. That is usually proof enough that the program is gone.",
                );
            }
        }
    }

    fn backup_selected(&self) {
        let idxs = self.selected_entries();
        if idxs.is_empty() {
            nwg::modal_info_message(&self.window, "Nothing selected", "Select a row first.");
            return;
        }
        let dir = self.work_dir();
        let mut done = 0usize;
        let mut errors: Vec<String> = Vec::new();
        {
            let all = self.all.borrow();
            for i in &idxs {
                if let Some(e) = all.get(*i) {
                    match scan::export_backup(e, &dir) {
                        Ok(_) => done += 1,
                        Err(err) => errors.push(format!("{}: {err}", e.name)),
                    }
                }
            }
        }
        let mut msg = format!("Wrote {done} .reg backup(s) to:\n  {}", dir.display());
        if !errors.is_empty() {
            msg.push_str(&format!("\n\nProblems:\n{}", errors.join("\n")));
        }
        nwg::modal_info_message(&self.window, "Backup", &msg);
    }

    fn export_report(&self) {
        let csv = {
            let all = self.all.borrow();
            scan::to_csv(&all)
        };
        let dir = self.work_dir();
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("uninstall-registry-ghosts-report.csv");
        match std::fs::write(&file, csv) {
            Ok(()) => {
                nwg::modal_info_message(
                    &self.window,
                    "Report written",
                    &format!(
                        "Full report - every key, its verdict and the reason:\n  {}\n\nYou can \
                         open it in Excel.",
                        file.display()
                    ),
                );
            }
            Err(e) => {
                nwg::modal_error_message(
                    &self.window,
                    "Could not write the report",
                    &e.to_string(),
                );
            }
        }
    }

    fn relaunch_as_admin(&self) {
        if sys::is_elevated() {
            nwg::modal_info_message(
                &self.window,
                "Already elevated",
                "This copy is already running as Administrator.",
            );
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => {
                nwg::modal_error_message(
                    &self.window,
                    "Cannot find this program",
                    "Could not work out which executable to relaunch.",
                );
                return;
            }
        };
        let command = format!("Start-Process -FilePath '{exe}' -Verb RunAs");
        let started = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &command])
            .spawn();
        match started {
            Ok(_) => nwg::stop_thread_dispatch(),
            Err(e) => {
                nwg::modal_error_message(
                    &self.window,
                    "Could not relaunch",
                    &format!("{e}\n\nStart this program as Administrator manually instead."),
                );
            }
        }
    }
}

/// Negative sizes would wrap into huge u32 values and wreck the layout.
fn u(v: i32) -> u32 {
    if v < 0 {
        0
    } else {
        v as u32
    }
}

/// Headless mode: `uninstall-registry-ghosts --cli [--all] [--csv <path>]`
/// Same analysis as the window, so it can be scripted or checked by hand.
fn run_cli(args: &[String]) {
    let show_all = args.iter().any(|a| a == "--all");
    let csv_path = args
        .iter()
        .position(|a| a == "--csv")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let entries = scan::scan();

    let mut ghosts = 0usize;
    let mut suspects = 0usize;
    let mut hidden = 0usize;
    for e in &entries {
        match e.verdict {
            Verdict::Orphan => ghosts += 1,
            Verdict::Suspect => suspects += 1,
            Verdict::Hidden => hidden += 1,
            Verdict::Ok => {}
        }
    }

    println!(
        "Uninstall Registry Ghosts - {} uninstall keys read across 4 registry views",
        entries.len()
    );
    println!("  definite ghosts : {ghosts}");
    println!("  likely suspects : {suspects}");
    println!("  hidden keys     : {hidden}");
    println!();

    let dump = |label: &str, verdict: Verdict| {
        println!("===== {label} =====");
        let mut n = 0;
        for e in entries
            .iter()
            .filter(|e| e.verdict == verdict && (show_all || !e.system_component))
        {
            n += 1;
            let version = if e.version.is_empty() {
                String::new()
            } else {
                format!("  ({})", e.version)
            };
            println!("[{}] {}{version}", e.verdict.label(), e.name);
            println!("    key : {}", e.full_key_path());
            if let Some(u) = &e.uninstall {
                println!("    uninstall : [{}] {u}", e.uninstall_state.label());
            }
            if let Some(l) = &e.location {
                println!("    location  : [{}] {l}", e.location_state.label());
            }
            for r in &e.reasons {
                println!("    - {r}");
            }
            println!();
        }
        if n == 0 {
            println!("  (none)\n");
        }
    };

    dump("DEFINITE GHOSTS - safe to remove", Verdict::Orphan);
    dump("LIKELY SUSPECTS - review before removing", Verdict::Suspect);

    if let Some(path) = csv_path {
        match std::fs::write(&path, scan::to_csv(&entries)) {
            Ok(()) => println!("CSV report written to {path}"),
            Err(e) => eprintln!("Could not write {path}: {e}"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--selftest") {
        match scan::self_test() {
            Ok(steps) => {
                println!("SELF-TEST PASSED\n  ok - {steps}");
            }
            Err(e) => {
                eprintln!("SELF-TEST FAILED\n  {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if args
        .iter()
        .skip(1)
        .any(|a| matches!(a.as_str(), "--cli" | "--scan" | "--csv" | "--all" | "--help" | "-h"))
    {
        run_cli(&args);
        return;
    }

    nwg::init().expect("Failed to initialize the Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to load Segoe UI");

    let _app = App::build_ui(Default::default()).expect("Failed to build the UI");

    nwg::dispatch_thread_events();
}






