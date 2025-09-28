use std::ffi::OsString;
use std::fs;
use std::env;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::process::Command;
use std::rc::Rc;
use std::cell::RefCell;
use winsafe::prelude::*;
use winsafe::{gui, AnyResult, co};
use winsafe::msg;
use path_tree::path_utils::{expand_env_vars_with_scope, RegistryScope, get_path_string_for_scope};

// Helper: strip child item decorations (emoji + overridden suffix)
fn strip_child_label(s: &str) -> String {
    // Remove inline goto chevron if present
    let s = s.strip_suffix(" ⤴").unwrap_or(s);
    // Remove overridden suffix if present
    let s = s.strip_suffix(" [overridden]").unwrap_or(s);
    // Remove color emoji
    if let Some(t) = s.strip_prefix("🟡 ") { return t.to_string(); }
    if let Some(t) = s.strip_prefix("🟢 ") { return t.to_string(); }
    s.to_string()
}

// Helper: strip root item decorations (emoji + trailing markers)
fn strip_root_label(mut s: &str) -> String {
    if let Some(t) = s.strip_suffix(" ⚠") { s = t; }
    if let Some(t) = s.strip_suffix(" ★") { s = t; }
    if let Some(t) = s.strip_suffix(" ★") { s = t; }
    if let Some(t) = s.strip_suffix(" ⚠") { s = t; }
    if let Some(t) = s.strip_prefix("🟢 ") { return t.to_string(); }
    if let Some(t) = s.strip_prefix("🔴 ") { return t.to_string(); }
    s.to_string()
}

fn is_executable_on_windows(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext = ext.to_ascii_lowercase();
        return matches!(ext.as_str(), "exe" | "bat" | "cmd" | "com" | "ps1");
    }
    false
}

fn collect_binaries_in_dir(dir: &Path) -> Vec<OsString> {
    let mut res = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if is_executable_on_windows(&p) {
                if let Some(name) = p.file_name().map(|s| s.to_os_string()) {
                    res.push(name);
                }
            }
        }
    }
    res
}


fn build_tree_data_with_scope(scope: RegistryScope) -> (
    Vec<Option<PathBuf>>,                 // first resolved directory per entry (if any)
    Vec<String>,                          // original PATH entries
    Vec<Vec<OsString>>,                   // binaries per entry (dedup across subpaths)
    HashMap<String, usize>,               // first-seen map for shadowing across entries
    Vec<Vec<PathBuf>>,                    // all resolved subpaths per entry
    Vec<HashMap<String, PathBuf>>,        // per-entry: bin name -> directory path where found
) {
    // Use PATH from the selected scope instead of process PATH, so we show only user or only system when requested.
    let path_str = get_path_string_for_scope(scope).unwrap_or_default();
    // Preserve original entries as they appear in PATH (split on ';'), but drop empty entries (e.g., trailing ';')
    let original_entries: Vec<String> = path_str
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let mut expanded_paths: Vec<Option<PathBuf>> = Vec::new();
    let mut original_paths: Vec<String> = Vec::new();
    let mut dir_bins: Vec<Vec<OsString>> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut all_dirs: Vec<Vec<PathBuf>> = Vec::new();
    let mut bin_dir_map_list: Vec<HashMap<String, PathBuf>> = Vec::new();

    for (idx, orig) in original_entries.into_iter().enumerate() {
        let info = expand_env_vars_with_scope(&orig, scope);
        let expanded = info.expanded;
        // Split expansion that may contain multiple ';'-separated paths
        let mut subpaths: Vec<PathBuf> = if expanded.is_empty() {
            Vec::new()
        } else {
            std::env::split_paths(&OsString::from(expanded)).collect()
        };
        // Keep only existing directories, preserve order
        let valid_dirs: Vec<PathBuf> = subpaths
            .drain(..)
            .filter(|p| p.exists() && p.is_dir())
            .collect();

        // Treat as resolved if any valid subdir exists; keep the first one for selection-based actions
        let resolved_first = valid_dirs.get(0).cloned();

        // Aggregate binaries across all valid subdirs for this entry; de-duplicate by name
        let mut bins_agg: Vec<OsString> = Vec::new();
        let mut seen_names = std::collections::HashSet::<String>::new();
        let mut bin_dir_map: HashMap<String, PathBuf> = HashMap::new();
        for dir_pb in &valid_dirs {
            let b = collect_binaries_in_dir(dir_pb);
            for bin in b {
                let name = bin.to_string_lossy().to_string();
                if seen_names.insert(name.clone()) {
                    bins_agg.push(OsString::from(name.clone()));
                    bin_dir_map.insert(name.clone(), dir_pb.clone());
                    // owner index is this entry's index
                    seen.entry(name).or_insert(idx);
                }
            }
        }

        expanded_paths.push(resolved_first);
        original_paths.push(orig);
        dir_bins.push(bins_agg);
        all_dirs.push(valid_dirs);
        bin_dir_map_list.push(bin_dir_map);
    }

    (expanded_paths, original_paths, dir_bins, seen, all_dirs, bin_dir_map_list)
}

#[derive(Clone)]
struct AppState {
    scope: RegistryScope,
    paths: Vec<Option<PathBuf>>,      // expanded directories
    orig_paths: Vec<String>,          // original PATH entries
    dir_bins: Vec<Vec<OsString>>,     // binaries per directory
    seen: HashMap<String, usize>,     // first-seen map for shadowing
    filter: String,                    // current filter text
    all_dirs: Vec<Vec<PathBuf>>,       // all resolved subpaths per entry
    bin_dir_map: Vec<HashMap<String, PathBuf>>, // per-entry bin -> directory path
}

impl AppState {
    fn rebuild(&mut self) {
    let (paths, orig_paths, dir_bins, seen, all_dirs, bin_dir_map) = build_tree_data_with_scope(self.scope);
    self.paths = paths;
    self.orig_paths = orig_paths;
    self.dir_bins = dir_bins;
    self.seen = seen;
    self.all_dirs = all_dirs;
    self.bin_dir_map = bin_dir_map;
    }
}

fn compute_stats(state: &AppState) -> (usize, usize, usize, usize, usize) {
    let total_dirs = state.orig_paths.len();
    let resolved = state.paths.iter().filter(|o| o.is_some()).count();
    let unresolved = total_dirs.saturating_sub(resolved);
    let total_bins: usize = state.dir_bins.iter().map(|v| v.len()).sum();
    let overridden = state
        .dir_bins
        .iter()
        .enumerate()
        .map(|(i, v)| v.iter().filter(|b| state.seen.get(&b.to_string_lossy().to_string()).map(|fi| *fi != i).unwrap_or(false)).count())
        .sum();
    (total_dirs, resolved, unresolved, total_bins, overridden)
}

fn set_window_title_with_stats(wnd: &gui::WindowMain, state: &AppState) -> AnyResult<()> {
    let (total_dirs, resolved, unresolved, total_bins, overridden) = compute_stats(state);
    let scope_label = match state.scope {
        RegistryScope::UserOnly => "User",
        RegistryScope::SystemOnly => "System",
        RegistryScope::ProcessOnly => "Process",
        RegistryScope::ProcessUserSystem => "Process+User+System",
        RegistryScope::UserThenSystem => "User→System",
        RegistryScope::SystemThenUser => "System→User",
    };
    let filtered = if state.filter.trim().is_empty() { String::new() } else { format!(" — Filter: '{}'", state.filter) };
    let title = format!(
        "Path Tree — {} dirs ({} resolved, {} unresolved), {} items, {} overridden — [{}]{}",
        total_dirs, resolved, unresolved, total_bins, overridden, scope_label, filtered
    );
    wnd.hwnd().SetWindowText(&title)?;
    Ok(())
}

fn set_status_bar(status: &gui::Edit, state: &AppState) -> AnyResult<()> {
    let (total_dirs, resolved, unresolved, total_bins, overridden) = compute_stats(state);
    let scope_label = match state.scope {
        RegistryScope::UserOnly => "User",
        RegistryScope::SystemOnly => "System",
        RegistryScope::ProcessOnly => "Process",
        RegistryScope::ProcessUserSystem => "Process+User+System",
        RegistryScope::UserThenSystem => "User→System",
        RegistryScope::SystemThenUser => "System→User",
    };
    let txt = format!(
        "Scope: {} | Dirs: {} ({} resolved, {} unresolved) | Items: {} | Overridden: {}",
        scope_label, total_dirs, resolved, unresolved, total_bins, overridden
    );
    status.set_text(&txt)?;
    Ok(())
}

fn settings_path() -> Option<PathBuf> {
    env::var_os("APPDATA").map(|p| PathBuf::from(p).join("PathTree").join("settings.txt"))
}

fn load_settings() -> Option<(RegistryScope, String)> {
    let path = settings_path()?;
    let content = fs::read_to_string(path).ok()?;
    let mut scope = RegistryScope::UserOnly;
    let mut filter = String::new();
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("scope=") {
            scope = match rest.trim() {
                "UserOnly" => RegistryScope::UserOnly,
                "SystemOnly" => RegistryScope::SystemOnly,
                "ProcessOnly" => RegistryScope::ProcessOnly,
                "ProcessUserSystem" => RegistryScope::ProcessUserSystem,
                "UserThenSystem" => RegistryScope::UserThenSystem,
                "SystemThenUser" => RegistryScope::SystemThenUser,
                _ => RegistryScope::UserOnly,
            };
        }
        if let Some(rest) = line.strip_prefix("filter=") { filter = rest.to_string(); }
    }
    Some((scope, filter))
}

fn save_settings(scope: RegistryScope, filter: &str) {
    if let Some(path) = settings_path() {
        let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
        let scope_str = match scope {
            RegistryScope::UserOnly => "UserOnly",
            RegistryScope::SystemOnly => "SystemOnly",
            RegistryScope::ProcessOnly => "ProcessOnly",
            RegistryScope::ProcessUserSystem => "ProcessUserSystem",
            RegistryScope::UserThenSystem => "UserThenSystem",
            RegistryScope::SystemThenUser => "SystemThenUser",
        };
        let data = format!("scope={}\nfilter={}\n", scope_str, filter);
        let _ = fs::write(path, data);
    }
}

fn expand_or_collapse_all_roots(tv: &gui::TreeView<String>, expand: bool) {
    unsafe {
        let hwnd = tv.hwnd();
        if let Some(mut hi) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::ROOT, hitem: None }) {
            loop {
                let _ = hwnd.SendMessage(msg::tvm::Expand {
                    action: if expand { co::TVE::EXPAND } else { co::TVE::COLLAPSE },
                    hitem: &hi,
                });
                if let Some(next) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::NEXT, hitem: Some(&hi) }) {
                    hi = next;
                } else {
                    break;
                }
            }
        }
    }
}

// Helper: select and reveal a specific child binary under a given root (by original PATH entry string)
// Returns true if selection succeeded
fn select_child_under_root(
    tv: &gui::TreeView<String>,
    root_clean_label: &str,
    child_name: &str,
) -> bool {
    unsafe {
        let hwnd = tv.hwnd();
        if let Some(mut hi) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::ROOT, hitem: None }) {
            loop {
                let root_item = tv.items().get(&hi);
                if let Ok(txt) = root_item.text() {
                    if strip_root_label(&txt) == root_clean_label {
                        // Expand this root so children are visible
                        let _ = hwnd.SendMessage(msg::tvm::Expand { action: co::TVE::EXPAND, hitem: &hi });
                        // Iterate first-level children to find the binary
                        if let Some(mut ch) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::CHILD, hitem: Some(&hi) }) {
                            loop {
                                let ch_item = tv.items().get(&ch);
                                if let Ok(ctxt) = ch_item.text() {
                                    if strip_child_label(&ctxt) == child_name {
                                        // Select and ensure visible
                                        let _ = hwnd.SendMessage(msg::tvm::SelectItem { action: co::TVGN::CARET, hitem: &ch });
                                        let _ = hwnd.SendMessage(msg::tvm::EnsureVisible { hitem: &ch });
                                        return true;
                                    }
                                }
                                if let Some(next) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::NEXT, hitem: Some(&ch) }) {
                                    ch = next;
                                } else {
                                    break;
                                }
                            }
                        }
                        // Found the root, but not the child
                        return false;
                    }
                }
                if let Some(next) = hwnd.SendMessage(msg::tvm::GetNextItem { relationship: co::TVGN::NEXT, hitem: Some(&hi) }) {
                    hi = next;
                } else {
                    break;
                }
            }
        }
    }
    false
}

fn populate_tree_from_state(tv: &gui::TreeView<String>, state: &AppState) -> AnyResult<()> {
    tv.items().delete_all()?;
    let filt = state.filter.trim().to_ascii_lowercase();
    for (i, _p) in state.paths.iter().enumerate() {
        let base_root = state.orig_paths.get(i).cloned().unwrap_or_default();
    let unresolved = state.paths.get(i).and_then(|o| o.as_ref()).is_none();
        let mut root_has_overrides = false;
        if let Some(bins) = state.dir_bins.get(i) {
            for b in bins {
                let b_str = b.to_string_lossy().to_string();
                if let Some(first_idx) = state.seen.get(&b_str) {
                    if *first_idx != i { root_has_overrides = true; break; }
                }
            }
        }
    // Color prefix semantics:
    // - � red: non-existent/unresolved root dir
    // - � green: existing root dir
    let color_prefix = if unresolved { "🔴 " } else { "🟢 " };
    let mut root_label = format!("{}{}", color_prefix, base_root);
    if root_has_overrides { root_label.push_str(" ★"); }
        let mut bins = state.dir_bins.get(i).cloned().unwrap_or_default();
        bins.sort_by_key(|s| s.to_string_lossy().to_lowercase());
    let mut filtered_bins: Vec<OsString> = if filt.is_empty() {
            bins
        } else {
            // match on file name, case-insensitive
            bins.into_iter()
                .filter(|s| s.to_string_lossy().to_ascii_lowercase().contains(&filt))
                .collect()
        };

        if !filt.is_empty() && filtered_bins.is_empty() {
            continue; // hide directory with no matches
        }

        let root = tv.items().add_root(&root_label, None, base_root.clone())?;
        for b in filtered_bins.drain(..) {
            let b_str = b.to_string_lossy().to_string();
            let is_overridden = state.seen.get(&b_str).map(|first_idx| *first_idx != i).unwrap_or(false);
            // Color prefix semantics for binaries:
            // - 🟡 yellow: overridden (shadowed)
            // - 🟢 green: effective
            let emoji = if is_overridden { "🟡 " } else { "🟢 " };
            // Append inline goto chevron for overridden binaries
            let label = if is_overridden {
                format!("{}{} [overridden] ⤴", emoji, b_str)
            } else {
                format!("{}{}", emoji, b_str)
            };
            root.add_child(&label, None, b_str)?;
        }
    }
    Ok(())
}

fn main() -> AnyResult<()> {
    // Set DPI awareness for proper scaling on high-DPI displays
    winsafe::SetProcessDPIAware()?;

    // initial scope: User only (requested default)
    let scope_state = RegistryScope::UserOnly;
    let (paths, orig_paths, dir_bins, seen, all_dirs_init, bin_dir_map_init) = build_tree_data_with_scope(scope_state);

    // Create main window
    let wnd_opts = gui::WindowMainOpts {
        title: "Path Tree".into(),
        size: gui::dpi(800, 600),
        ..Default::default()
    };
    let wnd = gui::WindowMain::new(wnd_opts);

    // Create scope radio-style buttons on top, TreeView on the left and a multi-line Edit on the right
    let mut rdo_user_opts = gui::ButtonOpts {
        text: "User".into(),
        position: gui::dpi(8, 6),
        width: gui::dpi_x(80),
        height: gui::dpi_y(20),
        control_style: co::BS::AUTORADIOBUTTON,
        ..Default::default()
    };
    rdo_user_opts.window_style = rdo_user_opts.window_style | co::WS::GROUP; // start group
    let rdo_user = gui::Button::new(&wnd, rdo_user_opts);

    let rdo_system = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "System".into(),
        position: gui::dpi(96, 6),
        width: gui::dpi_x(80),
        height: gui::dpi_y(20),
        control_style: co::BS::AUTORADIOBUTTON,
        ..Default::default()
    });
    // Refresh button
    let btn_refresh = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Refresh".into(),
        position: gui::dpi(184, 6),
        width: gui::dpi_x(80),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    // Expand/Collapse buttons
    let btn_expand_all = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Expand all".into(),
        position: gui::dpi(272, 6),
        width: gui::dpi_x(96),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_collapse_all = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Collapse all".into(),
        position: gui::dpi(372, 6),
        width: gui::dpi_x(96),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    // Filter and quick action buttons
    let edt_filter = gui::Edit::new(&wnd, gui::EditOpts {
        text: String::new(),
        position: gui::dpi(472, 6),
        width: gui::dpi_x(200),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_open_folder = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Open".into(),
        position: gui::dpi(676, 6),
        width: gui::dpi_x(40),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_copy_path = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Copy".into(),
        position: gui::dpi(720, 6),
        width: gui::dpi_x(40),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_ps_here = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "PS".into(),
        position: gui::dpi(764, 6),
        width: gui::dpi_x(32),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let tv_opts = gui::TreeViewOpts {
    position: gui::dpi(0, 32),
    size: gui::dpi(400, 548),
        ..Default::default()
    };
    let tv: gui::TreeView<String> = gui::TreeView::new(&wnd, tv_opts);

    let edit_opts = gui::EditOpts {
        text: String::new(),
    position: gui::dpi(400, 32),
    width: gui::dpi_x(400),
    height: gui::dpi_y(548),
        control_style: co::ES::MULTILINE | co::ES::WANTRETURN | co::ES::AUTOVSCROLL,
        ..Default::default()
    };
    let mut edit_opts = edit_opts;
    edit_opts.control_style = edit_opts.control_style | co::ES::READONLY;
    let details: gui::Edit = gui::Edit::new(&wnd, edit_opts);

    // Status bar at bottom (read-only single line)
    let status_opts = gui::EditOpts {
        text: String::new(),
        position: gui::dpi(0, 580),
        width: gui::dpi_x(800),
        height: gui::dpi_y(20),
        control_style: co::ES::READONLY | co::ES::AUTOHSCROLL,
        ..Default::default()
    };
    let status: gui::Edit = gui::Edit::new(&wnd, status_opts);

    // Populate TreeView and wire events once the window/control is created.
    {
    let tv = tv.clone();
    let details = details.clone();
    let status_bar = status.clone();
    let wnd_for_title = wnd.clone();
    let mut initial_state = AppState { scope: scope_state, paths, orig_paths, dir_bins, seen, filter: String::new(), all_dirs: all_dirs_init, bin_dir_map: bin_dir_map_init };
    if let Some((saved_scope, saved_filter)) = load_settings() {
        initial_state.scope = saved_scope;
        initial_state.filter = saved_filter;
    }
    initial_state.rebuild();
    let state = Rc::new(RefCell::new(initial_state));
        // register event handlers before creation
        {
            let details_sel = details.clone();
            let state_sel = state.clone();
            let tv_sel = tv.clone();
            tv.on().tvn_sel_changed(move |_p: &winsafe::NMTREEVIEW| -> winsafe::AnyResult<()> {
                if let Some(item) = tv_sel.items().iter_selected().next() {
                    let selected_text = item.text().unwrap_or_default();
                    let selected_clean = strip_child_label(&selected_text);
                    // If the selected item is a binary we can show expanded + original path + metadata
                    // determine the directory index using the selected item's parent when possible
                    let mut idx_opt: Option<usize> = None;
                    if let Some(parent_item) = item.parent() {
                        let parent_text = parent_item.text().unwrap_or_default();
                        let parent_clean = strip_root_label(&parent_text);
                        // match parent_text against original PATH entries
                        idx_opt = state_sel.borrow().orig_paths.iter().position(|orig| orig == &parent_clean);
                    }
                    // fallback to first-seen index
                    if idx_opt.is_none() {
                        if let Some(i) = state_sel.borrow().seen.get(selected_clean.as_str()) {
                            idx_opt = Some(*i);
                        }
                    }

                    if let Some(idx) = idx_opt {
                        let expanded_dir_pb_opt = state_sel.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned());
                        // Build a multi-line expanded list if multiple subpaths exist
                        let expanded_list: Vec<String> = state_sel
                            .borrow()
                            .all_dirs
                            .get(idx)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .map(|p| p.display().to_string())
                            .collect();
                        let expanded_dir_str = expanded_list.first().cloned().unwrap_or_default();
                        let original_dir = state_sel.borrow().orig_paths.get(idx).cloned().unwrap_or_default();
                        // status: overridden if this occurrence is not the first seen
                        let is_overridden = state_sel.borrow().seen.get(selected_clean.as_str()).map(|first_idx| *first_idx != idx).unwrap_or(false);
                        // try to get file metadata for expanded path + filename (only if expanded exists)
                        // Prefer the directory where this binary was actually found (within this entry)
                        let full_path = state_sel
                            .borrow()
                            .bin_dir_map
                            .get(idx)
                            .and_then(|m| m.get(selected_clean.as_str()).cloned())
                            .or_else(|| expanded_dir_pb_opt.clone())
                            .map(|dir_pb| dir_pb.join(&selected_clean));
                        let mut meta_lines = Vec::new();
                        if let Some(ref fp) = full_path {
                            if let Ok(md) = std::fs::metadata(fp) {
                                meta_lines.push(format!("Size: {} bytes", md.len()));
                                if let Ok(mtime) = md.modified() {
                                    if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                                        // crude formatting: seconds since epoch
                                        meta_lines.push(format!("Modified (unix secs): {}", dur.as_secs()));
                                    }
                                }
                            } else {
                                meta_lines.push("File: missing".to_string());
                            }
                        }
                        // Add diagnostic lines about unresolved/cycles using registry-backed expansion info
                        let scope_now = state_sel.borrow().scope;
                        let info = path_tree::path_utils::expand_env_vars_with_scope(&original_dir, scope_now);
                        if expanded_dir_str.is_empty() || info.expanded.is_empty() || info.expanded.contains('%') {
                            meta_lines.push("⚠ Unresolved after registry lookup (max depth 10)".to_string());
                        }
                        if info.cycle_detected { meta_lines.push("⚠ Cycle detected during expansion".to_string()); }
                        if info.reached_depth_limit { meta_lines.push("⚠ Reached expansion depth limit".to_string()); }
                        // shadowing status and overriding entry details
                        if is_overridden {
                            meta_lines.push("Status: overridden (shadowed)".to_string());
                            if let Some(first_idx) = state_sel.borrow().seen.get(selected_clean.as_str()) {
                                let ov_orig = state_sel.borrow().orig_paths.get(*first_idx).cloned().unwrap_or_default();
                                let ov_dir_pb_opt = state_sel.borrow().paths.get(*first_idx).and_then(|opt| opt.as_ref().cloned());
                                let ov_full = if let Some(ov_pb) = &ov_dir_pb_opt { ov_pb.join(&selected_clean).display().to_string() } else { String::new() };
                                meta_lines.push(format!("Overriding entry: {}", ov_orig));
                                if !ov_full.is_empty() { meta_lines.push(format!("Overriding expanded: {}", ov_full)); }
                            }
                        } else {
                            meta_lines.push("Status: effective".to_string());
                        }

                        let meta = if meta_lines.is_empty() { String::new() } else { meta_lines.join("\r\n") };
                        let full_expanded = full_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| selected_clean.clone());
                        // Show all expanded directories for this entry (if any)
                        let expanded_multi = if expanded_list.is_empty() { String::from("(unresolved)") } else { expanded_list.join("\r\n  ") };
                        let details_text = format!(
                            "Name: {}\r\nExpanded: {}\r\nOriginal PATH entry: {}\r\nAll expanded dirs:\r\n  {}\r\n{}",
                            selected_clean, full_expanded, original_dir, expanded_multi, meta);
                        details_sel.set_text(&details_text)?;
                    } else {
                        // could be a directory (root) item
                        let txt = item.text().unwrap_or_default();
                        // try to show original and expanded forms for the root if available
                        let txt_clean = strip_root_label(&txt);
                        let mut details_text = format!("Path: {}", txt_clean);
                        if let Some(idx) = state_sel.borrow().orig_paths.iter().position(|orig| orig == &txt_clean) {
                            let orig = state_sel.borrow().orig_paths.get(idx).cloned().unwrap_or_default();
                            let expanded_list: Vec<String> = state_sel
                                .borrow()
                                .all_dirs
                                .get(idx)
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|p| p.display().to_string())
                                .collect();
                            let expanded_opt = state_sel.borrow().paths.get(idx).and_then(|opt| opt.as_ref().map(|pb| pb.display().to_string()));
                            let expanded = expanded_opt.clone().unwrap_or_else(|| "(unresolved)".to_string());
                            // diagnostics for root
                            let scope_now = state_sel.borrow().scope;
                            let info = path_tree::path_utils::expand_env_vars_with_scope(&orig, scope_now);
                            let mut lines = vec![format!("Expanded: {}", expanded), format!("Original PATH entry: {}", orig)];
                            if !expanded_list.is_empty() {
                                lines.push("All expanded dirs:".to_string());
                                for e in &expanded_list { lines.push(format!("  {}", e)); }
                            }
                            // existence line
                            if let Some(exp) = expanded_opt {
                                if std::path::Path::new(&exp).exists() {
                                    lines.push("Exists: yes".to_string());
                                } else {
                                    lines.push("Exists: no".to_string());
                                }
                            } else {
                                lines.push("Exists: no".to_string());
                            }
                            if expanded == "(unresolved)" || info.expanded.is_empty() || info.expanded.contains('%') {
                                lines.push("⚠ Unresolved after registry lookup (max depth 10)".to_string());
                            }
                            if info.cycle_detected { lines.push("⚠ Cycle detected during expansion".to_string()); }
                            if info.reached_depth_limit { lines.push("⚠ Reached expansion depth limit".to_string()); }
                            details_text = lines.join("\r\n");
                        }
                        details_sel.set_text(&details_text)?;
                    }
                } else {
                    details_sel.set_text("")?;
                }
                Ok(())
            });

            let tv_dbl = tv.clone();
            let state_for_dbl = state.clone();
            let status_dbl = status_bar.clone();
            tv.on().nm_dbl_clk(move || -> winsafe::AnyResult<i32> {
                if let Some(item) = tv_dbl.items().iter_selected().next() {
                    if let Some(parent) = item.parent() {
                        let dir_label = parent.text().unwrap_or_else(|_| String::new());
                        let parent_clean = strip_root_label(&dir_label);
                        let file_name = item.text().unwrap_or_default();
                        let file_clean = strip_child_label(&file_name);
                        // If this is an overridden item, interpret double-click as "Go to" shadowing
                        let is_overridden = state_for_dbl.borrow().seen.get(file_clean.as_str()).map(|first_idx| {
                            if let Some(cur_idx) = state_for_dbl.borrow().orig_paths.iter().position(|orig| orig == &parent_clean) {
                                *first_idx != cur_idx
                            } else { false }
                        }).unwrap_or(false);

                        if is_overridden {
                            let cur_idx = state_for_dbl.borrow().orig_paths.iter().position(|orig| orig == &parent_clean);
                            let first_idx_opt = state_for_dbl.borrow().seen.get(file_clean.as_str()).copied();
                            if let (Some(_cur_idx), Some(first_idx)) = (cur_idx, first_idx_opt) {
                                let root_label = state_for_dbl.borrow().orig_paths[first_idx].clone();
                                let mut ok = select_child_under_root(&tv_dbl, &root_label, &file_clean);
                                if !ok {
                                    // Adjust filter to reveal the item, then repopulate and retry
                                    state_for_dbl.borrow_mut().filter = file_clean.clone();
                                    // Note: we don't have direct access to the filter edit here; repopulate using updated state
                                    populate_tree_from_state(&tv_dbl, &state_for_dbl.borrow())?;
                                    ok = select_child_under_root(&tv_dbl, &root_label, &file_clean);
                                }
                                if ok {
                                    let _ = status_dbl.set_text(&format!("Jumped to shadowing at: {}", root_label));
                                } else {
                                    let _ = status_dbl.set_text("Could not locate shadowing item in the tree");
                                }
                            }
                        } else {
                            // default behavior: open in Explorer
                            if let Some(idx) = state_for_dbl.borrow().orig_paths.iter().position(|orig| orig == &parent_clean) {
                                // Prefer actual directory for this binary (if known)
                                let dir_pb_opt = state_for_dbl
                                    .borrow()
                                    .bin_dir_map
                                    .get(idx)
                                    .and_then(|m| m.get(file_clean.as_str()).cloned())
                                    .or_else(|| state_for_dbl.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()));
                                if let Some(dir_pb) = dir_pb_opt {
                                    let full = dir_pb.join(&file_clean);
                                    if full.exists() {
                                        let _ = Command::new("explorer").arg(format!("/select,{}", full.display())).spawn();
                                        let _ = status_dbl.set_text(&format!("Opened: {}", full.display()));
                                    } else if dir_pb.exists() {
                                        let _ = Command::new("explorer").arg(&dir_pb).spawn();
                                        let _ = status_dbl.set_text(&format!("Opened folder: {}", dir_pb.display()));
                                    } else {
                                        let _ = status_dbl.set_text(&format!("Path does not exist: {}", dir_pb.display()));
                                    }
                                } else {
                                    let _ = status_dbl.set_text("Path is unresolved; nothing to open");
                                }
                            } else {
                                let _ = status_dbl.set_text("No matching PATH entry for selection");
                            }
                        }
                    } else {
                        let dir_label = item.text().unwrap_or_else(|_| String::new());
                        let root_clean = strip_root_label(&dir_label);
                        if Path::new(&root_clean).exists() {
                            let _ = Command::new("explorer").arg(&root_clean).spawn();
                            let _ = status_dbl.set_text(&format!("Opened folder: {}", root_clean));
                        } else {
                            let _ = status_dbl.set_text(&format!("Path does not exist: {}", root_clean));
                        }
                    }
                }
                Ok(0)
            });

            // Colorize TreeView items via custom draw so the circle glyphs show red/yellow/green
            let tv_cd = tv.clone();
            tv.on().nm_custom_draw(move |p: &mut winsafe::NMTVCUSTOMDRAW| -> AnyResult<co::CDRF> {
                let stage = p.nmcd.dwDrawStage;
                if stage == co::CDDS::PREPAINT {
                    return Ok(co::CDRF::NOTIFYITEMDRAW);
                }
                if stage == co::CDDS::ITEMPREPAINT {
                    // Avoid overriding selection highlight colors
                    if p.nmcd.uItemState.has(co::CDIS::SELECTED) {
                        return Ok(co::CDRF::DODEFAULT);
                    }
                    // Default to green
                    let mut color = winsafe::COLORREF::from_rgb(0, 128, 0);
                    // Identify item from dwItemSpec
                    let hitem = unsafe { winsafe::HTREEITEM::from_ptr(p.nmcd.dwItemSpec as _) };
                    let item = tv_cd.items().get(&hitem);
                    if let Ok(text) = item.text() {
                        // Choose color by emoji prefix
                        if text.starts_with("🔴 ") {
                            color = winsafe::COLORREF::from_rgb(200, 0, 0);
                        } else if text.starts_with("🟡 ") {
                            color = winsafe::COLORREF::from_rgb(200, 160, 0);
                        } else if text.starts_with("🟢 ") {
                            color = winsafe::COLORREF::from_rgb(0, 128, 0);
                        }
                    }
                    p.clrText = color;
                    return Ok(co::CDRF::NEWFONT);
                }
                Ok(co::CDRF::DODEFAULT)
            });
        }

        let tv_init = tv.clone();
        let state_init = state.clone();
        let rdo_user_init = rdo_user.clone();
        let rdo_system_init = rdo_system.clone();
        let wnd_on_create = wnd.clone();
        let edt_filter_init = edt_filter.clone();
        let status_init = status.clone();
        wnd.on().wm_create(move |_| {
            // initial tree population
            populate_tree_from_state(&tv_init, &state_init.borrow())?;
            set_window_title_with_stats(&wnd_on_create, &state_init.borrow())?;
            set_status_bar(&status_init, &state_init.borrow())?;
            // set radios per saved scope
            unsafe {
                match state_init.borrow().scope {
                    RegistryScope::SystemOnly => {
                        let _ = rdo_system_init.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::CHECKED });
                        let _ = rdo_user_init.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::UNCHECKED });
                    }
                    _ => {
                        let _ = rdo_user_init.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::CHECKED });
                        let _ = rdo_system_init.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::UNCHECKED });
                    }
                }
            }
            // apply saved filter text
            let ftxt = state_init.borrow().filter.clone();
            if !ftxt.is_empty() { edt_filter_init.set_text(&ftxt)?; }
            Ok(0)
        });

        // Wire radio buttons to rebuild state and tree
        let tv_user = tv.clone();
        let details_user = details.clone();
    let state_user = state.clone();
    let wnd_user = wnd_for_title.clone();
    let status_user = status_bar.clone();
        let rdo_user_self = rdo_user.clone();
        let rdo_system_peer = rdo_system.clone();
        rdo_user.on().bn_clicked(move || -> AnyResult<()> {
            // enforce exclusive selection visually
            unsafe {
                let _ = rdo_user_self.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::CHECKED });
                let _ = rdo_system_peer.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::UNCHECKED });
            }
            state_user.borrow_mut().scope = RegistryScope::UserOnly;
            state_user.borrow_mut().rebuild();
            populate_tree_from_state(&tv_user, &state_user.borrow())?;
            set_window_title_with_stats(&wnd_user, &state_user.borrow())?;
            set_status_bar(&status_user, &state_user.borrow())?;
            save_settings(state_user.borrow().scope, &state_user.borrow().filter);
            details_user.set_text("")?;
            Ok(())
        });

        let tv_system = tv.clone();
        let details_system = details.clone();
    let state_system = state.clone();
    let wnd_system = wnd_for_title.clone();
    let status_system = status_bar.clone();
        let rdo_system_self = rdo_system.clone();
        let rdo_user_peer = rdo_user.clone();
        rdo_system.on().bn_clicked(move || -> AnyResult<()> {
            // enforce exclusive selection visually
            unsafe {
                let _ = rdo_system_self.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::CHECKED });
                let _ = rdo_user_peer.hwnd().SendMessage(msg::bm::SetCheck { state: co::BST::UNCHECKED });
            }
            state_system.borrow_mut().scope = RegistryScope::SystemOnly;
            state_system.borrow_mut().rebuild();
            populate_tree_from_state(&tv_system, &state_system.borrow())?;
            set_window_title_with_stats(&wnd_system, &state_system.borrow())?;
            set_status_bar(&status_system, &state_system.borrow())?;
            save_settings(state_system.borrow().scope, &state_system.borrow().filter);
            details_system.set_text("")?;
            Ok(())
        });

        // Refresh button handler
        let tv_ref = tv.clone();
        let details_ref = details.clone();
        let state_ref = state.clone();
        let wnd_ref = wnd_for_title.clone();
        let status_ref = status_bar.clone();
        btn_refresh.on().bn_clicked(move || -> AnyResult<()> {
            state_ref.borrow_mut().rebuild();
            populate_tree_from_state(&tv_ref, &state_ref.borrow())?;
            set_window_title_with_stats(&wnd_ref, &state_ref.borrow())?;
            set_status_bar(&status_ref, &state_ref.borrow())?;
            details_ref.set_text("")?;
            Ok(())
        });

        // Filter change handler
        let tv_filt = tv.clone();
        let state_filt = state.clone();
        let wnd_filt = wnd_for_title.clone();
        let edt_filter_clone = edt_filter.clone();
        let status_filt = status_bar.clone();
        edt_filter.on().en_change(move || -> AnyResult<()> {
            let txt = edt_filter_clone.text()?;
            state_filt.borrow_mut().filter = txt;
            populate_tree_from_state(&tv_filt, &state_filt.borrow())?;
            set_window_title_with_stats(&wnd_filt, &state_filt.borrow())?;
            set_status_bar(&status_filt, &state_filt.borrow())?;
            save_settings(state_filt.borrow().scope, &state_filt.borrow().filter);
            Ok(())
        });

        // Expand/Collapse handlers
        let tv_exp = tv.clone();
        btn_expand_all.on().bn_clicked(move || -> AnyResult<()> {
            expand_or_collapse_all_roots(&tv_exp, true);
            Ok(())
        });
        let tv_col = tv.clone();
        btn_collapse_all.on().bn_clicked(move || -> AnyResult<()> {
            expand_or_collapse_all_roots(&tv_col, false);
            Ok(())
        });

    // (Removed top-level Go button; inline ⤴ plus double-click on overridden performs navigation)

        // Open folder button
        let tv_open = tv.clone();
        let state_open = state.clone();
        let status_open = status.clone();
        btn_open_folder.on().bn_clicked(move || -> AnyResult<()> {
            if let Some(item) = tv_open.items().iter_selected().next() {
                if let Some(parent) = item.parent() {
                    let dir_label = parent.text().unwrap_or_default();
                    let parent_clean = strip_root_label(&dir_label);
                    let file_name = item.text().unwrap_or_default();
                    let file_clean = strip_child_label(&file_name);
                    if let Some(idx) = state_open.borrow().orig_paths.iter().position(|orig| orig == &parent_clean) {
                        // Prefer the actual directory where this binary resides for this PATH entry
                        let dir_pb_opt = state_open
                            .borrow()
                            .bin_dir_map
                            .get(idx)
                            .and_then(|m| m.get(file_clean.as_str()).cloned())
                            .or_else(|| state_open.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()));
                        if let Some(dir_pb) = dir_pb_opt {
                            let full = dir_pb.join(&file_clean);
                            if full.exists() {
                                // Use /select to highlight the file in Explorer
                                let _ = Command::new("explorer").arg(format!("/select,{}", full.display())).spawn();
                                let _ = status_open.set_text(&format!("Selected: {}", full.display()));
                            } else if dir_pb.exists() {
                                let _ = Command::new("explorer").arg(&dir_pb).spawn();
                                let _ = status_open.set_text(&format!("Opened folder: {}", dir_pb.display()));
                            } else {
                                let _ = status_open.set_text(&format!("Path does not exist: {}", dir_pb.display()));
                            }
                        } else {
                            let _ = status_open.set_text("Path is unresolved; nothing to open");
                        }
                    }
                } else {
                    let dir_label = item.text().unwrap_or_default();
                    let root_clean = strip_root_label(&dir_label);
                    if Path::new(&root_clean).exists() {
                        let _ = Command::new("explorer").arg(&root_clean).spawn();
                        let _ = status_open.set_text(&format!("Opened folder: {}", root_clean));
                    } else {
                        let _ = status_open.set_text(&format!("Path does not exist: {}", root_clean));
                    }
                }
            }
            Ok(())
        });

        // Copy path button
    let tv_copy = tv.clone();
    let state_copy = state.clone();
    let status_copy = status.clone();
    btn_copy_path.on().bn_clicked(move || -> AnyResult<()> {
            if let Some(item) = tv_copy.items().iter_selected().next() {
                let mut to_copy = item.text().unwrap_or_default();
                // if child, get full expanded path
                if let Some(parent) = item.parent() {
                    let ptxt = parent.text().unwrap_or_default();
                    let parent_clean = strip_root_label(&ptxt);
                    let file_clean = strip_child_label(&to_copy);
                    if let Some(idx) = state_copy.borrow().orig_paths.iter().position(|orig| orig == &parent_clean) {
                        // Prefer bin-specific directory if available
                        let dir_pb_opt = state_copy
                            .borrow()
                            .bin_dir_map
                            .get(idx)
                            .and_then(|m| m.get(file_clean.as_str()).cloned())
                            .or_else(|| state_copy.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()));
                        if let Some(dir_pb) = dir_pb_opt { to_copy = dir_pb.join(&file_clean).display().to_string(); }
                    }
                }
                // Use PowerShell Set-Clipboard (reliable on Windows)
                let _ = Command::new("powershell")
                    .args(["-NoProfile", "-Command", &format!("Set-Clipboard -AsPlainText -Value @'\r\n{}\r\n'@", to_copy)])
                    .spawn();
        let _ = status_copy.set_text(&format!("Copied: {}", to_copy));
            }
            Ok(())
        });

        // PowerShell here button
        let tv_ps = tv.clone();
        let state_ps = state.clone();
        let status_ps = status.clone();
        btn_ps_here.on().bn_clicked(move || -> AnyResult<()> {
            let mut dir_to_open: Option<String> = None;
            if let Some(item) = tv_ps.items().iter_selected().next() {
                if let Some(parent) = item.parent() {
                    let ptxt = parent.text().unwrap_or_default();
                    let parent_clean = strip_root_label(&ptxt);
                    if let Some(idx) = state_ps.borrow().orig_paths.iter().position(|orig| orig == &parent_clean) {
                        // Prefer actual directory where the binary resides when a child is selected
                        if let Some(sel_text) = item.text().ok().map(|s| strip_child_label(&s)) {
                            if let Some(dir_pb) = state_ps.borrow().bin_dir_map.get(idx).and_then(|m| m.get(sel_text.as_str()).cloned()) {
                                if dir_pb.exists() { dir_to_open = Some(dir_pb.display().to_string()); }
                            }
                        }
                        // Fallback to first resolved directory for the entry
                        if dir_to_open.is_none() {
                            if let Some(Some(dir_pb)) = state_ps.borrow().paths.get(idx) {
                                if dir_pb.exists() { dir_to_open = Some(dir_pb.display().to_string()); }
                            }
                        }
                    }
                } else {
                    // root item: try expand to resolved path
                    let rtxt = item.text().unwrap_or_default();
                    let root_clean = strip_root_label(&rtxt);
                    if let Some(idx) = state_ps.borrow().orig_paths.iter().position(|orig| orig == &root_clean) {
                        if let Some(first) = state_ps.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()) {
                            if first.exists() { dir_to_open = Some(first.display().to_string()); }
                        }
                    }
                }
            }
            if let Some(dir) = dir_to_open {
                // Launch PowerShell in that directory
                let quoted = dir.replace("'", "''");
                let _ = Command::new("powershell")
                    .args(["-NoExit", "-NoProfile", "-Command", &format!("Set-Location -LiteralPath '{}'", quoted)])
                    .spawn();
                let _ = status_ps.set_text(&format!("PowerShell: cd {}", dir));
            } else {
                let _ = status_ps.set_text("Cannot open PowerShell here (path missing)");
            }
            Ok(())
        });
    }

    // Run main loop (this will create the window and controls as well)
    wnd.run_main(None).map(|_| ())
}
