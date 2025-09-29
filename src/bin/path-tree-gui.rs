use std::ffi::OsString;
use std::fs;
use std::env;
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::rc::Rc;
use std::cell::RefCell;
use winsafe::prelude::*;
use winsafe::{gui, AnyResult, co};
use windows::Win32::UI::WindowsAndMessaging::{CreatePopupMenu, AppendMenuW, TrackPopupMenuEx, SendMessageW, DestroyMenu, MF_STRING, TPM_RETURNCMD, TPM_RIGHTBUTTON};
use windows::Win32::Foundation::{POINT as WinPoint, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{TVM_HITTEST, TVHITTESTINFO, TVHITTESTINFO_FLAGS, TVHT_ONITEMICON, TVHT_ONITEMLABEL, TVHT_ONITEMSTATEICON};
use std::ffi::c_void;
use windows::core::PCWSTR;
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
    for suffix in [" ⚠", " ★", " ♦"] {
        if let Some(t) = s.strip_suffix(suffix) { s = t; }
    }

    if let Some(t) = s.strip_prefix("🟢 ") {
        s = t;
    } else if let Some(t) = s.strip_prefix("🟡 ") {
        s = t;
    } else if let Some(t) = s.strip_prefix("� ") {
        s = t;
    }

    if let Some(t) = s.strip_prefix("[marked] ") { s = t; }
    s.to_string()
}

fn extract_index_from_data(data: &Rc<RefCell<String>>) -> Option<usize> {
    let guard = data.borrow();
    guard
        .split_once(':')
        .and_then(|(idx, _)| idx.parse::<usize>().ok())
}

fn tree_item_index(item: &gui::TreeViewItem<String>) -> Option<usize> {
    item.data().ok().and_then(|data| extract_index_from_data(&data))
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
    HashMap<String, usize>,               // count of entries having each binary
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

    let mut duplicates = HashMap::new();
    for bins in &dir_bins {
        for b in bins {
            let key = b.to_string_lossy().to_string();
            *duplicates.entry(key).or_insert(0) += 1;
        }
    }

    (expanded_paths, original_paths, dir_bins, seen, all_dirs, bin_dir_map_list, duplicates)
}

/// Identify which PATH entries are redundant (duplicate resolved paths).
/// Returns a vector of indices of redundant entries.
fn find_redundant_entries(
    resolved_paths: &[Option<PathBuf>],
) -> Vec<usize> {
    let mut redundant = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();
    
    for (i, resolved_path) in resolved_paths.iter().enumerate() {
        match resolved_path {
            Some(path) => {
                // If we've seen this resolved path before, mark as redundant
                if !seen_paths.insert(path.clone()) {
                    redundant.push(i);
                }
            }
            None => {
                // Unresolved entries are redundant
                redundant.push(i);
            }
        }
    }
    redundant
}

/// Identify which PATH entries are unresolved (do not resolve to existing directories).
/// Returns a vector of indices of unresolved entries.
fn find_unresolved_entries(
    resolved_paths: &[Option<PathBuf>],
) -> Vec<usize> {
    let mut unresolved = Vec::new();
    
    for (i, resolved_path) in resolved_paths.iter().enumerate() {
        if resolved_path.is_none() {
            unresolved.push(i);
        }
    }
    unresolved
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
    duplicates: HashMap<String, usize>, // count of entries having each binary
    marked_for_deletion: HashSet<usize>, // indices of PATH entries marked for deletion
}

impl AppState {
    fn rebuild(&mut self) {
    let (paths, orig_paths, dir_bins, seen, all_dirs, bin_dir_map, duplicates) = build_tree_data_with_scope(self.scope);
    self.paths = paths;
    self.orig_paths = orig_paths;
    self.dir_bins = dir_bins;
    self.seen = seen;
    self.all_dirs = all_dirs;
    self.bin_dir_map = bin_dir_map;
    self.duplicates = duplicates;
    self.marked_for_deletion.clear();
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
#[allow(dead_code)]
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
        let unresolved = state
            .paths
            .get(i)
            .and_then(|opt| opt.as_ref())
            .is_none();
        let mut has_first = false;
        let mut has_duplicates = false;
        let mut has_overridden = false;
        if let Some(bins) = state.dir_bins.get(i) {
            for b in bins {
                let b_str = b.to_string_lossy().to_string();
                if let Some(first_idx) = state.seen.get(&b_str) {
                    if *first_idx == i { has_first = true; }
                    else { 
                        has_duplicates = true; 
                        has_overridden = true;
                    }
                }
                if let Some(count) = state.duplicates.get(&b_str) {
                    if *count > 1 { has_duplicates = true; }
                }
            }
        }
    // Color prefix semantics:
    // - 🟡 yellow: has overridden binaries
    // - 🔴 red: non-existent/unresolved root dir
    // - 🟢 green: existing root dir
    let color_prefix = match (has_overridden, unresolved) {
        (true, _) => "🟡 ",
        (false, true) => "🔴 ",
        (false, false) => "🟢 ",
    };
    let marker = if state.marked_for_deletion.contains(&i) { "[marked] " } else { "" };
    let mut root_label = format!("{}{}{}", color_prefix, marker, base_root);
    if has_duplicates {
        if has_first { root_label.push_str(" ★"); }
        else { root_label.push_str(" ♦"); }
    }
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

        let root = tv.items().add_root(&root_label, None, format!("{}:{}", i, base_root))?;
        for b in filtered_bins.drain(..) {
            let b_str = b.to_string_lossy().to_string();
            let _is_overridden = state.seen.get(&b_str).map(|first_idx| *first_idx != i).unwrap_or(false);
            // Color prefix semantics for binaries:
            // - 🟡 yellow: overridden (shadowed)
            // - 🟢 green: effective
            let emoji = if _is_overridden { "🟡 " } else { "🟢 " };
            // Append inline goto chevron for overridden binaries
            let label = if _is_overridden {
                format!("{}{} [overridden] ⤴", emoji, b_str)
            } else {
                format!("{}{}", emoji, b_str)
            };
            root.add_child(&label, None, b_str)?;
        }
    }
    Ok(())
}

fn prioritise_entry(state: &Rc<RefCell<AppState>>, selected_idx: usize) {
    let mut state_mut = state.borrow_mut();
    
    // Get the binaries provided by the selected entry
    let selected_binaries = match state_mut.bin_dir_map.get(selected_idx) {
        Some(map) => map.keys().cloned().collect::<HashSet<_>>(),
        None => return, // No binaries to prioritise
    };
    
    if selected_binaries.is_empty() {
        return;
    }
    
    // Find the first entry that provides any of the same binaries (anywhere in PATH)
    let mut target_idx = None;
    for (idx, bin_map) in state_mut.bin_dir_map.iter().enumerate() {
        if idx == selected_idx {
            continue; // Skip the selected entry itself
        }
        for binary in &selected_binaries {
            if bin_map.contains_key(binary) {
                target_idx = Some(idx);
                break;
            }
        }
        if target_idx.is_some() {
            break;
        }
    }
    
    if let Some(target_idx) = target_idx {
        // Calculate the insertion index, accounting for the removal
        let insert_idx = if selected_idx < target_idx {
            target_idx - 1
        } else {
            target_idx
        };
        
        // Move the selected entry to just before the target_idx
        // We need to reorder orig_paths, paths, and bin_dir_map
        
        // Move orig_paths
        let selected_orig = state_mut.orig_paths.remove(selected_idx);
        state_mut.orig_paths.insert(insert_idx, selected_orig);
        
        // Move paths
        let selected_path = state_mut.paths.remove(selected_idx);
        state_mut.paths.insert(insert_idx, selected_path);
        
        // Move bin_dir_map
        let selected_bin_map = state_mut.bin_dir_map.remove(selected_idx);
        state_mut.bin_dir_map.insert(insert_idx, selected_bin_map);
        
        // Update the resolved paths and binary mappings
        update_resolved_paths_and_mappings(&mut state_mut);
        
        // Persist the reordered PATH to the registry
        let new_path = state_mut.orig_paths.join(";");
        if path_tree::path_utils::set_path_string_for_scope(state_mut.scope, &new_path) {
            // Successfully updated PATH
        } else {
            // Failed to update PATH - could show error message
        }
    }
}

fn update_resolved_paths_and_mappings(state: &mut AppState) {
    // Rebuild the paths, bin_dir_map, and other mappings based on current orig_paths
    // This is similar to build_tree_data_with_scope but operates on existing state
    
    let scope = state.scope; // Assume we store the scope in AppState
    
    let mut expanded_paths: Vec<Option<PathBuf>> = Vec::new();
    let mut dir_bins: Vec<Vec<OsString>> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut all_dirs: Vec<Vec<PathBuf>> = Vec::new();
    let mut bin_dir_map_list: Vec<HashMap<String, PathBuf>> = Vec::new();
    
    for (idx, orig) in state.orig_paths.iter().enumerate() {
        let info = expand_env_vars_with_scope(orig, scope);
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
        dir_bins.push(bins_agg);
        all_dirs.push(valid_dirs);
        bin_dir_map_list.push(bin_dir_map);
    }

    let mut duplicates = HashMap::new();
    for bins in &dir_bins {
        for b in bins {
            let key = b.to_string_lossy().to_string();
            *duplicates.entry(key).or_insert(0) += 1;
        }
    }
    
    // Update the state
    state.paths = expanded_paths;
    state.bin_dir_map = bin_dir_map_list;
    state.seen = seen;
    state.all_dirs = all_dirs;
    state.duplicates = duplicates;
}

#[link(name = "user32")]
extern "system" {
    fn EnableWindow(hWnd: isize, bEnable: i32) -> i32;
}

fn main() -> AnyResult<()> {
    // Set DPI awareness for proper scaling on high-DPI displays
    winsafe::SetProcessDPIAware()?;

    // initial scope: User only (requested default)
    let scope_state = RegistryScope::UserOnly;
    let (paths, orig_paths, dir_bins, seen, all_dirs_init, bin_dir_map_init, duplicates_init) = build_tree_data_with_scope(scope_state);

    // Create main window
    let wnd_opts = gui::WindowMainOpts {
        title: "Path Tree".into(),
        size: gui::dpi(1300, 600),
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
        position: gui::dpi(376, 6),
        width: gui::dpi_x(96),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    // Filter and quick action buttons
    let btn_delete_marked = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Delete Marked".into(),
        position: gui::dpi(480, 6),
        width: gui::dpi_x(100),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let edt_filter = gui::Edit::new(&wnd, gui::EditOpts {
        text: String::new(),
        position: gui::dpi(588, 6),
        width: gui::dpi_x(200),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_open_folder = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Open".into(),
        position: gui::dpi(796, 6),
        width: gui::dpi_x(40),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_copy_path = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Copy".into(),
        position: gui::dpi(844, 6),
        width: gui::dpi_x(40),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_ps_here = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "PS".into(),
        position: gui::dpi(892, 6),
        width: gui::dpi_x(32),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_remove_dup = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Rm Dup".into(),
        position: gui::dpi(932, 6),
        width: gui::dpi_x(50),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_export_path = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Export".into(),
        position: gui::dpi(990, 6),
        width: gui::dpi_x(50),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_import_path = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Import".into(),
        position: gui::dpi(1048, 6),
        width: gui::dpi_x(50),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_prioritise = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Prioritise".into(),
        position: gui::dpi(1106, 6),
        width: gui::dpi_x(60),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let btn_remove_unresolved = gui::Button::new(&wnd, gui::ButtonOpts {
        text: "Rm Unresolved".into(),
        position: gui::dpi(1174, 6),
        width: gui::dpi_x(100),
        height: gui::dpi_y(20),
        ..Default::default()
    });
    let tv_opts = gui::TreeViewOpts {
    position: gui::dpi(0, 32),
    size: gui::dpi(500, 548),
        ..Default::default()
    };
    let tv: gui::TreeView<String> = gui::TreeView::new(&wnd, tv_opts);

    let edit_opts = gui::EditOpts {
        text: String::new(),
    position: gui::dpi(500, 32),
    width: gui::dpi_x(800),
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
        width: gui::dpi_x(1300),
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
    let mut initial_state = AppState { scope: scope_state, paths, orig_paths, dir_bins, seen, filter: String::new(), all_dirs: all_dirs_init, bin_dir_map: bin_dir_map_init, duplicates: duplicates_init, marked_for_deletion: HashSet::new() };
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
                        if let Some(idx) = tree_item_index(&parent_item) {
                            idx_opt = Some(idx);
                        }
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
                        let _is_overridden = state_sel.borrow().seen.get(selected_clean.as_str()).map(|first_idx| *first_idx != idx).unwrap_or(false);
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
                        if false {
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
                        if let Some(idx) = tree_item_index(&item) {
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
                        let file_name = item.text().unwrap_or_default();
                        let file_clean = strip_child_label(&file_name);
                        // If this is an overridden item, interpret double-click as "Go to" shadowing
                        let _is_overridden = tree_item_index(&parent)
                            .and_then(|cur_idx| {
                                state_for_dbl
                                    .borrow()
                                    .seen
                                    .get(file_clean.as_str())
                                    .map(|first_idx| *first_idx != cur_idx)
                            })
                            .unwrap_or(false);

                        // Removed: else open in Explorer on double-click
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

            let tv_rclick = tv.clone();
            let state_rclick = state.clone();
            let status_rclick = status_bar.clone();
            let wnd_rclick = wnd.clone();
            let btn_delete_marked_rclick = btn_delete_marked.clone();
            tv.on().nm_r_click(move || -> winsafe::AnyResult<i32> {
                let hwnd_tv = tv_rclick.hwnd();
                let cursor_pos = winsafe::GetCursorPos()?;
                let client_pos = hwnd_tv.ScreenToClient(cursor_pos)?;

                let mut hit = TVHITTESTINFO {
                    pt: WinPoint { x: client_pos.x, y: client_pos.y },
                    flags: TVHITTESTINFO_FLAGS(0),
                    hItem: Default::default(),
                };
                unsafe {
                    SendMessageW(
                        windows::Win32::Foundation::HWND(hwnd_tv.ptr()),
                        TVM_HITTEST,
                        WPARAM(0),
                        LPARAM(&mut hit as *mut _ as isize),
                    );
                }

                let hit_item = hit.hItem;
                let on_item = (hit.flags.0 & (TVHT_ONITEMICON.0 | TVHT_ONITEMLABEL.0 | TVHT_ONITEMSTATEICON.0)) != 0;

                if hit_item.0 != 0 && on_item {
                    let hi = unsafe { winsafe::HTREEITEM::from_ptr(hit_item.0 as *mut c_void) };
                    unsafe {
                        let _ = hwnd_tv.SendMessage(msg::tvm::SelectItem { action: co::TVGN::CARET, hitem: &hi });
                    }
                } else {
                    return Ok(0);
                }

                if let Some(item) = tv_rclick.items().iter_selected().next() {
                    if let Some(parent) = item.parent() {
                        // This is a binary under a PATH entry - just open in Explorer
                        let file_name = item.text().unwrap_or_default();
                        let file_clean = strip_child_label(&file_name);
                        if let Some(idx) = tree_item_index(&parent) {
                            let dir_pb_opt = state_rclick
                                .borrow()
                                .bin_dir_map
                                .get(idx)
                                .and_then(|m| m.get(file_clean.as_str()).cloned())
                                .or_else(|| state_rclick.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()));
                            if let Some(dir_pb) = dir_pb_opt {
                                let full = dir_pb.join(&file_clean);
                                if full.exists() {
                                    let _ = Command::new("explorer").arg(format!("/select,{}", full.display())).spawn();
                                    let _ = status_rclick.set_text(&format!("Opened: {}", full.display()));
                                } else if dir_pb.exists() {
                                    let _ = Command::new("explorer").arg(&dir_pb).spawn();
                                    let _ = status_rclick.set_text(&format!("Opened folder: {}", dir_pb.display()));
                                } else {
                                    let _ = status_rclick.set_text(&format!("Path does not exist: {}", dir_pb.display()));
                                }
                            } else {
                                let _ = status_rclick.set_text("Path is unresolved; nothing to open");
                            }
                        } else {
                            let _ = status_rclick.set_text("No matching PATH entry for selection");
                        }
                    } else {
                        // This is a root PATH entry - show context menu
                        let dir_label = item.text().unwrap_or_else(|_| String::new());
                        let root_clean = strip_root_label(&dir_label);
                        
                        // Create context menu using Windows API
                        let hmenu = unsafe { CreatePopupMenu()? };
                        
                        // Add menu items
                        let explorer_text = "Open in Explorer\tEnter";
                        let explorer_pcwstr = PCWSTR::from_raw(explorer_text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr());
                        unsafe { AppendMenuW(hmenu, MF_STRING, 1, explorer_pcwstr)?; }
                        
                        let prioritise_text = "Prioritise binaries";
                        let prioritise_pcwstr = PCWSTR::from_raw(prioritise_text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr());
                        unsafe { AppendMenuW(hmenu, MF_STRING, 2, prioritise_pcwstr)?; }
                        
                        // Check if already marked
                        let selected_idx = tree_item_index(&item);
                        let is_marked = selected_idx.map(|idx| state_rclick.borrow().marked_for_deletion.contains(&idx)).unwrap_or(false);
                        let mark_text = if is_marked { "Unmark for deletion" } else { "Mark for deletion" };
                        let mark_pcwstr = PCWSTR::from_raw(mark_text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>().as_ptr());
                        unsafe { AppendMenuW(hmenu, MF_STRING, 3, mark_pcwstr)?; }
                        
                        // Get cursor position
                        // Show the context menu
                        let cmd = unsafe {
                            TrackPopupMenuEx(
                                hmenu,
                                (TPM_RETURNCMD | TPM_RIGHTBUTTON).0 as u32,
                                cursor_pos.x,
                                cursor_pos.y,
                                windows::Win32::Foundation::HWND(wnd_rclick.hwnd().ptr()),
                                None,
                            ).0 as u32
                        };
                        
                        match cmd {
                            1 => {
                                // Open in Explorer
                                if Path::new(&root_clean).exists() {
                                    let _ = Command::new("explorer").arg(&root_clean).spawn();
                                    let _ = status_rclick.set_text(&format!("Opened folder: {}", root_clean));
                                } else {
                                    let _ = status_rclick.set_text(&format!("Path does not exist: {}", root_clean));
                                }
                            }
                            2 => {
                                // Prioritise binaries
                                if let Some(selected_idx) = selected_idx {
                                    prioritise_entry(&state_rclick, selected_idx);
                                    // Refresh the tree
                                    populate_tree_from_state(&tv_rclick, &*state_rclick.borrow())?;
                                    set_window_title_with_stats(&wnd_rclick, &*state_rclick.borrow())?;
                                    set_status_bar(&status_rclick, &*state_rclick.borrow())?;
                                    let _ = status_rclick.set_text(&format!("Prioritised: {}", root_clean));
                                } else {
                                    let _ = status_rclick.set_text("Selected entry not found in PATH");
                                }
                            }
                            3 => {
                                // Mark/Unmark for deletion
                                if let Some(selected_idx) = selected_idx {
                                    let mut state_mut = state_rclick.borrow_mut();
                                    if state_mut.marked_for_deletion.contains(&selected_idx) {
                                        state_mut.marked_for_deletion.remove(&selected_idx);
                                        let _ = status_rclick.set_text(&format!("Unmarked: {}", root_clean));
                                    } else {
                                        state_mut.marked_for_deletion.insert(selected_idx);
                                        let _ = status_rclick.set_text(&format!("Marked for deletion: {}", root_clean));
                                    }
                                    // Refresh the tree
                                    drop(state_mut);
                                    unsafe { EnableWindow(btn_delete_marked_rclick.hwnd().ptr() as _, if !state_rclick.borrow().marked_for_deletion.is_empty() {1} else {0}); }
                                    populate_tree_from_state(&tv_rclick, &*state_rclick.borrow())?;
                                    set_window_title_with_stats(&wnd_rclick, &*state_rclick.borrow())?;
                                    set_status_bar(&status_rclick, &*state_rclick.borrow())?;
                                } else {
                                    let _ = status_rclick.set_text("Selected entry not found in PATH");
                                }
                            }
                            _ => {} // Menu cancelled
                        }
                        unsafe { let _ = DestroyMenu(hmenu); }
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
                        // Override for marked items
                        if text.contains(" [marked]") {
                            color = winsafe::COLORREF::from_rgb(128, 0, 128); // Purple
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
        let btn_delete_marked_init = btn_delete_marked.clone();
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
            // disable delete button initially
            unsafe { EnableWindow(btn_delete_marked_init.hwnd().ptr() as _, 0); }
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
                    let idx = tree_item_index(&parent);
                    let file_name = item.text().unwrap_or_default();
                    let file_clean = strip_child_label(&file_name);
                    if let Some(idx) = idx {
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
                    let file_clean = strip_child_label(&to_copy);
                    if let Some(idx) = tree_item_index(&parent) {
                        // Prefer bin-specific directory if available
                        let dir_pb_opt = state_copy
                            .borrow()
                            .bin_dir_map
                            .get(idx)
                            .and_then(|m| m.get(file_clean.as_str()).cloned())
                            .or_else(|| state_copy.borrow().paths.get(idx).and_then(|opt| opt.as_ref().cloned()));
                        if let Some(dir_pb) = dir_pb_opt {
                            to_copy = dir_pb.join(&file_clean).display().to_string();
                        }
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
                    if let Some(idx) = tree_item_index(&parent) {
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
                } else if let Some(idx) = tree_item_index(&item) {
                    // root item: try expand to resolved path
                    if let Some(Some(dir_pb)) = state_ps.borrow().paths.get(idx) {
                        if dir_pb.exists() { dir_to_open = Some(dir_pb.display().to_string()); }
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

        // Remove duplicates button
        let state_rm = state.clone();
        let tv_rm = tv.clone();
        let status_rm = status.clone();
        let wnd_rm = wnd.clone();
        btn_remove_dup.on().bn_clicked(move || -> AnyResult<()> {
            let redundant = find_redundant_entries(&state_rm.borrow().paths);
            if redundant.is_empty() {
                let _ = status_rm.set_text("No redundant entries found");
                return Ok(());
            }

            // Show confirmation dialog using Windows API
            let scope_name = match state_rm.borrow().scope {
                RegistryScope::UserOnly => "User",
                RegistryScope::SystemOnly => "System", 
                RegistryScope::ProcessOnly => "Process",
                _ => "Unknown",
            };
            
            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE, MB_ICONWARNING, MB_YESNO};
            
            let title = "Confirm PATH Modification";
            let message = format!(
                "This will remove {} duplicate PATH entries from the {} scope.\n\
                Duplicate entries are those that resolve to the same directory as an earlier entry.\n\n\
                WARNING: This modifies your system's PATH environment variable.\n\
                It is recommended to backup your PATH before proceeding.\n\n\
                Do you want to continue?",
                redundant.len(), scope_name
            );
            
            // Convert strings to UTF-16
            let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
            let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
            
            let result = unsafe {
                MessageBoxW(
                    windows::Win32::Foundation::HWND(wnd_rm.hwnd().ptr() as _),
                    windows::core::PCWSTR(message_wide.as_ptr()),
                    windows::core::PCWSTR(title_wide.as_ptr()),
                    MESSAGEBOX_STYLE(MB_YESNO.0 | MB_ICONWARNING.0),
                )
            };
            
            if result.0 != 6 { // IDYES = 6
                let _ = status_rm.set_text("Operation cancelled");
                return Ok(());
            }

            // Build new PATH by removing redundant entries
            let mut new_entries = Vec::new();
            for (i, orig) in state_rm.borrow().orig_paths.iter().enumerate() {
                if !redundant.contains(&i) {
                    new_entries.push(orig.clone());
                }
            }
            let new_path = new_entries.join(";");

            // Set the new PATH
            if path_tree::path_utils::set_path_string_for_scope(state_rm.borrow().scope, &new_path) {
                let _ = status_rm.set_text(&format!("Removed {} redundant entries", redundant.len()));
                // Refresh the tree
                state_rm.borrow_mut().rebuild();
                populate_tree_from_state(&tv_rm, &*state_rm.borrow())?;
                set_window_title_with_stats(&wnd_rm, &*state_rm.borrow())?;
                set_status_bar(&status_rm, &*state_rm.borrow())?;
            } else {
                let _ = status_rm.set_text("Failed to update PATH");
            }
            Ok(())
        });

        // Prioritise button
        let state_pri = state.clone();
        let tv_pri = tv.clone();
        let status_pri = status.clone();
        let wnd_pri = wnd.clone();
        btn_prioritise.on().bn_clicked(move || -> AnyResult<()> {
            if let Some(item) = tv_pri.items().iter_selected().next() {
                if let Some(parent) = item.parent() {
                    // This is a binary under a PATH entry
                    let selected_idx = tree_item_index(&parent);
                    if let Some(selected_idx) = selected_idx {
                        prioritise_entry(&state_pri, selected_idx);
                        // Refresh the tree
                        populate_tree_from_state(&tv_pri, &*state_pri.borrow())?;
                        set_window_title_with_stats(&wnd_pri, &*state_pri.borrow())?;
                        set_status_bar(&status_pri, &*state_pri.borrow())?;
                        let _ = status_pri.set_text(&format!("Prioritised: {}", parent.text().unwrap_or_default()));
                    } else {
                        let _ = status_pri.set_text("Selected entry not found in PATH");
                    }
                } else {
                    // This is a root PATH entry
                    let selected_idx = tree_item_index(&item);
                    if let Some(selected_idx) = selected_idx {
                        prioritise_entry(&state_pri, selected_idx);
                        // Refresh the tree
                        populate_tree_from_state(&tv_pri, &*state_pri.borrow())?;
                        set_window_title_with_stats(&wnd_pri, &*state_pri.borrow())?;
                        set_status_bar(&status_pri, &*state_pri.borrow())?;
                        let _ = status_pri.set_text(&format!("Prioritised: {}", item.text().unwrap_or_default()));
                    } else {
                        let _ = status_pri.set_text("Selected entry not found in PATH");
                    }
                }
            } else {
                let _ = status_pri.set_text("No item selected for prioritisation");
            }
            Ok(())
        });

        // Remove Unresolved button
        let state_unres = state.clone();
        let tv_unres = tv.clone();
        let status_unres = status.clone();
        let wnd_unres = wnd.clone();
        btn_remove_unresolved.on().bn_clicked(move || -> AnyResult<()> {
            let unresolved = find_unresolved_entries(&state_unres.borrow().paths);
            if unresolved.is_empty() {
                let _ = status_unres.set_text("No unresolved entries found");
                return Ok(());
            }

            // Show confirmation dialog using Windows API
            let scope_name = match state_unres.borrow().scope {
                RegistryScope::UserOnly => "User",
                RegistryScope::SystemOnly => "System", 
                RegistryScope::ProcessOnly => "Process",
                _ => "Unknown",
            };
            
            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE, MB_ICONWARNING, MB_YESNO};
            
            let title = "Confirm PATH Modification";
            let message = format!(
                "This will remove {} unresolved PATH entries from the {} scope.\n\
                Unresolved entries are those that do not resolve to existing directories.\n\n\
                WARNING: This modifies your system's PATH environment variable.\n\
                It is recommended to backup your PATH before proceeding.\n\n\
                Do you want to continue?",
                unresolved.len(), scope_name
            );
            
            // Convert strings to UTF-16
            let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
            let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
            
            let result = unsafe {
                MessageBoxW(
                    windows::Win32::Foundation::HWND(wnd_unres.hwnd().ptr() as _),
                    windows::core::PCWSTR(message_wide.as_ptr()),
                    windows::core::PCWSTR(title_wide.as_ptr()),
                    MESSAGEBOX_STYLE(MB_YESNO.0 | MB_ICONWARNING.0),
                )
            };
            
            if result.0 != 6 { // IDYES = 6
                let _ = status_unres.set_text("Operation cancelled");
                return Ok(());
            }

            // Build new PATH by removing unresolved entries
            let mut new_entries = Vec::new();
            for (i, orig) in state_unres.borrow().orig_paths.iter().enumerate() {
                if !unresolved.contains(&i) {
                    new_entries.push(orig.clone());
                }
            }
            let new_path = new_entries.join(";");

            // Set the new PATH
            if path_tree::path_utils::set_path_string_for_scope(state_unres.borrow().scope, &new_path) {
                let _ = status_unres.set_text(&format!("Removed {} unresolved entries", unresolved.len()));
                // Refresh the tree
                state_unres.borrow_mut().rebuild();
                populate_tree_from_state(&tv_unres, &*state_unres.borrow())?;
                set_window_title_with_stats(&wnd_unres, &*state_unres.borrow())?;
                set_status_bar(&status_unres, &*state_unres.borrow())?;
            } else {
                let _ = status_unres.set_text("Failed to update PATH");
            }
            Ok(())
        });

        // Delete Marked button
        let state_del = state.clone();
        let tv_del = tv.clone();
        let status_del = status.clone();
        let wnd_del = wnd.clone();
        let btn_del_self = btn_delete_marked.clone();
        btn_delete_marked.on().bn_clicked(move || -> AnyResult<()> {
            let marked = state_del.borrow().marked_for_deletion.clone();
            if marked.is_empty() {
                let _ = status_del.set_text("No items marked for deletion");
                return Ok(());
            }

            // Show confirmation dialog
            let scope_name = match state_del.borrow().scope {
                RegistryScope::UserOnly => "User",
                RegistryScope::SystemOnly => "System",
                RegistryScope::ProcessOnly => "Process",
                _ => "Unknown",
            };

            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE, MB_ICONWARNING, MB_YESNO};

            let title = "Confirm PATH Modification";
            let message = format!(
                "This will remove {} marked PATH entries from the {} scope.\n\
                Marked entries will be permanently deleted from your PATH.\n\n\
                WARNING: This modifies your system's PATH environment variable.\n\
                It is recommended to backup your PATH before proceeding.\n\n\
                Do you want to continue?",
                marked.len(), scope_name
            );

            // Convert strings to UTF-16
            let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
            let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();

            let result = unsafe {
                MessageBoxW(
                    windows::Win32::Foundation::HWND(wnd_del.hwnd().ptr() as _),
                    windows::core::PCWSTR(message_wide.as_ptr()),
                    windows::core::PCWSTR(title_wide.as_ptr()),
                    MESSAGEBOX_STYLE(MB_YESNO.0 | MB_ICONWARNING.0),
                )
            };

            if result.0 != 6 { // IDYES = 6
                let _ = status_del.set_text("Operation cancelled");
                return Ok(());
            }

            // Build new PATH by removing marked entries
            let mut new_entries = Vec::new();
            for (i, orig) in state_del.borrow().orig_paths.iter().enumerate() {
                if !marked.contains(&i) {
                    new_entries.push(orig.clone());
                }
            }
            let new_path = new_entries.join(";");

            // Set the new PATH
            if path_tree::path_utils::set_path_string_for_scope(state_del.borrow().scope, &new_path) {
                let _ = status_del.set_text(&format!("Deleted {} marked entries", marked.len()));
                // Clear marked and refresh
                state_del.borrow_mut().marked_for_deletion.clear();
                state_del.borrow_mut().rebuild();
                populate_tree_from_state(&tv_del, &*state_del.borrow())?;
                set_window_title_with_stats(&wnd_del, &*state_del.borrow())?;
                set_status_bar(&status_del, &*state_del.borrow())?;
                unsafe { EnableWindow(btn_del_self.hwnd().ptr() as _, 0); }
            } else {
                let _ = status_del.set_text("Failed to update PATH");
            }
            Ok(())
        });

        // Export PATH button
        let state_exp = state.clone();
        let status_exp = status.clone();
        btn_export_path.on().bn_clicked(move || -> AnyResult<()> {
            let scope_name = match state_exp.borrow().scope {
                RegistryScope::UserOnly => "User",
                RegistryScope::SystemOnly => "System", 
                RegistryScope::ProcessOnly => "Process",
                _ => "Unknown",
            };

            // Get current PATH
            let current_path = match path_tree::path_utils::get_path_string_for_scope(state_exp.borrow().scope) {
                Some(path) => path,
                None => {
                    // Show error dialog
                    let message = "Failed to retrieve the current PATH for export.";
                    let title = "Export Failed";
                    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
                    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
                    
                    let _ = unsafe {
                        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                            windows::Win32::Foundation::HWND(std::ptr::null_mut()),
                            windows::core::PCWSTR(message_wide.as_ptr()),
                            windows::core::PCWSTR(title_wide.as_ptr()),
                            windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(
                                windows::Win32::UI::WindowsAndMessaging::MB_OK.0 | 
                                windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR.0
                            ),
                        )
                    };
                    
                    let _ = status_exp.set_text("Failed to get current PATH");
                    return Ok(());
                }
            };

            // Create default filename with timestamp
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let filename = format!("PATH_{}_{}.txt", scope_name, timestamp);
            
            // Get user's documents folder
            let documents_path = match std::env::var("USERPROFILE") {
                Ok(profile) => std::path::PathBuf::from(profile).join("Documents").join(&filename),
                Err(_) => std::path::PathBuf::from(&filename),
            };

            // Write PATH to file
            match std::fs::write(&documents_path, &current_path) {
                Ok(_) => {
                    // Show success dialog with option to open in Explorer
                    let message = format!(
                        "PATH successfully exported!\n\n\
                        Saved to: {}\n\n\
                        Do you want to open the file location in Explorer?",
                        documents_path.display()
                    );
                    
                    let title = "Export Successful";
                    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
                    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
                    
                    let result = unsafe {
                        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                            windows::Win32::Foundation::HWND(std::ptr::null_mut()), // Use desktop as parent for better visibility
                            windows::core::PCWSTR(message_wide.as_ptr()),
                            windows::core::PCWSTR(title_wide.as_ptr()),
                            windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(
                                windows::Win32::UI::WindowsAndMessaging::MB_YESNO.0 | 
                                windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION.0
                            ),
                        )
                    };
                    
                    if result.0 == 6 { // IDYES
                        // Open in Explorer
                        let _ = std::process::Command::new("explorer")
                            .args(["/select,", &documents_path.to_string_lossy()])
                            .spawn();
                    }
                    
                    let _ = status_exp.set_text(&format!("PATH exported to {}", documents_path.display()));
                }
                Err(e) => {
                    // Show error dialog
                    let message = format!("Failed to export PATH:\n\n{}", e);
                    let title = "Export Failed";
                    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
                    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
                    
                    let _ = unsafe {
                        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                            windows::Win32::Foundation::HWND(std::ptr::null_mut()),
                            windows::core::PCWSTR(message_wide.as_ptr()),
                            windows::core::PCWSTR(title_wide.as_ptr()),
                            windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(
                                windows::Win32::UI::WindowsAndMessaging::MB_OK.0 | 
                                windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR.0
                            ),
                        )
                    };
                    
                    let _ = status_exp.set_text(&format!("Export failed: {}", e));
                }
            }
            Ok(())
        });

        // Import PATH button
        let state_imp = state.clone();
        let tv_imp = tv.clone();
        let status_imp = status.clone();
        let wnd_imp = wnd.clone();
        btn_import_path.on().bn_clicked(move || -> AnyResult<()> {
            let scope_name = match state_imp.borrow().scope {
                RegistryScope::UserOnly => "User",
                RegistryScope::SystemOnly => "System", 
                RegistryScope::ProcessOnly => "Process",
                _ => "Unknown",
            };

            // For simplicity, look for the most recent PATH backup file
            let documents_path = match std::env::var("USERPROFILE") {
                Ok(profile) => std::path::PathBuf::from(profile).join("Documents"),
                Err(_) => std::path::PathBuf::from("."),
            };

            let mut latest_file: Option<std::path::PathBuf> = None;
            let mut latest_time = std::time::SystemTime::UNIX_EPOCH;

            if let Ok(entries) = std::fs::read_dir(&documents_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                        if filename.starts_with(&format!("PATH_{}_", scope_name)) && filename.ends_with(".txt") {
                            if let Ok(metadata) = entry.metadata() {
                                if let Ok(modified) = metadata.modified() {
                                    if modified > latest_time {
                                        latest_time = modified;
                                        latest_file = Some(path);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let file_path = match latest_file {
                Some(path) => path,
                None => {
                    let _ = status_imp.set_text(&format!("No {} PATH backup files found in Documents folder", scope_name));
                    return Ok(());
                }
            };

            // Read PATH from file
            match std::fs::read_to_string(&file_path) {
                Ok(content) => {
                    // Show confirmation dialog
                    let message = format!(
                        "This will replace the current {} PATH with the content from:\n{}\n\n\
                        WARNING: This will overwrite your current PATH settings.\n\
                        Make sure you have a backup!\n\n\
                        Do you want to continue?",
                        scope_name, file_path.display()
                    );
                    
                    let title = "Confirm PATH Import";
                    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
                    let message_wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
                    
                    let result = unsafe {
                        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
                            windows::Win32::Foundation::HWND(wnd_imp.hwnd().ptr() as _),
                            windows::core::PCWSTR(message_wide.as_ptr()),
                            windows::core::PCWSTR(title_wide.as_ptr()),
                            windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE(
                                windows::Win32::UI::WindowsAndMessaging::MB_YESNO.0 | 
                                windows::Win32::UI::WindowsAndMessaging::MB_ICONWARNING.0
                            ),
                        )
                    };
                    
                    if result.0 == 6 { // IDYES
                        // Apply the PATH
                        if path_tree::path_utils::set_path_string_for_scope(state_imp.borrow().scope, &content.trim()) {
                            let _ = status_imp.set_text(&format!("PATH imported from {}", file_path.display()));
                            // Refresh the tree
                            state_imp.borrow_mut().rebuild();
                            populate_tree_from_state(&tv_imp, &*state_imp.borrow())?;
                            set_window_title_with_stats(&wnd_imp, &*state_imp.borrow())?;
                            set_status_bar(&status_imp, &*state_imp.borrow())?;
                        } else {
                            let _ = status_imp.set_text("Failed to update PATH");
                        }
                    } else {
                        let _ = status_imp.set_text("Import cancelled");
                    }
                }
                Err(e) => {
                    let _ = status_imp.set_text(&format!("Failed to read file: {}", e));
                }
            }
            Ok(())
        });
    }

    // Run main loop (this will create the window and controls as well)
    wnd.run_main(None).map(|_| ())
}

