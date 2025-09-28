use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser, ValueEnum};
use owo_colors::OwoColorize;
use path_tree::path_utils::{expand_env_vars_with_scope, RegistryScope};
use std::io::{self, Write};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Scope {
    /// Use the current process environment only (effective PATH etc.)
    Effective,
    /// Read from the current user environment (HKCU) only
    User,
    /// Read from the system environment (HKLM) only
    System,
    /// Concatenate User then System values (PATH-like)
    UserThenSystem,
    /// Concatenate System then User values (PATH-like)
    SystemThenUser,
    /// Use process value; when expanding nested %VARS% fall back to User then System
    ProcessUserSystem,
}

#[derive(Parser, Debug)]
#[command(name = "path-tree", version, about = "Inspect binaries exposed by PATH-like environment variables on Windows")] 
struct Args {
    /// Environment variable(s) to inspect (PATH-like). Repeatable.
    #[arg(short = 'v', long = "var", action = ArgAction::Append)]
    vars: Vec<String>,

    /// Specific binary name(s) to query (e.g., python.exe). Repeatable.
    #[arg(short, long, action = ArgAction::Append)]
    binary: Vec<String>,

    /// Which environment scope to read from
    #[arg(long, value_enum, default_value_t = Scope::Effective)]
    scope: Scope,

    /// Disable ANSI colors in output
    #[arg(long)]
    no_color: bool,
}

fn is_executable_on_windows(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    // On Windows, executables typically end with these extensions.
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

#[cfg(windows)]
fn get_env_var_from_registry_raw_user(name: &str) -> Option<OsString> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let env = hkcu.open_subkey_with_flags("Environment", KEY_READ).ok()?;
    env.get_value::<OsString, _>(name).ok()
}

#[cfg(windows)]
fn get_env_var_from_registry_raw_system(name: &str) -> Option<OsString> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let env = hklm
        .open_subkey_with_flags(
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            KEY_READ,
        )
        .ok()?;
    env.get_value::<OsString, _>(name).ok()
}

/// Fetch raw variable string for a given scope.
/// For combined scopes, concatenates values with ';' (appropriate for PATH-like vars).
fn get_var_string_for_scope(scope: Scope, name: &str) -> Option<String> {
    match scope {
        Scope::Effective | Scope::ProcessUserSystem => {
            env::var_os(name).map(|v| v.to_string_lossy().to_string())
        }
        Scope::User => {
            #[cfg(windows)]
            { get_env_var_from_registry_raw_user(name).map(|v| v.to_string_lossy().to_string()) }
            #[cfg(not(windows))]
            { None }
        }
        Scope::System => {
            #[cfg(windows)]
            { get_env_var_from_registry_raw_system(name).map(|v| v.to_string_lossy().to_string()) }
            #[cfg(not(windows))]
            { None }
        }
        Scope::UserThenSystem => {
            #[cfg(windows)]
            {
                let u = get_env_var_from_registry_raw_user(name).map(|v| v.to_string_lossy().to_string());
                let s = get_env_var_from_registry_raw_system(name).map(|v| v.to_string_lossy().to_string());
                match (u, s) {
                    (Some(us), Some(ss)) => Some(format!("{};{}", us, ss)),
                    (Some(us), None) => Some(us),
                    (None, Some(ss)) => Some(ss),
                    _ => None,
                }
            }
            #[cfg(not(windows))]
            { None }
        }
        Scope::SystemThenUser => {
            #[cfg(windows)]
            {
                let u = get_env_var_from_registry_raw_user(name).map(|v| v.to_string_lossy().to_string());
                let s = get_env_var_from_registry_raw_system(name).map(|v| v.to_string_lossy().to_string());
                match (s, u) {
                    (Some(ss), Some(us)) => Some(format!("{};{}", ss, us)),
                    (Some(ss), None) => Some(ss),
                    (None, Some(us)) => Some(us),
                    _ => None,
                }
            }
            #[cfg(not(windows))]
            { None }
        }
    }
}

fn expand_with_scope_str(input: &str, scope: Scope) -> String {
    let rscope = match scope {
        Scope::Effective => RegistryScope::ProcessOnly,
        Scope::User => RegistryScope::UserOnly,
        Scope::System => RegistryScope::SystemOnly,
        Scope::UserThenSystem => RegistryScope::UserThenSystem,
        Scope::SystemThenUser => RegistryScope::SystemThenUser,
        Scope::ProcessUserSystem => RegistryScope::ProcessUserSystem,
    };
    expand_env_vars_with_scope(input, rscope).expanded
}

fn parse_paths_from_var(var_name: &str, scope: Scope) -> Vec<PathBuf> {
    let raw = get_var_string_for_scope(scope, var_name).unwrap_or_default();
    let expanded = expand_with_scope_str(&raw, scope);
    env::split_paths(&OsString::from(expanded)).collect()
}

fn build_dir_index(paths: &[PathBuf]) -> (HashMap<String, usize>, Vec<Vec<OsString>>) {
    // Map binary name (lowercase String) -> first-seen path index
    let mut seen: HashMap<String, usize> = HashMap::new();
    // For each directory index, list of binaries in it
    let mut dir_bins: Vec<Vec<OsString>> = Vec::new();

    for (i, p) in paths.iter().enumerate() {
        let bins = collect_binaries_in_dir(p);
        for b in &bins {
            let key = b.to_string_lossy().to_lowercase();
            seen.entry(key).or_insert(i);
        }
        dir_bins.push(bins);
    }
    (seen, dir_bins)
}

// Write a single line to stdout, returning false if the pipe is closed (BrokenPipe).
fn print_line(line: &str) -> bool {
    let mut out = io::stdout().lock();
    match out.write_all(line.as_bytes()).and_then(|_| out.write_all(b"\n")) {
        Ok(_) => true,
        Err(e) => {
            if e.kind() == io::ErrorKind::BrokenPipe { return false; }
            // For other IO errors, also stop printing to avoid panic storms.
            false
        }
    }
}

fn print_tree_for_var(var_name: &str, scope: Scope, no_color: bool) {
    let paths = parse_paths_from_var(var_name, scope);
    let (seen, dir_bins) = build_dir_index(&paths);

    let header = format!(
        "{} [{}]",
        var_name,
        match scope {
            Scope::Effective => "effective",
            Scope::User => "user",
            Scope::System => "system",
            Scope::UserThenSystem => "user→system",
            Scope::SystemThenUser => "system→user",
            Scope::ProcessUserSystem => "process+user+system",
        }
    );
    let header_line = if no_color { header } else { header.bold().blue().to_string() };
    if !print_line(&header_line) { return; }

    for (i, p) in paths.iter().enumerate() {
    let p_disp = p.display().to_string();
    let root_line = if no_color { p_disp.clone() } else { p_disp.bold().to_string() };
    if !print_line(&root_line) { return; }
        let mut bins = dir_bins.get(i).cloned().unwrap_or_default();
        bins.sort_by_key(|s| s.to_string_lossy().to_lowercase());
        for b in bins {
            let key = b.to_string_lossy().to_lowercase();
            let owner = seen.get(&key).copied().unwrap_or(i);
            if owner == i {
        let line = if no_color { format!("  ├─ {}", b.to_string_lossy()) } else { format!("  ├─ {}", b.to_string_lossy().green()) };
        if !print_line(&line) { return; }
            } else {
                let msg = format!(
                    "  ├─ {}  (ignored, first defined at [{}] {})",
                    b.to_string_lossy(),
                    owner,
                    paths[owner].display()
                );
        let line = if no_color { msg } else { msg.yellow().to_string() };
        if !print_line(&line) { return; }
            }
        }
    }
}

fn query_binaries(var_names: &[String], scope: Scope, binaries: &[String], no_color: bool) {
    // Collect data per var
    let mut overall_first: Option<(String, PathBuf, String)> = None; // (binary, path, var_name)

    for var in var_names {
        let paths = parse_paths_from_var(var, scope);
        let (_seen, _dir_bins) = build_dir_index(&paths);
        let header = format!(
            "{} [{}]",
            var,
            match scope {
                Scope::Effective => "effective",
                Scope::User => "user",
                Scope::System => "system",
                Scope::UserThenSystem => "user→system",
                Scope::SystemThenUser => "system→user",
                Scope::ProcessUserSystem => "process+user+system",
            }
        );
    let header_line = if no_color { header } else { header.bold().blue().to_string() };
    if !print_line(&header_line) { return; }

        for bin in binaries {
            // compute key if needed in future: let _key = bin.to_lowercase();
            let mut found_at: Vec<usize> = Vec::new();
            // Walk directories to find occurrences in order
            for (i, p) in paths.iter().enumerate() {
                let target = p.join(bin);
                if target.is_file() {
                    found_at.push(i);
                }
            }
            if found_at.is_empty() {
                if !print_line(&format!("  {} not found", bin)) { return; }
                continue;
            }

            // Winner within this var
            let winner_idx = *found_at.first().unwrap();
            let winner_path = paths[winner_idx].clone();
            let line = format!(
                "  {} -> {}",
                bin,
                winner_path.display(),
            );
            let line = if no_color { line } else { line.green().to_string() };
            if !print_line(&line) { return; }

            // Others shadowed
            for &idx in found_at.iter().skip(1) {
                let msg = format!(
                    "    shadows later entry at [{}] {}",
                    idx,
                    paths[idx].display()
                );
                let line = if no_color { msg } else { msg.yellow().to_string() };
                if !print_line(&line) { return; }
            }

            // Track overall precedence across provided vars (first var in list has precedence if same position logic)
            match &overall_first {
                None => overall_first = Some((bin.clone(), winner_path, var.clone())),
                Some((_, existing_path, _)) => {
                    // Keep the first seen according to var order, so do nothing
                    let _ = existing_path; // explicit no-op
                }
            }
        }
    }

    // Summary for the first binary only (if a single query) or per first seen
    if binaries.len() == 1 {
        if let Some((bin, path, var)) = overall_first {
            let msg = format!("Overall precedence winner for {}: {} (from {} variable)", bin, path.display(), var);
            let line = if no_color { msg } else { msg.bold().magenta().to_string() };
            let _ = print_line(&line);
        }
    }
}

fn main() {
    let mut args = Args::parse();
    // Honor NO_COLOR if set
    let env_no_color = env::var_os("NO_COLOR").is_some();
    if env_no_color { args.no_color = true; }

    // Default to PATH if no vars provided
    if args.vars.is_empty() {
        args.vars.push("PATH".to_string());
    }

    if args.binary.is_empty() {
        // Full report mode for each var
        for var in &args.vars {
            print_tree_for_var(var, args.scope, args.no_color);
        }
    } else {
        query_binaries(&args.vars, args.scope, &args.binary, args.no_color);
    }
}
