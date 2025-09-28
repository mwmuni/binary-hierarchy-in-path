use std::collections::HashSet;
use std::env;
// PathBuf import not needed here

/// Expand Windows-style %VAR% occurrences in the input string.
/// Unknown variables are left as-is (preserve %VAR%).
/// Information about an expansion attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandInfo {
    pub expanded: String,
    pub cycle_detected: bool,
    pub reached_depth_limit: bool,
}

/// Variable lookup abstraction for testability and alternate sources (e.g., registry on Windows).
pub trait VarLookup {
    fn get(&self, name: &str) -> Option<String>;
}

/// Process environment lookup (default behaviour).
pub struct ProcessEnvLookup;
impl VarLookup for ProcessEnvLookup {
    fn get(&self, name: &str) -> Option<String> {
        env::var_os(name).map(|v| v.to_string_lossy().to_string())
    }
}

/// Windows Registry lookup (HKCU/HKLM Environment). Only built on Windows.
#[cfg(windows)]
pub struct RegistryEnvLookup;
#[cfg(windows)]
impl VarLookup for RegistryEnvLookup {
    fn get(&self, name: &str) -> Option<String> {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::{RegKey, HKEY};
        let target_upper = name.to_ascii_uppercase();
        let lookup_in = |hkey: HKEY, subkey: &str| -> Option<String> {
            let root = RegKey::predef(hkey);
            let key = root.open_subkey_with_flags(subkey, KEY_READ).ok()?;
            // First, try direct get_value (case-sensitive)
            if let Ok(val) = key.get_value::<String, _>(name) { return Some(val); }
            // Then search case-insensitively
            for item in key.enum_values().flatten() {
                let (val_name, _val) = (item.0, item.1);
                if val_name.to_ascii_uppercase() == target_upper {
                    if let Ok(val) = key.get_value::<String, _>(&val_name) {
                        return Some(val);
                    }
                }
            }
            None
        };
        lookup_in(HKEY_CURRENT_USER, "Environment")
            .or_else(|| lookup_in(HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"))
    }
}

/// Windows Registry USER lookup (HKCU\Environment). Only built on Windows.
#[cfg(windows)]
pub struct RegistryUserLookup;
#[cfg(windows)]
impl VarLookup for RegistryUserLookup {
    fn get(&self, name: &str) -> Option<String> {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
        use winreg::{RegKey, HKEY};
        let target_upper = name.to_ascii_uppercase();
        let lookup_in = |hkey: HKEY, subkey: &str| -> Option<String> {
            let root = RegKey::predef(hkey);
            let key = root.open_subkey_with_flags(subkey, KEY_READ).ok()?;
            if let Ok(val) = key.get_value::<String, _>(name) { return Some(val); }
            for item in key.enum_values().flatten() {
                let (val_name, _val) = (item.0, item.1);
                if val_name.to_ascii_uppercase() == target_upper {
                    if let Ok(val) = key.get_value::<String, _>(&val_name) { return Some(val); }
                }
            }
            None
        };
        lookup_in(HKEY_CURRENT_USER, "Environment")
    }
}

/// Windows Registry SYSTEM lookup (HKLM...Session Manager\Environment). Only built on Windows.
#[cfg(windows)]
pub struct RegistrySystemLookup;
#[cfg(windows)]
impl VarLookup for RegistrySystemLookup {
    fn get(&self, name: &str) -> Option<String> {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::{RegKey, HKEY};
        let target_upper = name.to_ascii_uppercase();
        let lookup_in = |hkey: HKEY, subkey: &str| -> Option<String> {
            let root = RegKey::predef(hkey);
            let key = root.open_subkey_with_flags(subkey, KEY_READ).ok()?;
            if let Ok(val) = key.get_value::<String, _>(name) { return Some(val); }
            for item in key.enum_values().flatten() {
                let (val_name, _val) = (item.0, item.1);
                if val_name.to_ascii_uppercase() == target_upper {
                    if let Ok(val) = key.get_value::<String, _>(&val_name) { return Some(val); }
                }
            }
            None
        };
        lookup_in(HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
    }
}

/// Composite lookup (process env first, then registry if available) used for optional fallback.
pub struct DefaultLookup;
impl VarLookup for DefaultLookup {
    fn get(&self, name: &str) -> Option<String> {
        ProcessEnvLookup.get(name)
            .or_else(|| {
                #[cfg(windows)]
                { RegistryEnvLookup.get(name) }
                #[cfg(not(windows))]
                { None }
            })
    }
}

/// Scope for environment variable lookup ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryScope {
    /// Process env, then User (HKCU), then System (HKLM) [default]
    ProcessUserSystem,
    /// User (HKCU) only
    UserOnly,
    /// System (HKLM) only
    SystemOnly,
    /// User first, then System
    UserThenSystem,
    /// System first, then User
    SystemThenUser,
    /// Process env only
    ProcessOnly,
}

struct ScopeLookup {
    scope: RegistryScope,
}
impl VarLookup for ScopeLookup {
    fn get(&self, name: &str) -> Option<String> {
        match self.scope {
            RegistryScope::ProcessOnly => ProcessEnvLookup.get(name),
            RegistryScope::UserOnly => {
                #[cfg(windows)]
                { RegistryUserLookup.get(name) }
                #[cfg(not(windows))]
                { None }
            }
            RegistryScope::SystemOnly => {
                #[cfg(windows)]
                { RegistrySystemLookup.get(name) }
                #[cfg(not(windows))]
                { None }
            }
            RegistryScope::UserThenSystem => {
                #[cfg(windows)]
                { RegistryUserLookup.get(name).or_else(|| RegistrySystemLookup.get(name)) }
                #[cfg(not(windows))]
                { None }
            }
            RegistryScope::SystemThenUser => {
                #[cfg(windows)]
                { RegistrySystemLookup.get(name).or_else(|| RegistryUserLookup.get(name)) }
                #[cfg(not(windows))]
                { None }
            }
            RegistryScope::ProcessUserSystem => {
                #[cfg(windows)]
                { ProcessEnvLookup.get(name).or_else(|| RegistryUserLookup.get(name)).or_else(|| RegistrySystemLookup.get(name)) }
                #[cfg(not(windows))]
                { ProcessEnvLookup.get(name) }
            }
        }
    }
}

/// Single-pass expansion that replaces %VAR% with lookup value if present, leaves unknown %VAR% intact,
/// and treats '%%' as literal '%%'.
fn single_pass_with_lookup(src: &str, lookup: &impl VarLookup) -> String {
        let mut out = String::with_capacity(src.len());
        let mut chars = src.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '%' {
                // read until next '%'
                let mut var = String::new();
                let mut closed = false;
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '%' {
                        closed = true;
                        break;
                    }
                    var.push(nc);
                }
                if closed {
                    if var.is_empty() {
                        out.push('%'); out.push('%');
                    } else if let Some(val) = lookup.get(&var) {
                        out.push_str(&val);
                    } else {
                        out.push('%'); out.push_str(&var); out.push('%');
                    }
                } else {
                    out.push('%'); out.push_str(&var);
                }
            } else {
                out.push(c);
            }
        }
        out
}

/// Expand with cycle detection and depth limit using provided lookup.
pub fn expand_env_vars_with_info_lookup(input: &str, max_depth: usize, lookup: &impl VarLookup) -> ExpandInfo {
    let mut current = input.to_string();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cycle_detected = false;
    let mut reached_depth_limit = false;

    for i in 0..max_depth {
        if !seen.insert(current.clone()) {
            cycle_detected = true;
            break;
        }
        let next = single_pass_with_lookup(&current, lookup);
        if next == current {
            return ExpandInfo { expanded: current, cycle_detected, reached_depth_limit };
        }
        current = next;
        if i == max_depth - 1 {
            reached_depth_limit = true;
        }
    }
    ExpandInfo { expanded: current, cycle_detected, reached_depth_limit }
}

/// Default expansion using process env only.
pub fn expand_env_vars(input: &str) -> String {
    let info = expand_env_vars_with_info_lookup(input, 10, &ProcessEnvLookup);
    info.expanded
}

/// Expansion with registry fallback (Windows only); on non-Windows same as process env.
pub fn expand_env_vars_with_registry(input: &str) -> ExpandInfo {
    expand_env_vars_with_info_lookup(input, 10, &DefaultLookup)
}

/// Expansion with selectable lookup scope.
pub fn expand_env_vars_with_scope(input: &str, scope: RegistryScope) -> ExpandInfo {
    let lookup = ScopeLookup { scope };
    expand_env_vars_with_info_lookup(input, 10, &lookup)
}

/// Retrieve the PATH string according to the given scope.
/// - ProcessUserSystem/ProcessOnly: uses current process PATH.
/// - UserOnly: reads HKCU\Environment Path on Windows.
/// - SystemOnly: reads HKLM...Session Manager\Environment Path on Windows.
/// - UserThenSystem/SystemThenUser: concatenates both (if available) with ';'.
pub fn get_path_string_for_scope(scope: RegistryScope) -> Option<String> {
    match scope {
        RegistryScope::ProcessOnly | RegistryScope::ProcessUserSystem => {
            env::var_os("PATH").map(|v| v.to_string_lossy().to_string())
        }
        RegistryScope::UserOnly => {
            #[cfg(windows)]
            { RegistryUserLookup.get("Path") }
            #[cfg(not(windows))]
            { None }
        }
        RegistryScope::SystemOnly => {
            #[cfg(windows)]
            { RegistrySystemLookup.get("Path") }
            #[cfg(not(windows))]
            { None }
        }
        RegistryScope::UserThenSystem => {
            #[cfg(windows)]
            {
                let u = RegistryUserLookup.get("Path");
                let s = RegistrySystemLookup.get("Path");
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
        RegistryScope::SystemThenUser => {
            #[cfg(windows)]
            {
                let u = RegistryUserLookup.get("Path");
                let s = RegistrySystemLookup.get("Path");
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

/// Set the PATH string according to the given scope.
/// - ProcessOnly: sets current process PATH.
/// - UserOnly: writes HKCU\Environment Path on Windows.
/// - SystemOnly: writes HKLM...Session Manager\Environment Path on Windows.
/// Returns true if successful.
pub fn set_path_string_for_scope(scope: RegistryScope, new_path: &str) -> bool {
    match scope {
        RegistryScope::ProcessOnly => {
            env::set_var("PATH", new_path);
            true
        }
        RegistryScope::UserOnly => {
            #[cfg(windows)]
            {
                use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
                use winreg::{RegKey};
                let root = RegKey::predef(HKEY_CURRENT_USER);
                if let Ok(key) = root.open_subkey_with_flags("Environment", KEY_SET_VALUE) {
                    return key.set_value("Path", &new_path.to_string()).is_ok();
                }
                false
            }
            #[cfg(not(windows))]
            { false }
        }
        RegistryScope::SystemOnly => {
            #[cfg(windows)]
            {
                use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
                use winreg::{RegKey};
                let root = RegKey::predef(HKEY_LOCAL_MACHINE);
                if let Ok(key) = root.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", KEY_SET_VALUE) {
                    return key.set_value("Path", &new_path.to_string()).is_ok();
                }
                false
            }
            #[cfg(not(windows))]
            { false }
        }
        _ => false, // Combined scopes not supported for setting
    }
}

#[cfg(test)]
mod tests {
    use super::{expand_env_vars, expand_env_vars_with_info_lookup, VarLookup};
    use std::env;

    #[test]
    fn expands_known_variable() {
        env::set_var("TEST_VAR", "VALUE123");
        let s = "%TEST_VAR%\\bin";
        assert_eq!(expand_env_vars(s), "VALUE123\\bin");
    }

    #[test]
    fn leaves_unknown_variable_intact() {
        env::remove_var("NO_SUCH_VAR");
        let s = "%NO_SUCH_VAR%\\x";
        assert_eq!(expand_env_vars(s), "%NO_SUCH_VAR%\\x");
    }

    #[test]
    fn handles_mixed_text() {
        env::set_var("A", "one");
        let s = "start;%A%;end";
        assert_eq!(expand_env_vars(s), "start;one;end");
    }

    #[test]
    fn unmatched_percent_kept() {
        let s = "%UNFINISHED";
        assert_eq!(expand_env_vars(s), "%UNFINISHED");
    }

    #[test]
    fn empty_var_name_kept() {
        let s = "%%\\path";
        assert_eq!(expand_env_vars(s), "%%\\path");
    }

    #[test]
    fn multiple_vars() {
        env::set_var("X", "xv");
        env::set_var("Y", "yv");
        let s = "%X%-%Y%";
        assert_eq!(expand_env_vars(s), "xv-yv");
    }

    #[test]
    fn preserves_percent_literal() {
        let s = "100%% sure"; // '%%' should remain '%%'
        assert_eq!(expand_env_vars(s), "100%% sure");
    }

    // --- PB1..PB4 investigation tests ---
    #[test]
    fn pb_variables_resolve_all() {
        env::set_var("PB1", "VAL1");
        env::set_var("PB2", "VAL2");
        env::set_var("PB3", "VAL3");
        env::set_var("PB4", "VAL4");
        let s = "%PB1%;%PB2%;%PB3%;%PB4%";
        assert_eq!(expand_env_vars(s), "VAL1;VAL2;VAL3;VAL4");
    }

    #[test]
    fn pb_variables_case_insensitive_on_windows() {
        // On Windows env var names are case-insensitive; we set upper and request lower.
        env::set_var("PB1", "X1");
        let s = "%pb1%";
        assert_eq!(expand_env_vars(s), "X1");
    }

    #[test]
    fn pb_variables_in_path_like_string() {
        env::set_var("PB1", "C:\\PB1DIR");
        let s = "%PB1%;C:\\Other";
        assert_eq!(expand_env_vars(s), "C:\\PB1DIR;C:\\Other");
    }

    #[test]
    fn pb_variable_unresolved_if_absent() {
        env::remove_var("PB2");
        let s = "start;%PB2%;end";
        // If PB2 is not present in the current process, the token should be left intact.
        assert_eq!(expand_env_vars(s), "start;%PB2%;end");
    }

    #[test]
    fn recursive_expansion_resolves_nested() {
        env::set_var("A", "%B%");
        env::set_var("B", "%C%");
        env::set_var("C", "FINAL");
        let s = "%A%";
        assert_eq!(expand_env_vars(s), "FINAL");
    }

    #[test]
    fn recursive_expansion_stops_at_depth() {
        // Create a cycle A -> B -> A
        env::set_var("A", "%B%");
        env::set_var("B", "%A%");
        let s = "%A%";
        // With depth limit, it should stabilize to something like "%A%" or a repeated pattern,
        // but must not loop infinitely. We assert it returns a string containing '%' (i.e. unresolved)
        let out = expand_env_vars(s);
        assert!(out.contains('%'));
    }

    // Fake lookup to simulate registry fallback in tests without touching system state
    struct FakeLookup(std::collections::HashMap<String, String>);
    impl VarLookup for FakeLookup {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(&name.to_ascii_uppercase()).cloned()
        }
    }

    #[test]
    fn pb_variables_resolve_via_fallback() {
        // Ensure not set in process env
        env::remove_var("PB1"); env::remove_var("PB2"); env::remove_var("PB3"); env::remove_var("PB4");
        let mut map = std::collections::HashMap::new();
        map.insert("PB1".to_string(), "R1".to_string());
        map.insert("PB2".to_string(), "R2".to_string());
        map.insert("PB3".to_string(), "R3".to_string());
        map.insert("PB4".to_string(), "R4".to_string());
        let f = FakeLookup(map);
        let info = expand_env_vars_with_info_lookup("%PB1%;%PB2%;%PB3%;%PB4%", 10, &f);
        assert_eq!(info.expanded, "R1;R2;R3;R4");
        assert!(!info.cycle_detected);
        assert!(!info.reached_depth_limit);
    }

    #[test]
    fn cycle_detection_flagged() {
        struct CycleLookup;
        impl VarLookup for CycleLookup {
            fn get(&self, name: &str) -> Option<String> {
                match name.to_ascii_uppercase().as_str() {
                    "A" => Some("%B%".to_string()),
                    "B" => Some("%A%".to_string()),
                    _ => None,
                }
            }
        }
        let info = expand_env_vars_with_info_lookup("%A%", 10, &CycleLookup);
        assert!(info.cycle_detected || info.reached_depth_limit);
        assert!(info.expanded.contains('%'));
    }

    // =========================
    // CLI vs GUI-style comparisons
    // =========================

    // Helper: simple case-insensitive map-based lookup
    #[derive(Default, Clone)]
    struct MapLookup(std::collections::HashMap<String, String>);
    impl MapLookup {
        fn from_pairs(pairs: &[(&str, &str)]) -> Self {
            let mut m = std::collections::HashMap::new();
            for (k, v) in pairs {
                m.insert(k.to_string().to_ascii_uppercase(), (*v).to_string());
            }
            MapLookup(m)
        }
        fn empty() -> Self { MapLookup(Default::default()) }
    }
    impl VarLookup for MapLookup {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(&name.to_ascii_uppercase()).cloned()
        }
    }

    // Helper: ordered composite lookup to simulate Process/User/System ordering
    enum Source {
        Process,
        User,
        System,
    }
    struct OrderLookup {
        order: Vec<Source>,
        process: MapLookup,
        user: MapLookup,
        system: MapLookup,
    }
    impl OrderLookup {
        fn new(order: Vec<Source>, process: MapLookup, user: MapLookup, system: MapLookup) -> Self {
            Self { order, process, user, system }
        }
    }
    impl VarLookup for OrderLookup {
        fn get(&self, name: &str) -> Option<String> {
            for src in &self.order {
                let val = match src {
                    Source::Process => self.process.get(name),
                    Source::User => self.user.get(name),
                    Source::System => self.system.get(name),
                };
                if val.is_some() { return val; }
            }
            None
        }
    }

    #[test]
    fn compare_cli_process_vs_gui_user_only_when_only_process_has_var() {
        // Unique names per test to avoid cross-test interference
        let var = "TC_PROC_ONLY_X2";
        env::set_var(var, "PX2");
        let s = format!("%{}%\\bin", var);

        // CLI-like (process only)
        let cli = expand_env_vars(&s);
        assert_eq!(cli, format!("PX2\\bin"));

        // GUI-like with UserOnly (no fallback) simulated by OrderLookup with only User
        let user_lookup = MapLookup::empty();
        let order = OrderLookup::new(vec![Source::User], MapLookup::empty(), user_lookup, MapLookup::empty());
        let gui = expand_env_vars_with_info_lookup(&s, 10, &order).expanded;
        assert_eq!(gui, s, "GUI(UserOnly) should leave token unresolved when only process has it");

        // cleanup
        env::remove_var(var);
    }

    #[test]
    fn compare_gui_user_then_system_precedence() {
        // No process vars here
        let user = MapLookup::from_pairs(&[("TC_X", "UVAL")]);
        let sys = MapLookup::from_pairs(&[("TC_X", "SVAL")]);
        let s = "%TC_X%";

        // UserThenSystem -> U wins
        let us = OrderLookup::new(vec![Source::User, Source::System], MapLookup::empty(), user.clone(), sys.clone());
        let out_us = expand_env_vars_with_info_lookup(s, 10, &us).expanded;
        assert_eq!(out_us, "UVAL");

        // SystemThenUser -> S wins
        let su = OrderLookup::new(vec![Source::System, Source::User], MapLookup::empty(), user.clone(), sys.clone());
        let out_su = expand_env_vars_with_info_lookup(s, 10, &su).expanded;
        assert_eq!(out_su, "SVAL");
    }

    #[test]
    fn nested_expansion_across_scopes_user_then_system() {
        // A -> %B%\\bin; B only in System
        let user = MapLookup::from_pairs(&[("TCA", "%TCB%\\bin")]);
        let sys = MapLookup::from_pairs(&[("TCB", "ROOT")]);
        let order = OrderLookup::new(vec![Source::User, Source::System], MapLookup::empty(), user, sys);
        let info = expand_env_vars_with_info_lookup("%TCA%", 10, &order);
        assert_eq!(info.expanded, "ROOT\\bin");
        assert!(!info.cycle_detected);
    }

    #[test]
    fn cycle_across_user_and_system_is_detected() {
        // TCA -> %TCB%, TCB -> %TCA%
        let user = MapLookup::from_pairs(&[("TCA", "%TCB%")]);
        let sys = MapLookup::from_pairs(&[("TCB", "%TCA%")]);
        let order = OrderLookup::new(vec![Source::User, Source::System], MapLookup::empty(), user, sys);
        let info = expand_env_vars_with_info_lookup("%TCA%", 10, &order);
        assert!(info.cycle_detected || info.reached_depth_limit);
        assert!(info.expanded.contains('%'));
    }

    #[test]
    fn compare_cli_process_only_vs_gui_process_user_system_fallback() {
        // Process PATH-like value containing variables known only to user/system
        env::remove_var("TC_A");
        env::remove_var("TC_B");
        env::set_var("TC_PATHVAL", "%TC_A%;%TC_B%");

        let s = "%TC_PATHVAL%";
        // CLI: process-only expansion — leaves %TC_A%;%TC_B% unresolved inside
        let cli = expand_env_vars(s);
        assert_eq!(cli, "%TC_A%;%TC_B%", "process-only should not resolve A/B");

        // GUI-like with Process+User+System ordering
        let process = MapLookup::from_pairs(&[("TC_PATHVAL", "%TC_A%;%TC_B%")]);
        let user = MapLookup::from_pairs(&[("TC_A", "UA")]);
        let sys = MapLookup::from_pairs(&[("TC_B", "SB")]);
        let pus = OrderLookup::new(vec![Source::Process, Source::User, Source::System], process, user, sys);
        let out = expand_env_vars_with_info_lookup("%TC_PATHVAL%", 10, &pus).expanded;
        assert_eq!(out, "UA;SB");

        // cleanup
        env::remove_var("TC_PATHVAL");
    }

    #[test]
    fn mixed_known_unknown_tokens_are_preserved() {
        // Only one of the two exists in ordered lookup
        let user = MapLookup::from_pairs(&[("KNOWN1", "V1")]);
        let order = OrderLookup::new(vec![Source::User], MapLookup::empty(), user, MapLookup::empty());
        let info = expand_env_vars_with_info_lookup("%KNOWN1%;%UNKNOWN2%", 10, &order);
        assert_eq!(info.expanded, "V1;%UNKNOWN2%");
    }

    #[test]
    fn path_like_semicolon_with_multiple_tokens() {
        let process = MapLookup::from_pairs(&[("P1", "C:/P1"), ("P2", "C:/P2")]);
        let order = OrderLookup::new(vec![Source::Process], process, MapLookup::empty(), MapLookup::empty());
        let info = expand_env_vars_with_info_lookup("%P1%;%P2%;C:/Fixed", 10, &order);
        assert_eq!(info.expanded, "C:/P1;C:/P2;C:/Fixed");
    }
}
