# Path Tree

A Windows PATH environment variable analyzer with both CLI and GUI interfaces. Displays the hierarchy of PATH entries, identifies duplicate binaries, and shows which executables are masked by earlier entries.

## Features

### CLI Tool (`path-tree`)

- Displays PATH entries in a tree structure
- Shows binaries in each PATH directory
- Identifies overridden (masked) executables
- Supports different PATH scopes (User, System, Process, combined)

### GUI Tool (`path-tree-gui`)

- Interactive tree view of PATH entries
- Real-time filtering of binaries
- Visual indicators:
  - 🟢 Green: Resolved PATH entries
  - 🔴 Red: Unresolved PATH entries
  - 🟡 Yellow: Entries containing overridden binaries
  - ★ Star: Entries with original (first) occurrences of duplicated keys
  - ♦ Diamond: Entries with duplicate (later) occurrences of keys
  - 🟡 Yellow binaries: Overridden executables with ⤴ indicator
- Scope selection (User, System, Process, User+System, etc.)
- Context menu actions:
  - Right-click: Open folder in Windows Explorer
- Double-click overridden binaries to jump to the overriding entry
- Detailed information panel showing file metadata and shadowing details

## Building

```bash
cargo build --release
```

## Running

### CLI

```bash
# Default: User PATH scope
.\target\release\path-tree.exe

# System PATH
.\target\release\path-tree.exe --scope system

# Available scopes: user, system, process, process-user-system, user-then-system, system-then-user
```

### GUI

```bash
.\target\release\path-tree-gui.exe
```

## Usage

### CLI Options

- `--scope <SCOPE>`: Choose PATH scope to analyze
  - `user`: User PATH entries only
  - `system`: System PATH entries only
  - `process`: Current process PATH
  - `process-user-system`: Process + User + System combined
  - `user-then-system`: User entries first, then System
  - `system-then-user`: System entries first, then User

### GUI Features

- **Scope Selection**: Radio buttons to switch between different PATH scopes
- **Filtering**: Type in the filter box to show only PATH entries containing matching binaries
- **Tree Navigation**:
  - Click entries to view details
  - Double-click yellow (overridden) binaries to jump to the effective version
  - Right-click binaries to open their containing folder in Explorer
- **Visual Legend**:
  - Green entries: Valid directories
  - Red entries: Invalid/missing directories
  - Yellow entries: Contain overridden binaries
  - Star (★): Contains first occurrence of duplicated binaries
  - Diamond (♦): Contains duplicate occurrences
  - Yellow binary with ⤴: Overridden executable

## Examples

### CLI Output

```text
C:\Windows\system32
├── cmd.exe
├── notepad.exe
└── ...
C:\Windows
├── where.exe [overridden]
└── ...
```

### GUI Interface

The GUI provides an interactive tree view with color-coded entries and detailed information panels showing file paths, modification times, and shadowing relationships.

## Requirements

- Windows (uses Windows-specific APIs for PATH handling)
- Rust 1.70+ for building

## License

MIT
