# Reg text format

Windows Registry Editor text format (`.reg`) import and export.

## Export

Module: `reg_export`

### Output structure

```
FF FE                          UTF-16LE BOM
Windows Registry Editor Version 5.00
                                 blank line
[KeyPath\SubKey]
"ValueName"=data
@=default_value
```

### RegExportOptions

| Field | Effect |
|-------|--------|
| `root_path` | Prefix prepended to all key paths (e.g. `HKEY_LOCAL_MACHINE\SOFTWARE`) |
| `include_empty_keys` | Emit keys with no values |
| `recursive` | Descend subkeys |
| `version` | `Version5` (Unicode) or `Version4` (legacy ANSI) |

### Value encoding

| DataType | Output form |
|----------|-------------|
| REG_SZ | `"value"` with escaped `\` and `"` |
| REG_DWORD | `dword:xxxxxxxx` |
| REG_QWORD | `hex(b):aa,bb,...` |
| REG_BINARY | `hex:aa,bb,...` |
| REG_EXPAND_SZ | `hex(2):...` |
| REG_MULTI_SZ | `hex(7):...` |

Long hex lines wrap with `\` continuation per regedit convention.

### Example

```rust
use regf::{RegistryHive, RegExporter, RegExportOptions};

let hive = RegistryHive::from_file("software.dat")?;
let options = RegExportOptions {
    root_path: "HKEY_LOCAL_MACHINE\\SOFTWARE".into(),
    ..Default::default()
};
RegExporter::new(&hive, options).export_to_file("out.reg")?;
```

## Import

Module: `reg_import`

Uses `RegParser` (shared with export) to parse text, then `HiveBuilder::from_tree` to produce binary hive.

### RegImportOptions

| Field | Effect |
|-------|--------|
| `root_name` | Override hive root key name |
| `strip_prefix` | Remove path prefix from all keys |
| `minor_version` | Hive version written (3–6) |

### Parsing rules

- Header: `Windows Registry Editor Version 5.00` or `REGEDIT4`
- Key lines: `[Path]` — backslash-separated
- Default value: `@=...`
- Named values: `"Name"=...`
- Line continuation: trailing `\`
- Comments: `;` at line start (skipped)

### Path handling

When `strip_prefix` is set, keys matching the prefix have it removed before tree construction. Useful for converting full-path exports to relative hives.

### Example

```rust
use regf::{RegImporter, RegImportOptions, reg_file_to_hive_file};

reg_file_to_hive_file("settings.reg", "settings.dat")?;

let options = RegImportOptions {
    strip_prefix: Some("HKEY_CURRENT_USER\\Software\\MyApp".into()),
    minor_version: 6,
    ..Default::default()
};
RegImporter::from_file_with_options("settings.reg", options)?
    .build_hive_to_file("relative.dat")?;
```

## RegParser (low-level)

```rust
use regf::reg_export::{RegParser, RegEntry};

let parser = RegParser::new(content);
let entries: Vec<RegEntry> = parser.parse();
```

`RegEntry` contains key path and `Vec<RegValue>`.

## Encoding

Export always writes UTF-16LE with BOM.

Import accepts:

- UTF-16LE (with or without BOM)
- UTF-8 (with BOM detection via `encoding_rs`)

## Comparison with regdat

| Aspect | regf | regdat |
|--------|------|--------|
| Platform | Cross-platform | Windows only |
| Engine | Native Rust parser | offreg API |
| Merge/diff/patch | Not provided | Built-in CLI |
| Hive write | HiveBuilder | ORSaveHive |

For merge, diff, and patch workflows on Windows, use [regdat](../regdat/docs/README.md). For library integration and cross-platform builds, use `regf`.

## Supported import value syntax

| Syntax | Type |
|--------|------|
| `"string"` | REG_SZ |
| `dword:hex` | REG_DWORD |
| `hex:aa,bb` | REG_BINARY |
| `hex(b):...` | REG_QWORD |
| `hex(2):...` | REG_EXPAND_SZ |
| `hex(7):...` | REG_MULTI_SZ |

Unsupported syntax returns parse errors or skips lines depending on context.
