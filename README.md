# regf

A Rust library for parsing, manipulating, and writing Windows Registry hive files (regf format).

## Features

- Parse binary registry hive files (`.dat`, `NTUSER.DAT`, etc.)
- Navigate and read registry keys and values
- Create new registry hives from scratch
- Export hives to `.reg` text format
- Import `.reg` files to binary hive format

## Installation

```toml
[dependencies]
regf = "0.1"
```

## Quick Start

### Reading a Registry Hive

```rust
use regf::RegistryHive;

let hive = RegistryHive::from_file("NTUSER.DAT")?;
let root = hive.root_key()?;

// Navigate to a key
let key = hive.open_key("Software\\Microsoft\\Windows")?;

// Read values
for value in key.values()? {
    println!("{}: {:?}", value.name(), value.data()?);
}

// Iterate subkeys
for subkey in key.subkeys()? {
    println!("Subkey: {}", subkey.name());
}
```

### Creating a New Hive

```rust
use regf::{HiveBuilder, DataType};

let mut builder = HiveBuilder::new();
let root = builder.root_offset();

// Add keys
let software = builder.add_key(root, "Software")?;
let app = builder.add_key(software, "MyApp")?;

// Add values
builder.add_value(app, "Version", DataType::Dword, &1u32.to_le_bytes())?;

// Write to file
builder.write_to_file("output.dat")?;
```

### Export to .reg Format

```rust
use regf::{RegistryHive, RegExporter, RegExportOptions};

let hive = RegistryHive::from_file("input.dat")?;
let options = RegExportOptions {
    root_path: "HKEY_LOCAL_MACHINE\\SOFTWARE".to_string(),
    ..Default::default()
};

let exporter = RegExporter::new(&hive, options);
exporter.export_to_file("output.reg")?;
```

### Import from .reg Format

```rust
use regf::{RegImporter, reg_file_to_hive_file};

// Quick conversion
reg_file_to_hive_file("input.reg", "output.dat")?;

// Or with options
let importer = RegImporter::from_file("input.reg")?;
importer.build_hive_to_file("output.dat")?;
```

## Supported Data Types

| Type | Description |
|------|-------------|
| `REG_SZ` | String |
| `REG_EXPAND_SZ` | Expandable string |
| `REG_BINARY` | Binary data |
| `REG_DWORD` | 32-bit integer |
| `REG_QWORD` | 64-bit integer |
| `REG_MULTI_SZ` | Multi-string |

## License

MIT
