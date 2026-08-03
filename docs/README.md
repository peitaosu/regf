# regf documentation

Rust library for parsing, creating, and writing Windows Registry hive files (regf primary format).

Based on the [Windows registry file format specification](Windows_registry_file_format_specification.md) by Maxim Suhanov ([upstream](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)).

## Contents

| Document | Description |
|----------|-------------|
| [Windows registry file format specification](Windows_registry_file_format_specification.md) | Raw format spec (upstream) |
| [Overview](overview.md) | Features, version support, crate layout |
| [Architecture](architecture.md) | Module structure and data flow |
| [Format reference](format-reference.md) | Binary layout summary mapped to spec |
| [Implementation notes](implementation-notes.md) | Coverage, limits, spec deviations |
| [API reference](api-reference.md) | Public types and functions |
| [Transaction logs](transaction-logs.md) | Log file formats and parsing |
| [Reg text format](reg-text-format.md) | `.reg` import and export |

## Quick start

```rust
use regf::RegistryHive;

let hive = RegistryHive::from_file("NTUSER.DAT")?;
let key = hive.open_key("Software\\Microsoft")?;

for subkey in key.subkeys()? {
    println!("{}", subkey.name());
}
```

See crate `README.md` and `examples/` for additional usage.
