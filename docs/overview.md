# Overview

## Purpose

`regf` reads and writes Windows Registry primary hive files without requiring the Windows registry API. It implements the on-disk regf binary format and provides high-level key/value navigation plus `.reg` text conversion.

## Features

| Capability | Module |
|------------|--------|
| Parse primary hive files | `parser`, `structures` |
| Navigate keys and values | `hive` |
| Create and write hives | `writer` |
| Export to `.reg` | `reg_export` |
| Import from `.reg` | `reg_import` |
| Parse transaction logs | `transaction_log` |

## Supported hive versions

| Version | Windows | Support |
|---------|---------|---------|
| 1.1 | NT 3.1 | Not supported (16-byte cell alignment) |
| 1.2 | NT 3.5 | Not supported |
| 1.3 | NT 4.0 | Read; Fast Leaf |
| 1.4 | 2000 | Read |
| 1.5 | XP | Read/Write; Hash Leaf, Big Data |
| 1.6 | Vista+ | Read/Write; full base block |

Parser rejects major != 1 or minor < 3.

## Supported value types

| Type | Read | Write | `.reg` export |
|------|------|-------|---------------|
| REG_SZ | yes | yes | yes |
| REG_EXPAND_SZ | yes | yes | yes |
| REG_BINARY | yes | yes | yes |
| REG_DWORD | yes | yes | yes |
| REG_QWORD | yes | yes | yes |
| REG_MULTI_SZ | yes | yes | yes |
| REG_NONE | yes | yes | no |
| Other types | yes | partial | as hex |

Values larger than 16344 bytes use Big Data (`db`) cells on write.

## Dependencies

| Crate | Use |
|-------|-----|
| `byteorder` | Little-endian I/O |
| `thiserror` | Error types |
| `bitflags` | Base block and key flags |
| `chrono` | FILETIME conversion |
| `encoding_rs` | Legacy encoding in reg import |

Optional `serde` feature for structure serialization.

## Examples

| Example | Demonstrates |
|---------|--------------|
| `basic.rs` | Load hive, print structure |
| `read_hive.rs` | Key/value enumeration |
| `create_hive.rs` | HiveBuilder usage |
| `roundtrip.rs` | Write and re-read |
| `hive_to_reg.rs` | Export |
| `reg_to_hive.rs` | Import |
| `import_reg.rs` | RegImporter options |

## Related tools

[regdat](../regdat/docs/README.md) provides a Windows CLI for `.reg`/`.dat` conversion using offreg. `regf` is a cross-platform Rust library with native format implementation.
