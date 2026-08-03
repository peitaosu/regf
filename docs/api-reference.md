# API reference

## Crate root (`lib.rs`)

```rust
pub mod error;
pub mod structures;
pub mod parser;
pub mod hive;
pub mod reg_export;
pub mod reg_import;
pub mod writer;
pub mod transaction_log;

pub use error::{Error, Result};
pub use hive::RegistryHive;
pub use structures::*;
pub use transaction_log::TransactionLog;
pub use reg_import::{RegImporter, RegImportOptions, reg_to_hive, reg_file_to_hive_file};
pub use writer::{HiveBuilder, KeyTreeNode, KeyTreeValue};
```

## RegistryHive

| Method | Description |
|--------|-------------|
| `from_file(path)` | Load hive from path |
| `from_reader(reader)` | Load from `Read` |
| `from_bytes(data)` | Load from `Vec<u8>` |
| `new()` | Create empty hive |
| `base_block()` | Reference to header |
| `root_key()` | Root `RegistryKey` |
| `open_key(path)` | Navigate by `\`-separated path |
| `is_dirty()` | Sequence numbers differ |
| `file_name()` | Embedded hive name |
| `version()` | `(major, minor)` tuple |
| `enumerate_all_keys()` | All key paths |

## RegistryKey

| Method | Description |
|--------|-------------|
| `name()` | Key name string |
| `path()` | Full path from root |
| `last_written()` | `DateTime<Utc>` |
| `is_root()` | Root key check |
| `subkey_count()` | Number of subkeys |
| `value_count()` | Number of values |
| `class_name()` | Optional class name |
| `subkeys()` | Child keys |
| `open_subkey(name)` | Direct child by name |
| `values()` | All values |
| `value(name)` | Named value |
| `default_value()` | Default (empty name) value |
| `raw_node()` | Underlying `KeyNode` |
| `offset()` | Cell offset |

## RegistryValueEntry

| Method | Description |
|--------|-------------|
| `name()` | Value name |
| `data_type()` | `DataType` enum |
| `data()` | Raw bytes |
| `as_string()` | Decode REG_SZ |
| `as_dword()` | Decode REG_DWORD |
| `as_qword()` | Decode REG_QWORD |
| `as_multi_string()` | Decode REG_MULTI_SZ |

## HiveBuilder

| Method | Description |
|--------|-------------|
| `new()` | Empty builder |
| `from_tree(node)` | Build from `KeyTreeNode` |
| `root_offset()` | Root cell offset |
| `add_key(parent, name)` | Create subkey |
| `add_value(key, type, data)` | Add value |
| `write_to_file(path)` | Persist hive |
| `into_bytes()` | Return hive bytes |

## KeyTreeNode / KeyTreeValue

```rust
pub struct KeyTreeValue {
    pub name: String,
    pub data_type: DataType,
    pub data: Vec<u8>,
}

pub struct KeyTreeNode {
    pub name: String,
    pub values: Vec<KeyTreeValue>,
    pub children: Vec<KeyTreeNode>,
}
```

| Method | Description |
|--------|-------------|
| `KeyTreeNode::new(name)` | Create node |
| `get_or_create_path(path)` | Navigate/create hierarchy |

## RegExporter

```rust
RegExporter::new(hive, RegExportOptions)
```

| Method | Description |
|--------|-------------|
| `export(writer)` | Write `.reg` content |
| `export_to_file(path)` | Write to file |

### RegExportOptions

| Field | Default |
|-------|---------|
| `version` | `RegVersion::Version5` |
| `root_path` | `""` |
| `include_empty_keys` | `true` |
| `recursive` | `true` |

## RegImporter

| Constructor | Description |
|-------------|-------------|
| `from_file(path)` | Load and parse `.reg` |
| `from_file_with_options(path, opts)` | With options |
| `from_string(content)` | Parse string |
| `new(entries, options)` | From parsed entries |

| Method | Description |
|--------|-------------|
| `build_hive()` | Return `Vec<u8>` |
| `build_hive_to_file(path)` | Write hive file |

### RegImportOptions

| Field | Default |
|-------|---------|
| `root_name` | `""` |
| `strip_prefix` | `None` |
| `minor_version` | `6` |

## Convenience functions

```rust
reg_to_hive(reg_path) -> Result<Vec<u8>>
reg_file_to_hive_file(reg_path, hive_path) -> Result<()>
```

## TransactionLog

| Method | Description |
|--------|-------------|
| `parse(reader)` | Auto-detect old/new format |
| `base_block()` | Embedded base block copy |

Variants: `TransactionLog::Old(OldFormatLog)`, `TransactionLog::New(NewFormatLog)`.

## Error

| Variant | Cause |
|---------|-------|
| `Io` | File I/O |
| `InvalidSignature` | Wrong magic bytes |
| `ChecksumMismatch` | Header checksum failure |
| `SequenceMismatch` | Dirty hive indicator |
| `InvalidCellOffset` | Out-of-range offset |
| `InvalidCellSize` | Corrupt cell size |
| `UnallocatedCell` | Read free cell |
| `UnknownCellType` | Unrecognized signature |
| `KeyNotFound` | Path lookup failed |
| `ValueNotFound` | Value name not found |
| `UnsupportedVersion` | Hive < 1.3 |
| `CorruptHive` | General corruption |
| `DataTooLarge` | Exceeds limits |
| `InvalidUtf16String` | String decode failure |

## DataType

Standard Windows registry types. Conversion:

- `DataType::from(u32)` — raw type constant
- `u32::from(DataType)` — to constant

Helpers in `structures::data_types`:

- `decode_utf16le_string`, `encode_utf16le_string`
- `decode_multi_string`, `encode_multi_string`

## HiveParser (advanced)

Low-level parser exposed via `RegistryHive` internals. Direct use requires `Read + Seek`:

| Method | Description |
|--------|-------------|
| `new(reader)` | Parse file |
| `read_cell(offset)` | Raw cell |
| `read_key_node(offset)` | nk cell |
| `read_key_value(offset)` | vk cell |
| `read_subkeys_list(offset)` | Subkey index |
| `get_subkey_offsets(node)` | Resolved subkey offsets |
| `get_value_offsets(node)` | Value cell offsets |
| `read_value_data(offset, size)` | Value payload |
