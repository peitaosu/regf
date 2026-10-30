# Architecture

## Module map

```
src/
├── lib.rs              Public re-exports
├── error.rs            Error enum, Result alias
├── structures/         Binary format types
│   ├── base_block.rs   4096-byte file header
│   ├── hive_bin.rs     hbin containers
│   ├── cell.rs         Cell headers, types, alignment
│   ├── key_node.rs     nk cells
│   ├── key_value.rs    vk cells
│   ├── subkeys_list.rs li, lf, lh, ri structures
│   ├── key_security.rs sk cells
│   ├── big_data.rs     db cells for large values
│   └── data_types.rs   REG_* types, UTF-16 helpers
├── parser.rs           HiveParser: low-level read
├── hive.rs             RegistryHive, RegistryKey, RegistryValueEntry
├── writer.rs           HiveBuilder, KeyTreeNode
├── reg_export.rs       RegExporter, RegParser
├── reg_import.rs       RegImporter
└── transaction_log.rs  Old and new log formats
```

## Layer model

```
┌─────────────────────────────────────┐
│  reg_export / reg_import            │  .reg text
├─────────────────────────────────────┤
│  hive / writer                      │  Keys, values, build
├─────────────────────────────────────┤
│  parser                             │  Cell traversal
├─────────────────────────────────────┤
│  structures                         │  Binary layout
└─────────────────────────────────────┘
```

## Read path

```
File / bytes
  → HiveParser::new()
      Read BaseBlock (4096 bytes), validate primary-file invariants
      Validate exact HiveBin coverage and index every cell start
      Validate key, value, subkey, and security references
  → RegistryHive::from_bytes()
  → RegistryKey via root_cell_offset
      get_subkey_offsets() → SubkeysList (li/lf/lh/ri)
      get_value_offsets()  → values list cell
      read_value_data()    → inline or BigData chain
```

## Write path

Two strategies in `writer.rs`:

### Incremental (HiveBuilder)

```
HiveBuilder::new()?
  → add_key(parent, name)
  → add_value(key, type, data)
  → write_to_file()
```

Allocates cells dynamically. Suitable for programmatic construction.

### Tree-based (KeyTreeNode)

```
KeyTreeNode tree
  → HiveBuilder::from_tree(tree)?
  → write_to_file()
```

Pre-computes sizes for tighter layout. Used by `RegImporter`.

## Cell addressing

Cell offsets are relative to the start of hive bin data (after the 4096-byte base block). Each cell begins with a signed 32-bit size:

- Negative size → allocated cell
- Positive size → free (unallocated) cell

Minimum cell size: 8 bytes (4-byte header + 4-byte alignment padding).

## Subkey indexing

| Signature | Structure | Introduced |
|-----------|-----------|------------|
| `li` | Index leaf | NT 3.1+ |
| `lf` | Fast leaf (name hints) | NT 4.0 (1.3+) |
| `lh` | Hash leaf | XP (1.5+) |
| `ri` | Index root | NT 3.1+ |

Parser resolves `ri` recursively via `collect_subkey_offsets()`. Leaf types return offsets directly.

## Key lookup

Case-insensitive name match (`to_uppercase()` comparison) for `open_key`, `open_subkey`, and `value`.

## Checksum

Base block checksum: XOR of first 508 bytes in 32-bit groups. Special cases: 0 → 1, 0xFFFFFFFF → 0xFFFFFFFE.

Implemented in `structures::calculate_checksum`.
