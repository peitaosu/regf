# Format reference

Condensed reference for the regf primary file format. Full specification: [Windows_registry_file_format_specification.md](Windows_registry_file_format_specification.md).

Implementation mapping uses `src/structures/` types.

## File layout

```
┌──────────────────┐  offset 0
│   Base block     │  4096 bytes
├──────────────────┤  offset 4096
│   Hive bin 0     │  variable (multiple of 4096)
├──────────────────┤
│   Hive bin 1     │
├──────────────────┤
│   ...            │
└──────────────────┘
```

## Base block

| Field | Offset | Type | Rust type |
|-------|--------|------|-----------|
| Signature | 0 | char[4] | `"regf"` |
| Primary sequence | 4 | uint32 | `sequence1` |
| Secondary sequence | 8 | uint32 | `sequence2` |
| Last modification | 12 | FILETIME | `last_written` |
| Major version | 24 | uint32 | `major_version` |
| Minor version | 28 | uint32 | `minor_version` |
| File type | 32 | uint32 | `FileType::Primary` (0) |
| File format | 36 | uint32 | `FileFormat::DirectMemoryLoad` (1) |
| Root cell offset | 44 | uint32 | `root_cell_offset` |
| Hive bins data size | 48 | uint32 | `hive_bins_data_size` |
| Clustering factor | 52 | uint32 | `clustering_factor` |
| File name | 56 | char[64] | UTF-16LE, null-padded |
| Checksum | 508 | uint32 | XOR-32 |
| Flags | 512+ | uint32 | `BaseBlockFlags` (1.6) |

Type: `structures::BaseBlock`

Dirty state: `sequence1 != sequence2`.

## Hive bin

| Field | Offset | Type |
|-------|--------|------|
| Signature | 0 | `"hbin"` |
| Offset in file | 4 | uint32 |
| Size | 8 | uint32 |
| Reserved | 12 | uint32 |
| Timestamp | 16 | FILETIME |
| Cells | 32+ | variable |

Type: `structures::HiveBin`, header in `HiveBinHeader`.

## Cell header

| Field | Size | Description |
|-------|------|-------------|
| Size | 4 | Signed; negative = allocated |
| Signature | 2 | Cell type (if allocated) |
| Data | n | Type-specific payload |

Type: `structures::RawCell`, `CellType` enum.

## Cell types

| Sig | Name | Rust parser |
|-----|------|-------------|
| `nk` | Key node | `KeyNode` |
| `vk` | Key value | `KeyValue` |
| `sk` | Security | `KeySecurity` |
| `lf` | Fast leaf | `FastLeaf` |
| `lh` | Hash leaf | `HashLeaf` |
| `li` | Index leaf | `IndexLeaf` |
| `ri` | Index root | `IndexRoot` |
| `db` | Big data | `BigData` |

## Key node (nk)

Core fields parsed by `KeyNode::parse`:

| Field | Description |
|-------|-------------|
| Flags | Key flags, virtualization, layered keys |
| Last written | FILETIME |
| Access bits | Access control hint |
| Parent offset | Parent nk cell |
| Num subkeys | Subkey count |
| Subkeys list offset | lf/lh/li/ri cell |
| Num values | Value count |
| Values list offset | List of vk offsets |
| Key name length | Name byte length |
| Class name offset/length | Optional class name cell |
| Security offset | sk cell |
| Key name | UTF-16LE inline |

## Key value (vk)

| Field | Description |
|-------|-------------|
| Name length | Value name length |
| Data size | Size or inline data encoding |
| Data offset | Cell offset or inline |
| Data type | REG_* constant |
| Flags | Value flags |
| Name | UTF-16LE inline |

Data size high bit indicates inline storage (≤ 4 bytes in offset field).

Big data threshold: **16344 bytes** (`BIG_DATA_THRESHOLD`).

## Big data (db)

For values exceeding inline/single-cell capacity:

```
BigData → DataSegmentsList → [segment cells...]
```

Types: `BigData`, `DataSegmentsList`. Max segment: 16344 bytes.

## Unallocated cells

Positive size in cell header. No signature. Skipped during traversal.

## Version-specific features

| Feature | Min version |
|---------|-------------|
| 8-byte cell alignment | 1.3 |
| Fast leaf (lf) | 1.3 |
| Hash leaf (lh) | 1.5 |
| Big data (db) | 1.4 |
| Extended base block fields | 1.6 |
| Layered keys | 1.6 + flags |

## Constants

```rust
REGF_SIGNATURE     // b"regf"
HBIN_SIGNATURE     // b"hbin"
BASE_BLOCK_SIZE    // 4096
MIN_HIVE_BIN_SIZE  // 4096
INVALID_OFFSET     // 0xFFFFFFFF
BIG_DATA_THRESHOLD // 16344
MARVIN32_SEED      // 0xC5554E7A884DEF82
```

Defined in `structures/mod.rs`.
