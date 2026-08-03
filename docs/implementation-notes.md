# Implementation notes

## Spec source

This crate implements structures and behavior described in:

[Windows_registry_file_format_specification.md](Windows_registry_file_format_specification.md)

## Version support matrix

| Capability | 1.1–1.2 | 1.3 | 1.4 | 1.5 | 1.6 |
|------------|---------|-----|-----|-----|-----|
| Parse primary file | no | yes | yes | yes | yes |
| Write primary file | no | partial | partial | yes | yes |
| Fast leaf | — | yes | yes | yes | yes |
| Hash leaf | — | — | — | yes | yes |
| Big data read | — | — | yes | yes | yes |
| Big data write | — | — | — | yes | yes |
| Transaction log parse | — | — | — | yes | yes |
| Dirty hive recovery | no | no | no | no | no |

Parser entry check (`parser.rs`):

```rust
if base_block.major_version != 1 || base_block.minor_version < 3 {
    return Err(Error::UnsupportedVersion { ... });
}
```

## Implemented

### Primary files

- Base block read/write with checksum validation
- Hive bin iteration and cell map
- All standard cell types: nk, vk, sk, li, lf, lh, ri, db
- Subkey list recursion through index root
- Value data: inline, cell-resident, big data chains
- Key security descriptor cells (parse only; not written by HiveBuilder)
- FILETIME ↔ chrono conversion
- Name hash for lh cells (`calculate_name_hash`)
- Offline registry signature detection (`OfRg` in base block)

### High-level API

- Path-based key open
- Subkey and value enumeration
- Default value access
- Class name read
- Full key path reconstruction
- Hive creation from scratch
- Incremental and tree-based hive writing

### Reg text

- Version 5.00 export with UTF-16LE BOM
- Import with prefix stripping, root naming
- Line continuation in reg parser
- Hex, dword, string value syntax

### Transaction logs

- Old format: dirty vector + dirty pages
- New format: log entries with Marvin32 hash
- Auto-detection by file type field
- Parse only; no log replay onto primary file

## Not implemented

| Feature | Notes |
|---------|-------|
| NT 3.1/3.5 hives (1.1–1.2) | Different cell layout with `Last` field |
| Log replay / recovery | `TransactionLog` parses but does not apply dirty pages |
| KTM / transactional registry | TxR hive states not handled |
| In-place hive modification | Read-focused; changes require rewrite via HiveBuilder |
| Security descriptor authoring | Default SD not attached on write |
| Defragmentation | No hive compaction |
| Layered key semantics | Flags parsed; layering logic not applied |
| REG_LINK following | Link type recognized, not dereferenced |
| Resource list types | Stored as raw bytes only |

## Write behavior

`HiveBuilder` creates minimal valid hives:

- Default minor version: 6 (Windows 10 era)
- Subkey lists use lf or lh depending on count thresholds in writer
- Checksum recalculated on finalize
- Sequence numbers set equal (clean hive)
- Single initial hive bin; grows as needed

Security cells are omitted on newly written keys unless extended by caller.

## Error handling

Strict validation on:

- Signature mismatch
- Checksum mismatch (optional enforcement in parser paths)
- Invalid cell offsets and sizes
- Unallocated cell dereference
- UTF-16 decode failures

Case-insensitive key/value lookup may return first match if duplicates exist (non-standard; Windows prevents duplicates).

## Testing

Unit tests in:

- `structures/mod.rs` — checksum, hash, FILETIME
- `parser.rs` — minimal hive roundtrip
- `transaction_log.rs` — dirty vector bitmap
- `writer.rs` — hive construction
- `reg_export.rs`, `reg_import.rs` — text format

Integration examples in `examples/` directory.

## Interoperability

Hives written by `regf` load in:

- Windows Offline Registry (offreg)
- This crate's parser
- `regdat` tool (via offreg)

Verify cross-tool compatibility when mixing `regf` output with `regdat` workflows.
