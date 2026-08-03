# Transaction logs

Transaction log files provide fault-tolerant writes to primary hive files. Before modifying a primary file, the hive writer stores dirty data in log files.

Spec reference: [Format of transaction log files](Windows_registry_file_format_specification.md#format-of-transaction-log-files).

## File types

Detected via base block `file type` field at offset 32:

| Value | Format | Windows |
|-------|--------|---------|
| 1 | Old | XP+ |
| 2 | Old (legacy) | NT/2000 |
| 6 | New | 8.1+ |

Implementation: `transaction_log::TransactionLog::parse`.

## Typical hive file set

```
SYSTEM          Primary
SYSTEM.LOG      Active log
SYSTEM.LOG1     First spare
SYSTEM.LOG2     Second spare
```

Only one log is active at a time. Rotation uses LOG1/LOG2.

## Old format

Type: `OldFormatLog`

```
┌─────────────────────────┐
│ Base block (partial)    │  Clustering factor × 512 bytes
├─────────────────────────┤
│ Dirty vector ("DIRT")   │  Bitmap of dirty 512-byte pages
├─────────────────────────┤
│ Dirty pages             │  Page data for set bits
└─────────────────────────┘
```

### DirtyVector

- Signature: `DIRT`
- Bitmap: one bit per 512-byte page of primary file
- Methods: `is_page_dirty(index)`, `dirty_page_count()`, `set_page_dirty()`

### DirtyPage

- Page index
- Raw 512-byte page content

## New format

Type: `NewFormatLog`

```
┌─────────────────────────┐
│ Base block              │  Full 4096 bytes
├─────────────────────────┤
│ Log entries             │  Sequence of LogEntry
└─────────────────────────┘
```

### LogEntry

| Field | Description |
|-------|-------------|
| Size | Entry size |
| Flags | Entry flags |
| Hash | Marvin32 of entry body |
| Sequence | Sequence number |
| Dirty pages | List of page references |

Hash seed: `MARVIN32_SEED` (`0xC5554E7A884DEF82`).

Implementation: `structures::marvin32_hash`.

### DirtyPageReference

- Page index in primary file
- Inline page data or offset

## Dirty state

Primary hive is dirty when `sequence1 != sequence2` in base block.

`RegistryHive::is_dirty()` exposes this.

Recovery requires replaying log entries over the primary file. **This crate parses logs but does not perform recovery.**

## Multiple log files

Windows maintains LOG, LOG1, LOG2 with rotation. Parser operates on a single log file stream. Selecting the correct active log for recovery is caller responsibility.

## Usage

```rust
use regf::TransactionLog;
use std::fs::File;

let file = File::open("SYSTEM.LOG")?;
let log = TransactionLog::parse(file)?;

match log {
    TransactionLog::Old(old) => {
        let dirty_count = old.dirty_vector.dirty_page_count();
        // inspect old.dirty_pages
    }
    TransactionLog::New(new) => {
        // inspect new.entries
    }
}
```

## Flush strategies

Not implemented. Spec describes write-through and lazy flush behaviors tied to Windows kernel configuration. See spec section "Flush strategies".

## Sector size

Default sector size: 512 bytes. Clustering factor in base block determines log base block copy size (old format).
