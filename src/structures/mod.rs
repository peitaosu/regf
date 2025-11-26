//! Binary structures for the Windows Registry file format.
//!
//! This module contains all the low-level structures that make up a registry hive file.
//!
//! # Version History
//!
//! The regf format has evolved over Windows versions:
//!
//! | Version | Windows | Notes |
//! |---------|---------|-------|
//! | 1.1 | NT 3.1 | Initial version, 16-byte cell alignment, `Last` field in cells |
//! | 1.2 | NT 3.5 | No Fast Leaf support |
//! | 1.3 | NT 4.0 | Fast Leaf introduced, 8-byte cell alignment |
//! | 1.4 | 2000 | - |
//! | 1.5 | XP | Hash Leaf introduced, Big Data support |
//! | 1.6 | Vista+ | Current format, additional base block fields |
//!
//! This crate primarily supports versions 1.3-1.6. Versions 1.1-1.2 have a different
//! cell structure and may not parse correctly.
//!
//! # Cell Alignment
//!
//! - Version 1.1: Cells aligned to 16 bytes, have `Last` field pointing to previous cell
//! - Version 1.2+: Cells aligned to 8 bytes, no `Last` field
//!
//! # Feature Availability by Version
//!
//! - **Fast Leaf (lf)**: Version 1.3+ (uses name hints for quick lookups)
//! - **Hash Leaf (lh)**: Version 1.5+ (uses name hashes for quick lookups)
//! - **Big Data (db)**: Version 1.4+ (for values > 16344 bytes)

mod base_block;
mod hive_bin;
mod cell;
mod key_node;
mod key_value;
mod key_security;
mod subkeys_list;
mod big_data;
mod data_types;

pub use base_block::*;
pub use hive_bin::*;
pub use cell::*;
pub use key_node::*;
pub use key_value::*;
pub use key_security::*;
pub use subkeys_list::*;
pub use big_data::*;
pub use data_types::*;

/// Signature for the regf file format.
pub const REGF_SIGNATURE: &[u8; 4] = b"regf";

/// Signature for hive bins.
pub const HBIN_SIGNATURE: &[u8; 4] = b"hbin";

/// Size of the base block (file header).
pub const BASE_BLOCK_SIZE: usize = 4096;

/// Minimum hive bin size.
pub const MIN_HIVE_BIN_SIZE: usize = 4096;

/// Invalid cell offset marker.
pub const INVALID_OFFSET: u32 = 0xFFFFFFFF;

/// Maximum data size before big data is used.
pub const BIG_DATA_THRESHOLD: usize = 16344;

/// Maximum size of a single data segment in big data.
pub const MAX_DATA_SEGMENT_SIZE: usize = 16344;

/// Convert a Windows FILETIME to a chrono DateTime.
pub fn filetime_to_datetime(filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    // FILETIME is 100-nanosecond intervals since January 1, 1601
    // Unix epoch is January 1, 1970
    // Difference is 11644473600 seconds
    const FILETIME_UNIX_DIFF: u64 = 116444736000000000;

    if filetime < FILETIME_UNIX_DIFF {
        return None;
    }

    let unix_100ns = filetime - FILETIME_UNIX_DIFF;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nsecs = ((unix_100ns % 10_000_000) * 100) as u32;

    chrono::DateTime::from_timestamp(secs, nsecs)
}

/// Convert a chrono DateTime to a Windows FILETIME.
pub fn datetime_to_filetime(dt: chrono::DateTime<chrono::Utc>) -> u64 {
    const FILETIME_UNIX_DIFF: u64 = 116444736000000000;

    let unix_100ns = (dt.timestamp() as u64) * 10_000_000
        + (dt.timestamp_subsec_nanos() as u64) / 100;

    unix_100ns + FILETIME_UNIX_DIFF
}

/// Calculate the XOR-32 checksum as specified in the regf format.
pub fn calculate_checksum(data: &[u8]) -> u32 {
    assert!(data.len() >= 508);

    let mut checksum: u32 = 0;

    // XOR each 32-bit group
    for chunk in data[..508].chunks_exact(4) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        checksum ^= value;
    }

    // Special cases
    if checksum == 0xFFFFFFFF {
        checksum = 0xFFFFFFFE;
    } else if checksum == 0 {
        checksum = 1;
    }

    checksum
}

/// Calculate Marvin32 hash (used in new format transaction logs).
pub fn marvin32_hash(data: &[u8], seed: u64) -> u64 {
    let mut lo = seed as u32;
    let mut hi = (seed >> 32) as u32;

    let len = data.len();
    let mut offset = 0;

    // Process 4-byte blocks
    while offset + 4 <= len {
        let block = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        lo = lo.wrapping_add(block);
        hi ^= lo;
        lo = lo.rotate_left(20).wrapping_add(hi);
        hi = hi.rotate_left(9) ^ lo;
        lo = lo.rotate_left(27).wrapping_add(hi);
        hi = hi.rotate_left(19);

        offset += 4;
    }

    // Process remaining bytes
    let remaining = len - offset;
    let mut final_block: u32 = 0x80;

    match remaining {
        3 => {
            final_block = (data[offset + 2] as u32) << 16
                | (data[offset + 1] as u32) << 8
                | (data[offset] as u32)
                | 0x80000000;
        }
        2 => {
            final_block = (data[offset + 1] as u32) << 8 | (data[offset] as u32) | 0x800000;
        }
        1 => {
            final_block = (data[offset] as u32) | 0x8000;
        }
        0 => {}
        _ => unreachable!(),
    }

    lo = lo.wrapping_add(final_block);
    hi ^= lo;
    lo = lo.rotate_left(20).wrapping_add(hi);
    hi = hi.rotate_left(9) ^ lo;
    lo = lo.rotate_left(27).wrapping_add(hi);
    hi = hi.rotate_left(19);

    // Final mix
    lo = lo.wrapping_add(0);
    hi ^= lo;
    lo = lo.rotate_left(20).wrapping_add(hi);
    hi = hi.rotate_left(9) ^ lo;
    lo = lo.rotate_left(27).wrapping_add(hi);
    hi = hi.rotate_left(19);

    ((hi as u64) << 32) | (lo as u64)
}

/// Marvin32 seed used in regf transaction logs.
pub const MARVIN32_SEED: u64 = 0xC5554E7A884DEF82;

/// Calculate hash for a key name (used in hash leaf).
pub fn calculate_name_hash(name: &str) -> u32 {
    let uppercase = name.to_uppercase();
    let mut hash: u32 = 0;

    for c in uppercase.chars() {
        // Use wide character (UTF-16) code
        let code = c as u32;
        hash = hash.wrapping_mul(37).wrapping_add(code);
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let mut data = vec![0u8; 512];
        // Set some test values
        for i in 0..127 {
            let offset = i * 4;
            data[offset..offset + 4].copy_from_slice(&(i as u32).to_le_bytes());
        }

        let checksum = calculate_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_name_hash() {
        // Test known hash values
        let hash = calculate_name_hash("Test");
        assert!(hash != 0);

        // Hash should be case-insensitive
        assert_eq!(calculate_name_hash("test"), calculate_name_hash("TEST"));
    }

    #[test]
    fn test_filetime_conversion() {
        use chrono::{TimeZone, Utc};

        // Test a known date
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let filetime = datetime_to_filetime(dt);

        let converted = filetime_to_datetime(filetime).unwrap();
        assert_eq!(dt, converted);
    }
}

