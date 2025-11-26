//! Cell structures.
//!
//! Cells are the basic building blocks of registry data within hive bins.
//!
//! # Cell Structure
//!
//! A cell consists of:
//! - Size field (4 bytes, i32): Negative if allocated, positive if free
//! - Cell data: Variable length
//!
//! # Version Differences
//!
//! ## Version 1.2+ (NT 3.5 and later)
//! - Cells aligned to 8 bytes
//! - Cell structure: `[Size (4)] [Data ...]`
//!
//! ## Version 1.1 (NT 3.1)
//! - Cells aligned to 16 bytes
//! - Cell structure: `[Size (4)] [Last (4)] [Data ...]`
//! - `Last` field points to previous cell in the bin (or 0xFFFFFFFF for first cell)
//!
//! This crate primarily supports version 1.2+ cell structure.
//!
//! # Unallocated Cell Free Lists
//!
//! When a cell is unallocated (free), its data area may contain free list pointers:
//!
//! ## Windows 2000
//! ```text
//! Offset | Length | Field | Description
//! 0      | 4      | Next  | Offset to next unallocated cell in free list (or 0xFFFFFFFF)
//! ```
//!
//! ## Windows NT 3.1 (Version 1.1)
//! ```text
//! Offset | Length | Field    | Description
//! 0      | 4      | Next     | Offset to next unallocated cell (or 0xFFFFFFFF)
//! 4      | 4      | Previous | Offset to previous unallocated cell (or 0xFFFFFFFF)
//! ```
//!
//! These free list structures are not used in Windows XP and later versions.
//! The free list pointers are relative offsets from the start of hive bins data.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Write};

use crate::error::{Error, Result};

/// Minimum cell size (size field + minimal content).
pub const MIN_CELL_SIZE: usize = 8;

/// Cell alignment for version 1.2+ (cells are aligned to 8 bytes).
pub const CELL_ALIGNMENT: usize = 8;

/// Cell alignment for version 1.1 (cells are aligned to 16 bytes).
pub const CELL_ALIGNMENT_V1_1: usize = 16;

/// Cell signatures.
pub mod signatures {
    /// Key node signature.
    pub const KEY_NODE: &[u8; 2] = b"nk";
    /// Key value signature.
    pub const KEY_VALUE: &[u8; 2] = b"vk";
    /// Key security signature.
    pub const KEY_SECURITY: &[u8; 2] = b"sk";
    /// Index leaf signature.
    pub const INDEX_LEAF: &[u8; 2] = b"li";
    /// Fast leaf signature.
    pub const FAST_LEAF: &[u8; 2] = b"lf";
    /// Hash leaf signature.
    pub const HASH_LEAF: &[u8; 2] = b"lh";
    /// Index root signature.
    pub const INDEX_ROOT: &[u8; 2] = b"ri";
    /// Big data signature.
    pub const BIG_DATA: &[u8; 2] = b"db";
}

/// Cell type based on signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    /// Key node (nk).
    KeyNode,
    /// Key value (vk).
    KeyValue,
    /// Key security (sk).
    KeySecurity,
    /// Index leaf (li).
    IndexLeaf,
    /// Fast leaf (lf).
    FastLeaf,
    /// Hash leaf (lh).
    HashLeaf,
    /// Index root (ri).
    IndexRoot,
    /// Big data (db).
    BigData,
    /// Unknown or raw data.
    Unknown,
}

impl CellType {
    /// Determine cell type from signature bytes.
    pub fn from_signature(sig: &[u8; 2]) -> Self {
        match sig {
            b"nk" => CellType::KeyNode,
            b"vk" => CellType::KeyValue,
            b"sk" => CellType::KeySecurity,
            b"li" => CellType::IndexLeaf,
            b"lf" => CellType::FastLeaf,
            b"lh" => CellType::HashLeaf,
            b"ri" => CellType::IndexRoot,
            b"db" => CellType::BigData,
            _ => CellType::Unknown,
        }
    }

    /// Get the signature bytes for this cell type.
    pub fn signature(&self) -> Option<&'static [u8; 2]> {
        match self {
            CellType::KeyNode => Some(signatures::KEY_NODE),
            CellType::KeyValue => Some(signatures::KEY_VALUE),
            CellType::KeySecurity => Some(signatures::KEY_SECURITY),
            CellType::IndexLeaf => Some(signatures::INDEX_LEAF),
            CellType::FastLeaf => Some(signatures::FAST_LEAF),
            CellType::HashLeaf => Some(signatures::HASH_LEAF),
            CellType::IndexRoot => Some(signatures::INDEX_ROOT),
            CellType::BigData => Some(signatures::BIG_DATA),
            CellType::Unknown => None,
        }
    }
}

/// A raw cell with its metadata.
#[derive(Debug, Clone)]
pub struct RawCell {
    /// Size of the cell (negative if allocated, positive if unallocated).
    pub size: i32,
    /// Cell data (excluding size field).
    pub data: Vec<u8>,
    /// Offset of this cell relative to hive bins data.
    pub offset: u32,
}

impl RawCell {
    /// Parse a cell from a byte slice at the given offset.
    pub fn parse(data: &[u8], offset: u32) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooSmall {
                needed: 4,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let size = cursor.read_i32::<LittleEndian>()?;

        let abs_size = size.abs() as usize;

        if abs_size < MIN_CELL_SIZE {
            return Err(Error::InvalidCellSize(size));
        }

        if data.len() < abs_size {
            return Err(Error::BufferTooSmall {
                needed: abs_size,
                available: data.len(),
            });
        }

        // Cell data is everything after the size field
        let cell_data = data[4..abs_size].to_vec();

        Ok(Self {
            size,
            data: cell_data,
            offset,
        })
    }

    /// Check if this cell is allocated.
    pub fn is_allocated(&self) -> bool {
        self.size < 0
    }

    /// Get the absolute size of this cell.
    pub fn abs_size(&self) -> usize {
        self.size.abs() as usize
    }

    /// Get the data size (excluding size field).
    pub fn data_size(&self) -> usize {
        self.abs_size().saturating_sub(4)
    }

    /// Get the cell type based on signature.
    pub fn cell_type(&self) -> CellType {
        if self.data.len() < 2 {
            return CellType::Unknown;
        }

        let sig: [u8; 2] = [self.data[0], self.data[1]];
        CellType::from_signature(&sig)
    }

    /// Write the cell to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_i32::<LittleEndian>(self.size)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    /// Create a new allocated cell with the given data.
    pub fn new_allocated(data: Vec<u8>, offset: u32) -> Self {
        // Calculate aligned size
        let total_size = 4 + data.len(); // size field + data
        let aligned_size = (total_size + CELL_ALIGNMENT - 1) & !(CELL_ALIGNMENT - 1);
        let padded_data_len = aligned_size - 4;

        let mut padded_data = data;
        padded_data.resize(padded_data_len, 0);

        Self {
            size: -(aligned_size as i32),
            data: padded_data,
            offset,
        }
    }

    /// Create a new unallocated (free) cell.
    pub fn new_unallocated(size: usize, offset: u32) -> Self {
        let aligned_size = (size + CELL_ALIGNMENT - 1) & !(CELL_ALIGNMENT - 1);
        let data_size = aligned_size - 4;

        Self {
            size: aligned_size as i32,
            data: vec![0; data_size],
            offset,
        }
    }

    /// Mark this cell as allocated.
    pub fn allocate(&mut self) {
        if self.size > 0 {
            self.size = -self.size;
        }
    }

    /// Mark this cell as unallocated.
    pub fn deallocate(&mut self) {
        if self.size < 0 {
            self.size = -self.size;
        }
    }
}

/// Align a size to cell alignment.
pub fn align_cell_size(size: usize) -> usize {
    (size + CELL_ALIGNMENT - 1) & !(CELL_ALIGNMENT - 1)
}

/// Calculate the required cell size for given data.
pub fn required_cell_size(data_len: usize) -> usize {
    align_cell_size(4 + data_len) // 4 bytes for size field
}

/// Free list entry for unallocated cells (Windows 2000 format).
/// This is stored in the data area of unallocated cells.
#[derive(Debug, Clone, Copy)]
pub struct FreeListEntry {
    /// Offset to next unallocated cell in free list (or 0xFFFFFFFF if none).
    pub next: u32,
}

impl FreeListEntry {
    /// Parse a free list entry from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let next = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        Some(Self { next })
    }

    /// Check if there is a next entry in the free list.
    pub fn has_next(&self) -> bool {
        self.next != 0xFFFFFFFF
    }
}

/// Free list entry for unallocated cells (Windows NT 3.1 / version 1.1 format).
/// This is stored in the data area of unallocated cells in version 1.1 hives.
#[derive(Debug, Clone, Copy)]
pub struct FreeListEntryV1 {
    /// Offset to next unallocated cell in free list (or 0xFFFFFFFF if none).
    pub next: u32,
    /// Offset to previous unallocated cell in free list (or 0xFFFFFFFF if none).
    pub previous: u32,
}

impl FreeListEntryV1 {
    /// Parse a version 1.1 free list entry from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let next = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let previous = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Some(Self { next, previous })
    }

    /// Check if there is a next entry in the free list.
    pub fn has_next(&self) -> bool {
        self.next != 0xFFFFFFFF
    }

    /// Check if there is a previous entry in the free list.
    pub fn has_previous(&self) -> bool {
        self.previous != 0xFFFFFFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_alignment() {
        assert_eq!(align_cell_size(1), 8);
        assert_eq!(align_cell_size(8), 8);
        assert_eq!(align_cell_size(9), 16);
        assert_eq!(align_cell_size(16), 16);
    }

    #[test]
    fn test_cell_type_detection() {
        assert_eq!(CellType::from_signature(b"nk"), CellType::KeyNode);
        assert_eq!(CellType::from_signature(b"vk"), CellType::KeyValue);
        assert_eq!(CellType::from_signature(b"??"), CellType::Unknown);
    }

    #[test]
    fn test_raw_cell() {
        let cell = RawCell::new_allocated(vec![b'n', b'k', 0, 0], 0);
        assert!(cell.is_allocated());
        assert_eq!(cell.cell_type(), CellType::KeyNode);
    }
}

