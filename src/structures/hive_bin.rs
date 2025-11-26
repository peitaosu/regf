//! Hive bin structure.
//!
//! Hive bins contain the actual registry data (cells).
//!
//! # Hive Bin Structure
//!
//! Each hive bin consists of a 32-byte header followed by cells.
//! Hive bins are always a multiple of 4096 bytes in size.
//!
//! # Timestamp Field
//!
//! The `timestamp` field in the hive bin header is only defined for the
//! **first hive bin** in a hive. For the first bin, it acts as a backup copy
//! of the `last_written` timestamp from the base block. This can be used
//! during recovery if the base block is corrupted.
//!
//! For other hive bins, this field contains undefined/remnant data.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::{HBIN_SIGNATURE, MIN_HIVE_BIN_SIZE};

/// Header size of a hive bin.
pub const HIVE_BIN_HEADER_SIZE: usize = 32;

/// Hive bin header structure.
#[derive(Debug, Clone)]
pub struct HiveBinHeader {
    /// Signature: "hbin"
    pub signature: [u8; 4],
    /// Offset of this hive bin relative to start of hive bins data.
    pub offset: u32,
    /// Size of this hive bin in bytes (multiple of 4096).
    pub size: u32,
    /// Reserved bytes.
    pub reserved: [u8; 8],
    /// Timestamp (FILETIME).
    /// **Note**: This field is only defined for the first hive bin,
    /// where it acts as a backup of the `last_written` timestamp.
    /// For other bins, this field may contain undefined/remnant data.
    pub timestamp: u64,
    /// Spare/MemAlloc (no meaning on disk).
    /// In Windows 2000, this field was called MemAlloc and used for memory tracking.
    /// It is used when shifting hive bins and cells in memory.
    pub spare: u32,
}

impl HiveBinHeader {
    /// Parse a hive bin header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HIVE_BIN_HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: HIVE_BIN_HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;

        if &signature != HBIN_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: String::from_utf8_lossy(HBIN_SIGNATURE).to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let offset = cursor.read_u32::<LittleEndian>()?;
        let size = cursor.read_u32::<LittleEndian>()?;

        // Validate size
        if (size as usize) < MIN_HIVE_BIN_SIZE || size % 4096 != 0 {
            return Err(Error::InvalidHiveBin {
                offset,
                message: format!("Invalid size: {} (must be multiple of 4096)", size),
            });
        }

        let mut reserved = [0u8; 8];
        cursor.read_exact(&mut reserved)?;

        let timestamp = cursor.read_u64::<LittleEndian>()?;
        let spare = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            signature,
            offset,
            size,
            reserved,
            timestamp,
            spare,
        })
    }

    /// Write the hive bin header to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u32::<LittleEndian>(self.offset)?;
        writer.write_u32::<LittleEndian>(self.size)?;
        writer.write_all(&self.reserved)?;
        writer.write_u64::<LittleEndian>(self.timestamp)?;
        writer.write_u32::<LittleEndian>(self.spare)?;
        Ok(())
    }

    /// Create a new hive bin header.
    pub fn new(offset: u32, size: u32) -> Self {
        Self {
            signature: *HBIN_SIGNATURE,
            offset,
            size,
            reserved: [0; 8],
            timestamp: 0,
            spare: 0,
        }
    }
}

/// A hive bin containing the header and raw cell data.
#[derive(Debug, Clone)]
pub struct HiveBin {
    /// The hive bin header.
    pub header: HiveBinHeader,
    /// Raw cell data (excluding header).
    pub data: Vec<u8>,
}

impl HiveBin {
    /// Parse a hive bin from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = HiveBinHeader::parse(data)?;

        let bin_size = header.size as usize;
        if data.len() < bin_size {
            return Err(Error::BufferTooSmall {
                needed: bin_size,
                available: data.len(),
            });
        }

        let cell_data = data[HIVE_BIN_HEADER_SIZE..bin_size].to_vec();

        Ok(Self {
            header,
            data: cell_data,
        })
    }

    /// Write the hive bin to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.header.write(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    /// Create a new empty hive bin.
    pub fn new(offset: u32, size: u32) -> Self {
        let header = HiveBinHeader::new(offset, size);

        // Create cell data with a single unallocated cell
        let cell_data_size = size as usize - HIVE_BIN_HEADER_SIZE;
        let mut data = vec![0u8; cell_data_size];

        // Write the size of the unallocated cell (positive = unallocated)
        let cell_size = cell_data_size as i32;
        data[0..4].copy_from_slice(&cell_size.to_le_bytes());

        Self { header, data }
    }

    /// Get the total size of this hive bin.
    pub fn size(&self) -> u32 {
        self.header.size
    }

    /// Get the offset of this hive bin.
    pub fn offset(&self) -> u32 {
        self.header.offset
    }

    /// Check if this is the first hive bin (offset == 0).
    /// The timestamp field is only valid for the first hive bin.
    pub fn is_first_bin(&self) -> bool {
        self.header.offset == 0
    }

    /// Get the backup timestamp (only valid for the first hive bin).
    /// Returns None if this is not the first bin.
    pub fn get_backup_timestamp(&self) -> Option<u64> {
        if self.is_first_bin() {
            Some(self.header.timestamp)
        } else {
            None
        }
    }

    /// Calculate the file offset for a cell offset within this bin.
    pub fn cell_file_offset(&self, cell_offset: u32) -> u64 {
        // Cell offset is relative to start of hive bins data
        // File offset = base block size (4096) + cell offset
        4096 + cell_offset as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_hive_bin() {
        let bin = HiveBin::new(0, 4096);
        assert_eq!(bin.size(), 4096);
        assert_eq!(bin.offset(), 0);
        assert_eq!(bin.data.len(), 4096 - HIVE_BIN_HEADER_SIZE);
    }

    #[test]
    fn test_hive_bin_roundtrip() {
        let bin = HiveBin::new(0, 4096);

        let mut buffer = Vec::new();
        bin.write(&mut buffer).unwrap();

        let parsed = HiveBin::parse(&buffer).unwrap();
        assert_eq!(parsed.size(), bin.size());
        assert_eq!(parsed.offset(), bin.offset());
    }
}

