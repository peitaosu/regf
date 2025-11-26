//! Transaction log file support.
//!
//! This module handles reading and writing transaction log files (.LOG, .LOG1, .LOG2).
//! Transaction logs are used for fault-tolerant writes to primary hive files.
//!
//! Two formats are supported:
//! - Old format (Windows XP - Windows 8): Dirty vector + dirty pages
//! - New format (Windows 8.1+): Log entries with Marvin32 hashes

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use crate::error::{Error, Result};
use crate::structures::{
    marvin32_hash, BaseBlock, BASE_BLOCK_SIZE, MARVIN32_SEED, REGF_SIGNATURE,
};

/// Old format transaction log file.
#[derive(Debug, Clone)]
pub struct OldFormatLog {
    /// Base block (partial backup, first Clustering factor * 512 bytes).
    pub base_block: BaseBlock,
    /// Dirty vector indicating which pages are dirty.
    pub dirty_vector: DirtyVector,
    /// Dirty pages data.
    pub dirty_pages: Vec<DirtyPage>,
}

/// Dirty vector for old format logs.
#[derive(Debug, Clone)]
pub struct DirtyVector {
    /// Signature: "DIRT"
    pub signature: [u8; 4],
    /// Bitmap of dirty pages (each bit represents a 512-byte page).
    pub bitmap: Vec<u8>,
}

impl DirtyVector {
    /// Signature for dirty vector.
    pub const SIGNATURE: &'static [u8; 4] = b"DIRT";

    /// Parse a dirty vector from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooSmall {
                needed: 4,
                available: data.len(),
            });
        }

        let mut signature = [0u8; 4];
        signature.copy_from_slice(&data[0..4]);

        if &signature != Self::SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "DIRT".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let bitmap = data[4..].to_vec();

        Ok(Self { signature, bitmap })
    }

    /// Check if a specific page is dirty.
    /// Page index is 0-based, corresponding to 512-byte pages.
    pub fn is_page_dirty(&self, page_index: usize) -> bool {
        let byte_index = page_index / 8;
        let bit_index = page_index % 8;

        if byte_index >= self.bitmap.len() {
            return false;
        }

        (self.bitmap[byte_index] >> bit_index) & 1 == 1
    }

    /// Get the number of dirty pages.
    pub fn dirty_page_count(&self) -> usize {
        self.bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Write the dirty vector to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_all(&self.bitmap)?;
        Ok(())
    }

    /// Create a new dirty vector with the given hive bins data size.
    pub fn new(hive_bins_data_size: u32) -> Self {
        let num_pages = (hive_bins_data_size / 512) as usize;
        let bitmap_len = (num_pages + 7) / 8;

        Self {
            signature: *Self::SIGNATURE,
            bitmap: vec![0u8; bitmap_len],
        }
    }

    /// Mark a page as dirty.
    pub fn set_page_dirty(&mut self, page_index: usize) {
        let byte_index = page_index / 8;
        let bit_index = page_index % 8;

        if byte_index >= self.bitmap.len() {
            self.bitmap.resize(byte_index + 1, 0);
        }

        self.bitmap[byte_index] |= 1 << bit_index;
    }
}

/// A dirty page from an old format log.
#[derive(Debug, Clone)]
pub struct DirtyPage {
    /// Offset in the primary file (relative to hive bins data).
    pub offset: u32,
    /// Page data (512 bytes).
    pub data: Vec<u8>,
}

impl OldFormatLog {
    /// Parse an old format transaction log from a reader.
    pub fn parse<R: Read + Seek>(mut reader: R) -> Result<Self> {
        // Read base block (may be partial)
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        reader.read_exact(&mut base_block_data)?;

        // Verify it's a transaction log
        if &base_block_data[0..4] != REGF_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "regf".to_string(),
                found: String::from_utf8_lossy(&base_block_data[0..4]).to_string(),
            });
        }

        // Parse base block (may fail checksum if partial)
        let base_block = BaseBlock::parse(&base_block_data)?;

        // Verify file type is transaction log
        if base_block.file_type != 1 && base_block.file_type != 2 {
            return Err(Error::CorruptHive(format!(
                "Not a transaction log file (type={})",
                base_block.file_type
            )));
        }

        // Read dirty vector from second sector (offset 512)
        reader.seek(SeekFrom::Start(512))?;
        let mut dirty_vector_data = vec![0u8; 4096]; // Read up to a sector
        reader.read_exact(&mut dirty_vector_data)?;

        let dirty_vector = DirtyVector::parse(&dirty_vector_data)?;

        // Calculate expected number of dirty pages
        let dirty_count = dirty_vector.dirty_page_count();

        // Read dirty pages starting after dirty vector
        // (aligned to 512-byte boundary)
        let dirty_vector_size = 4 + dirty_vector.bitmap.len();
        let dirty_pages_start = 512 + ((dirty_vector_size + 511) / 512) * 512;
        reader.seek(SeekFrom::Start(dirty_pages_start as u64))?;

        let mut dirty_pages = Vec::with_capacity(dirty_count);
        let mut page_index = 0;
        let num_pages = (dirty_vector.bitmap.len() * 8).min(
            base_block.hive_bins_data_size as usize / 512,
        );

        for i in 0..num_pages {
            if dirty_vector.is_page_dirty(i) {
                let mut page_data = vec![0u8; 512];
                if reader.read_exact(&mut page_data).is_ok() {
                    dirty_pages.push(DirtyPage {
                        offset: (i * 512) as u32,
                        data: page_data,
                    });
                }
                page_index += 1;
                if page_index >= dirty_count {
                    break;
                }
            }
        }

        Ok(Self {
            base_block,
            dirty_vector,
            dirty_pages,
        })
    }

    /// Check if this log can be applied to a primary file with the given timestamp.
    pub fn can_apply_to(&self, primary_timestamp: u64) -> bool {
        self.base_block.last_written == primary_timestamp
    }
}

/// New format transaction log file (Windows 8.1+).
#[derive(Debug, Clone)]
pub struct NewFormatLog {
    /// Base block (partial backup).
    pub base_block: BaseBlock,
    /// Log entries.
    pub log_entries: Vec<LogEntry>,
}

/// A log entry in a new format transaction log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Signature: "HvLE"
    pub signature: [u8; 4],
    /// Size of this log entry in bytes.
    pub size: u32,
    /// Flags (partial copy of base block flags).
    pub flags: u32,
    /// Sequence number.
    pub sequence_number: u32,
    /// Hive bins data size at time of creation.
    pub hive_bins_data_size: u32,
    /// Number of dirty pages in this entry.
    pub dirty_pages_count: u32,
    /// Hash-1 (Marvin32 hash of page references + dirty pages).
    pub hash1: u64,
    /// Hash-2 (Marvin32 hash of first 32 bytes including hash1).
    pub hash2: u64,
    /// Dirty page references.
    pub page_references: Vec<DirtyPageReference>,
    /// Dirty pages data.
    pub dirty_pages: Vec<Vec<u8>>,
}

/// Reference to a dirty page in a new format log entry.
#[derive(Debug, Clone)]
pub struct DirtyPageReference {
    /// Offset of page in primary file (relative to hive bins data).
    pub offset: u32,
    /// Size of page in bytes.
    pub size: u32,
}

impl LogEntry {
    /// Signature for log entries.
    pub const SIGNATURE: &'static [u8; 4] = b"HvLE";
    /// Header size (fixed part before page references).
    pub const HEADER_SIZE: usize = 40;

    /// Parse a log entry from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;

        if &signature != Self::SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "HvLE".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let size = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let sequence_number = cursor.read_u32::<LittleEndian>()?;
        let hive_bins_data_size = cursor.read_u32::<LittleEndian>()?;
        let dirty_pages_count = cursor.read_u32::<LittleEndian>()?;
        let hash1 = cursor.read_u64::<LittleEndian>()?;
        let hash2 = cursor.read_u64::<LittleEndian>()?;

        // Verify hive bins data size is valid
        if hive_bins_data_size % 4096 != 0 {
            return Err(Error::CorruptHive(format!(
                "Invalid hive bins data size in log entry: {}",
                hive_bins_data_size
            )));
        }

        // Read page references
        let mut page_references = Vec::with_capacity(dirty_pages_count as usize);
        for _ in 0..dirty_pages_count {
            let offset = cursor.read_u32::<LittleEndian>()?;
            let page_size = cursor.read_u32::<LittleEndian>()?;
            page_references.push(DirtyPageReference {
                offset,
                size: page_size,
            });
        }

        // Read dirty pages
        let mut dirty_pages = Vec::with_capacity(dirty_pages_count as usize);
        for ref_entry in &page_references {
            let pos = cursor.position() as usize;
            let end = pos + ref_entry.size as usize;

            if end > data.len() {
                return Err(Error::BufferTooSmall {
                    needed: end,
                    available: data.len(),
                });
            }

            dirty_pages.push(data[pos..end].to_vec());
            cursor.set_position(end as u64);
        }

        // Verify Hash-1
        let hash_data = &data[Self::HEADER_SIZE..size as usize];
        let calculated_hash1 = marvin32_hash(hash_data, MARVIN32_SEED);
        if hash1 != calculated_hash1 {
            return Err(Error::ChecksumMismatch {
                expected: hash1 as u32,
                calculated: calculated_hash1 as u32,
            });
        }

        // Verify Hash-2
        let calculated_hash2 = marvin32_hash(&data[0..32], MARVIN32_SEED);
        if hash2 != calculated_hash2 {
            return Err(Error::ChecksumMismatch {
                expected: hash2 as u32,
                calculated: calculated_hash2 as u32,
            });
        }

        Ok(Self {
            signature,
            size,
            flags,
            sequence_number,
            hive_bins_data_size,
            dirty_pages_count,
            hash1,
            hash2,
            page_references,
            dirty_pages,
        })
    }

    /// Write the log entry to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buffer = Vec::new();

        // Write header (without hashes initially)
        buffer.write_all(&self.signature)?;
        buffer.write_u32::<LittleEndian>(self.size)?;
        buffer.write_u32::<LittleEndian>(self.flags)?;
        buffer.write_u32::<LittleEndian>(self.sequence_number)?;
        buffer.write_u32::<LittleEndian>(self.hive_bins_data_size)?;
        buffer.write_u32::<LittleEndian>(self.dirty_pages_count)?;
        buffer.write_u64::<LittleEndian>(0)?; // Hash-1 placeholder
        buffer.write_u64::<LittleEndian>(0)?; // Hash-2 placeholder

        // Write page references
        for ref_entry in &self.page_references {
            buffer.write_u32::<LittleEndian>(ref_entry.offset)?;
            buffer.write_u32::<LittleEndian>(ref_entry.size)?;
        }

        // Write dirty pages
        for page in &self.dirty_pages {
            buffer.write_all(page)?;
        }

        // Calculate and set Hash-1
        let hash1 = marvin32_hash(&buffer[Self::HEADER_SIZE..], MARVIN32_SEED);
        buffer[24..32].copy_from_slice(&hash1.to_le_bytes());

        // Calculate and set Hash-2
        let hash2 = marvin32_hash(&buffer[0..32], MARVIN32_SEED);
        buffer[32..40].copy_from_slice(&hash2.to_le_bytes());

        writer.write_all(&buffer)
    }
}

impl NewFormatLog {
    /// Parse a new format transaction log from a reader.
    pub fn parse<R: Read + Seek>(mut reader: R) -> Result<Self> {
        // Read base block
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        reader.read_exact(&mut base_block_data)?;

        // Verify it's a transaction log
        if &base_block_data[0..4] != REGF_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "regf".to_string(),
                found: String::from_utf8_lossy(&base_block_data[0..4]).to_string(),
            });
        }

        let base_block = BaseBlock::parse(&base_block_data)?;

        // Verify file type is new format transaction log
        if base_block.file_type != 6 {
            return Err(Error::CorruptHive(format!(
                "Not a new format transaction log file (type={})",
                base_block.file_type
            )));
        }

        // Read log entries starting from second sector
        reader.seek(SeekFrom::Start(512))?;
        let mut log_entries = Vec::new();

        loop {
            // Read potential log entry header
            let mut header = vec![0u8; LogEntry::HEADER_SIZE];
            if reader.read_exact(&mut header).is_err() {
                break;
            }

            // Check for HvLE signature
            if &header[0..4] != LogEntry::SIGNATURE {
                break;
            }

            // Get entry size and read full entry
            let entry_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

            if entry_size < LogEntry::HEADER_SIZE as u32 || entry_size > 1024 * 1024 * 16 {
                break; // Invalid size
            }

            let mut entry_data = vec![0u8; entry_size as usize];
            entry_data[..LogEntry::HEADER_SIZE].copy_from_slice(&header);

            let _remaining = entry_size as usize - LogEntry::HEADER_SIZE;
            if reader.read_exact(&mut entry_data[LogEntry::HEADER_SIZE..]).is_err() {
                break;
            }

            match LogEntry::parse(&entry_data) {
                Ok(entry) => log_entries.push(entry),
                Err(_) => break, // Stop on invalid entry
            }

            // Align to 512-byte boundary for next entry
            let pos = reader.stream_position().unwrap_or(0);
            let aligned_pos = (pos + 511) / 512 * 512;
            if reader.seek(SeekFrom::Start(aligned_pos)).is_err() {
                break;
            }
        }

        Ok(Self {
            base_block,
            log_entries,
        })
    }

    /// Get log entries that should be applied (sequence number >= start_seq).
    pub fn applicable_entries(&self, start_seq: u32) -> impl Iterator<Item = &LogEntry> {
        self.log_entries
            .iter()
            .filter(move |e| e.sequence_number >= start_seq)
    }
}

/// Enumeration of transaction log formats.
#[derive(Debug, Clone)]
pub enum TransactionLog {
    /// Old format (Windows XP - Windows 8).
    Old(OldFormatLog),
    /// New format (Windows 8.1+).
    New(NewFormatLog),
}

impl TransactionLog {
    /// Parse a transaction log from a reader, automatically detecting format.
    pub fn parse<R: Read + Seek>(mut reader: R) -> Result<Self> {
        // Read and check base block file type
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        reader.read_exact(&mut base_block_data)?;

        let file_type = u32::from_le_bytes([
            base_block_data[28],
            base_block_data[29],
            base_block_data[30],
            base_block_data[31],
        ]);

        // Rewind to start
        reader.seek(SeekFrom::Start(0))?;

        match file_type {
            1 | 2 => Ok(TransactionLog::Old(OldFormatLog::parse(reader)?)),
            6 => Ok(TransactionLog::New(NewFormatLog::parse(reader)?)),
            _ => Err(Error::CorruptHive(format!(
                "Unknown transaction log file type: {}",
                file_type
            ))),
        }
    }

    /// Get the base block from this transaction log.
    pub fn base_block(&self) -> &BaseBlock {
        match self {
            TransactionLog::Old(log) => &log.base_block,
            TransactionLog::New(log) => &log.base_block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirty_vector() {
        let mut dv = DirtyVector::new(8192);
        assert!(!dv.is_page_dirty(0));
        assert!(!dv.is_page_dirty(5));

        dv.set_page_dirty(5);
        assert!(!dv.is_page_dirty(0));
        assert!(dv.is_page_dirty(5));
        assert_eq!(dv.dirty_page_count(), 1);

        dv.set_page_dirty(0);
        dv.set_page_dirty(15);
        assert_eq!(dv.dirty_page_count(), 3);
    }
}

