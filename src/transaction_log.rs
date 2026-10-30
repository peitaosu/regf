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
    calculate_checksum, marvin32_hash, BaseBlock, BASE_BLOCK_SIZE, MARVIN32_SEED, REGF_SIGNATURE,
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
        let bitmap_len = num_pages.div_ceil(8);

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
        let mut first_sector = vec![0u8; 512];
        reader.read_exact(&mut first_sector)?;

        if &first_sector[0..4] != REGF_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "regf".to_string(),
                found: String::from_utf8_lossy(&first_sector[0..4]).to_string(),
            });
        }

        let clustering_factor = u32::from_le_bytes([
            first_sector[44],
            first_sector[45],
            first_sector[46],
            first_sector[47],
        ]);
        if clustering_factor != 1 && clustering_factor != 8 {
            return Err(Error::CorruptHive(
                format!("Invalid transaction log clustering factor: {clustering_factor}"),
            ));
        }
        let base_block_copy_size = (clustering_factor as usize)
            .checked_mul(512)
            .ok_or_else(|| Error::CorruptHive("Base block copy size overflow".to_string()))?;
        if base_block_copy_size > BASE_BLOCK_SIZE {
            return Err(Error::CorruptHive(format!(
                "Invalid base block copy size: {base_block_copy_size}"
            )));
        }
        let mut partial_base_block = vec![0u8; base_block_copy_size];
        partial_base_block[..512].copy_from_slice(&first_sector);
        if base_block_copy_size > 512 {
            reader.read_exact(&mut partial_base_block[512..])?;
        }
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        base_block_data[..base_block_copy_size].copy_from_slice(&partial_base_block);
        let base_block = BaseBlock::parse(&base_block_data)?;
        if !base_block.checksum_valid {
            return Err(Error::ChecksumMismatch {
                expected: base_block.checksum,
                calculated: calculate_checksum(&base_block_data),
            });
        }

        if base_block.file_type != 1 && base_block.file_type != 2 {
            return Err(Error::CorruptHive(format!(
                "Not a transaction log file (type={})",
                base_block.file_type
            )));
        }
        if base_block.file_format != 1 {
            return Err(Error::CorruptHive(format!(
                "Invalid transaction log file format: {}",
                base_block.file_format
            )));
        }
        if base_block.primary_sequence != base_block.secondary_sequence {
            return Err(Error::SequenceMismatch {
                primary: base_block.primary_sequence,
                secondary: base_block.secondary_sequence,
            });
        }
        if base_block.hive_bins_data_size % 4096 != 0 {
            return Err(Error::CorruptHive(format!(
                "Invalid hive bins data size: {}",
                base_block.hive_bins_data_size
            )));
        }

        let page_count = base_block.hive_bins_data_size as usize / 512;
        let bitmap_length = page_count.div_ceil(8);
        let dirty_vector_size = 4usize
            .checked_add(bitmap_length)
            .ok_or_else(|| Error::CorruptHive("Dirty vector size overflow".to_string()))?;
        reader.seek(SeekFrom::Start(base_block_copy_size as u64))?;
        let mut dirty_vector_data = vec![0u8; dirty_vector_size];
        reader.read_exact(&mut dirty_vector_data)?;

        let dirty_vector = DirtyVector::parse(&dirty_vector_data)?;
        if !page_count.is_multiple_of(8) {
            let used_bits = page_count % 8;
            let unused_mask = !((1u8 << used_bits) - 1);
            if dirty_vector
                .bitmap
                .last()
                .is_some_and(|byte| byte & unused_mask != 0)
            {
                return Err(Error::CorruptHive(
                    "Dirty vector has bits beyond the hive size".to_string(),
                ));
            }
        }
        let dirty_count = dirty_vector.dirty_page_count();
        let dirty_pages_start = base_block_copy_size
            .checked_add(dirty_vector_size.div_ceil(base_block_copy_size) * base_block_copy_size)
            .ok_or_else(|| Error::CorruptHive("Dirty pages offset overflow".to_string()))?;
        let dirty_pages_size = dirty_count
            .checked_mul(512)
            .ok_or_else(|| Error::CorruptHive("Dirty pages size overflow".to_string()))?;
        let required_size = dirty_pages_start
            .checked_add(dirty_pages_size)
            .ok_or_else(|| Error::CorruptHive("Transaction log size overflow".to_string()))?;
        let file_size = reader.seek(SeekFrom::End(0))?;
        if required_size as u64 > file_size {
            return Err(Error::BufferTooSmall {
                needed: required_size,
                available: file_size as usize,
            });
        }
        reader.seek(SeekFrom::Start(dirty_pages_start as u64))?;

        let mut dirty_pages = Vec::with_capacity(dirty_count);
        for i in 0..page_count {
            if dirty_vector.is_page_dirty(i) {
                let mut page_data = vec![0u8; 512];
                reader.read_exact(&mut page_data)?;
                dirty_pages.push(DirtyPage {
                    offset: (i * 512) as u32,
                    data: page_data,
                });
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
        let entry_size = size as usize;
        if entry_size != data.len()
            || entry_size < Self::HEADER_SIZE
            || !entry_size.is_multiple_of(512)
        {
            return Err(Error::CorruptHive(format!(
                "Invalid log entry size: {size}"
            )));
        }
        if flags > 1 {
            return Err(Error::CorruptHive(format!(
                "Invalid log entry flags: {flags:#010x}"
            )));
        }

        // Verify hive bins data size is valid
        if hive_bins_data_size % 4096 != 0 {
            return Err(Error::CorruptHive(format!(
                "Invalid hive bins data size in log entry: {}",
                hive_bins_data_size
            )));
        }

        let references_size = (dirty_pages_count as usize)
            .checked_mul(8)
            .ok_or_else(|| Error::CorruptHive("Page reference size overflow".to_string()))?;
        let data_start = Self::HEADER_SIZE
            .checked_add(references_size)
            .ok_or_else(|| Error::CorruptHive("Page data offset overflow".to_string()))?;
        if data_start > entry_size {
            return Err(Error::BufferTooSmall {
                needed: data_start,
                available: entry_size,
            });
        }

        let mut page_references = Vec::with_capacity(dirty_pages_count as usize);
        for _ in 0..dirty_pages_count {
            let offset = cursor.read_u32::<LittleEndian>()?;
            let page_size = cursor.read_u32::<LittleEndian>()?;
            if page_size == 0 {
                return Err(Error::CorruptHive(
                    "Dirty page size is zero".to_string(),
                ));
            }
            let page_end = offset
                .checked_add(page_size)
                .ok_or_else(|| Error::CorruptHive("Dirty page extent overflow".to_string()))?;
            if page_end > hive_bins_data_size {
                return Err(Error::CorruptHive(format!(
                    "Dirty page end {page_end} exceeds hive size {hive_bins_data_size}"
                )));
            }
            page_references.push(DirtyPageReference {
                offset,
                size: page_size,
            });
        }

        // Read dirty pages
        let mut dirty_pages = Vec::with_capacity(dirty_pages_count as usize);
        for ref_entry in &page_references {
            let pos = cursor.position() as usize;
            let end = pos
                .checked_add(ref_entry.size as usize)
                .ok_or_else(|| Error::CorruptHive("Dirty page size overflow".to_string()))?;

            if end > entry_size {
                return Err(Error::BufferTooSmall {
                    needed: end,
                    available: data.len(),
                });
            }

            dirty_pages.push(data[pos..end].to_vec());
            cursor.set_position(end as u64);
        }

        // Verify Hash-1
        let hash_data = &data[Self::HEADER_SIZE..entry_size];
        let calculated_hash1 = marvin32_hash(hash_data, MARVIN32_SEED);
        if hash1 != calculated_hash1 {
            return Err(Error::HashMismatch {
                expected: hash1,
                calculated: calculated_hash1,
            });
        }

        // Verify Hash-2
        let calculated_hash2 = marvin32_hash(&data[0..32], MARVIN32_SEED);
        if hash2 != calculated_hash2 {
            return Err(Error::HashMismatch {
                expected: hash2,
                calculated: calculated_hash2,
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
        if self.size < Self::HEADER_SIZE as u32 || !self.size.is_multiple_of(512) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid log entry size: {}", self.size),
            ));
        }
        if self.page_references.len() != self.dirty_pages.len()
            || self.page_references.len() != self.dirty_pages_count as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Dirty page count mismatch",
            ));
        }
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
        for (reference, page) in self.page_references.iter().zip(&self.dirty_pages) {
            if reference.size == 0 || page.len() != reference.size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Dirty page size mismatch",
                ));
            }
            buffer.write_all(page)?;
        }
        if buffer.len() > self.size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Log entry payload exceeds declared size",
            ));
        }
        buffer.resize(self.size as usize, 0);

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
        let mut partial_base_block = vec![0u8; 512];
        reader.read_exact(&mut partial_base_block)?;

        if &partial_base_block[0..4] != REGF_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: "regf".to_string(),
                found: String::from_utf8_lossy(&partial_base_block[0..4]).to_string(),
            });
        }

        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        base_block_data[..512].copy_from_slice(&partial_base_block);
        let base_block = BaseBlock::parse(&base_block_data)?;
        if !base_block.checksum_valid {
            return Err(Error::ChecksumMismatch {
                expected: base_block.checksum,
                calculated: calculate_checksum(&base_block_data),
            });
        }

        // Verify file type is new format transaction log
        if base_block.file_type != 6 {
            return Err(Error::CorruptHive(format!(
                "Not a new format transaction log file (type={})",
                base_block.file_type
            )));
        }
        if base_block.file_format != 1 {
            return Err(Error::CorruptHive(format!(
                "Invalid transaction log file format: {}",
                base_block.file_format
            )));
        }
        if base_block.clustering_factor != 1 {
            return Err(Error::CorruptHive(format!(
                "Invalid new transaction log clustering factor: {}",
                base_block.clustering_factor
            )));
        }
        if base_block.primary_sequence != base_block.secondary_sequence {
            return Err(Error::SequenceMismatch {
                primary: base_block.primary_sequence,
                secondary: base_block.secondary_sequence,
            });
        }

        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(512))?;
        let mut log_entries = Vec::new();

        loop {
            let entry_start = reader.stream_position()?;
            let mut header = vec![0u8; LogEntry::HEADER_SIZE];
            match reader.read_exact(&mut header) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }

            if &header[0..4] != LogEntry::SIGNATURE {
                break;
            }

            let entry_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

            if entry_size < LogEntry::HEADER_SIZE as u32 || !entry_size.is_multiple_of(512) {
                break;
            }
            let Some(entry_end) = entry_start.checked_add(entry_size as u64) else {
                break;
            };
            if entry_end > file_size {
                break;
            }

            let mut entry_data = vec![0u8; entry_size as usize];
            entry_data[..LogEntry::HEADER_SIZE].copy_from_slice(&header);

            match reader.read_exact(&mut entry_data[LogEntry::HEADER_SIZE..]) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }
            match LogEntry::parse(&entry_data) {
                Ok(entry) => log_entries.push(entry),
                Err(_) => break,
            }
        }

        Ok(Self {
            base_block,
            log_entries,
        })
    }

    pub fn applicable_entries(&self, start_seq: u32) -> Result<Vec<&LogEntry>> {
        let first = self
            .log_entries
            .iter()
            .position(|entry| entry.sequence_number == start_seq)
            .ok_or_else(|| {
                Error::CorruptHive(format!("Expected log sequence {start_seq} is missing"))
            })?;
        let mut expected = start_seq;
        let mut entries = Vec::new();
        for entry in &self.log_entries[first..] {
            if entry.sequence_number != expected {
                break;
            }
            entries.push(entry);
            expected = expected.wrapping_add(1);
        }
        Ok(entries)
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
        let mut base_block_data = vec![0u8; 512];
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
    use crate::structures::FileType;

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

    fn log_base_block(file_type: u32) -> Vec<u8> {
        log_base_block_with(file_type, 4096, 1)
    }

    fn log_base_block_with(
        file_type: u32,
        hive_bins_data_size: u32,
        clustering_factor: u32,
    ) -> Vec<u8> {
        let base_block = BaseBlock {
            file_type,
            hive_bins_data_size,
            clustering_factor,
            ..BaseBlock::default()
        };
        let mut data = Vec::new();
        base_block.write(&mut data).unwrap();
        data
    }

    #[test]
    fn parses_compact_old_format_log() {
        let mut data = log_base_block(FileType::TransactionLog as u32)[..512].to_vec();
        data.extend_from_slice(DirtyVector::SIGNATURE);
        data.push(1);
        data.resize(1024, 0);
        data.extend_from_slice(&vec![0xAB; 512]);

        let log = OldFormatLog::parse(Cursor::new(data)).unwrap();
        assert_eq!(log.dirty_vector.bitmap, vec![1]);
        assert_eq!(log.dirty_pages.len(), 1);
        assert_eq!(log.dirty_pages[0].offset, 0);
        assert_eq!(log.dirty_pages[0].data, vec![0xAB; 512]);
    }

    #[test]
    fn parses_old_log_bitmap_lengths_and_clustering() {
        for hive_size in [8192u32, 12_288] {
            let mut data =
                log_base_block_with(FileType::TransactionLog as u32, hive_size, 1)[..512].to_vec();
            let page_count = hive_size as usize / 512;
            let bitmap_length = page_count.div_ceil(8);
            data.extend_from_slice(DirtyVector::SIGNATURE);
            data.extend_from_slice(&vec![0; bitmap_length - 1]);
            data.push(0x80);
            data.resize(1024, 0);
            data.extend_from_slice(&vec![0xCD; 512]);
            let log = OldFormatLog::parse(Cursor::new(data)).unwrap();
            assert_eq!(log.dirty_vector.bitmap.len(), bitmap_length);
            assert_eq!(log.dirty_pages.len(), 1);
        }

        let mut clustered = log_base_block_with(FileType::TransactionLog as u32, 4096, 8);
        clustered.extend_from_slice(DirtyVector::SIGNATURE);
        clustered.push(1);
        clustered.resize(8192, 0);
        clustered.extend_from_slice(&vec![0xEF; 512]);
        let log = OldFormatLog::parse(Cursor::new(clustered)).unwrap();
        assert_eq!(log.dirty_pages[0].data, vec![0xEF; 512]);
    }

    #[test]
    fn parses_compact_new_format_log() {
        let mut data = log_base_block(FileType::TransactionLogNew as u32)[..512].to_vec();
        let entry = LogEntry {
            signature: *LogEntry::SIGNATURE,
            size: 512,
            flags: 0,
            sequence_number: 1,
            hive_bins_data_size: 4096,
            dirty_pages_count: 1,
            hash1: 0,
            hash2: 0,
            page_references: vec![DirtyPageReference { offset: 0, size: 4 }],
            dirty_pages: vec![vec![1, 2, 3, 4]],
        };
        entry.write(&mut data).unwrap();

        let log = NewFormatLog::parse(Cursor::new(data)).unwrap();
        assert_eq!(log.log_entries.len(), 1);
        assert_eq!(log.log_entries[0].dirty_pages[0], vec![1, 2, 3, 4]);
    }

    #[test]
    fn keeps_valid_log_entry_prefix() {
        let mut data = log_base_block(FileType::TransactionLogNew as u32)[..512].to_vec();
        let entry = LogEntry {
            signature: *LogEntry::SIGNATURE,
            size: 512,
            flags: 0,
            sequence_number: 1,
            hive_bins_data_size: 4096,
            dirty_pages_count: 0,
            hash1: 0,
            hash2: 0,
            page_references: Vec::new(),
            dirty_pages: Vec::new(),
        };
        entry.write(&mut data).unwrap();
        let second_entry_offset = data.len();
        entry.write(&mut data).unwrap();
        data[second_entry_offset + 24] ^= 0xFF;

        let log = NewFormatLog::parse(Cursor::new(data)).unwrap();
        assert_eq!(log.log_entries.len(), 1);
    }

    #[test]
    fn rejects_invalid_log_entry_bounds() {
        for size in [0u32, 39, 511, 1024] {
            let mut data = vec![0u8; 512];
            data[..4].copy_from_slice(LogEntry::SIGNATURE);
            data[4..8].copy_from_slice(&size.to_le_bytes());
            assert!(LogEntry::parse(&data).is_err());
        }
    }

    #[test]
    fn rejects_zero_sized_page_and_invalid_clustering() {
        let entry = LogEntry {
            signature: *LogEntry::SIGNATURE,
            size: 512,
            flags: 0,
            sequence_number: 1,
            hive_bins_data_size: 4096,
            dirty_pages_count: 1,
            hash1: 0,
            hash2: 0,
            page_references: vec![DirtyPageReference { offset: 0, size: 0 }],
            dirty_pages: vec![Vec::new()],
        };
        assert!(entry.write(&mut Vec::new()).is_err());

        let invalid_old =
            log_base_block_with(FileType::TransactionLog as u32, 4096, 2);
        assert!(OldFormatLog::parse(Cursor::new(invalid_old)).is_err());

        let invalid_new =
            log_base_block_with(FileType::TransactionLogNew as u32, 4096, 8);
        assert!(NewFormatLog::parse(Cursor::new(invalid_new)).is_err());
    }

    #[test]
    fn applicable_entries_stop_at_sequence_gap() {
        let entry = |sequence_number| LogEntry {
            signature: *LogEntry::SIGNATURE,
            size: 512,
            flags: 0,
            sequence_number,
            hive_bins_data_size: 4096,
            dirty_pages_count: 0,
            hash1: 0,
            hash2: 0,
            page_references: Vec::new(),
            dirty_pages: Vec::new(),
        };
        let log = NewFormatLog {
            base_block: BaseBlock::default(),
            log_entries: vec![entry(5), entry(6), entry(8)],
        };
        let sequences = log
            .applicable_entries(5)
            .unwrap()
            .iter()
            .map(|entry| entry.sequence_number)
            .collect::<Vec<_>>();

        assert_eq!(sequences, vec![5, 6]);
        assert!(log.applicable_entries(4).is_err());
    }

    #[test]
    fn rejects_log_with_invalid_base_block_checksum() {
        let mut data = log_base_block(FileType::TransactionLog as u32)[..512].to_vec();
        data[100] ^= 0xFF;
        data.extend_from_slice(DirtyVector::SIGNATURE);
        data.push(0);
        data.resize(1024, 0);
        assert!(OldFormatLog::parse(Cursor::new(data)).is_err());
    }
}

