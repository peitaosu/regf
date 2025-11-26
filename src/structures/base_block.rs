//! Base block (file header) structure.
//!
//! The base block is 4096 bytes in length and contains the file header information.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::{calculate_checksum, BASE_BLOCK_SIZE, REGF_SIGNATURE};

/// File type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileType {
    /// Primary hive file.
    Primary = 0,
    /// Transaction log (old format, Windows XP+).
    TransactionLog = 1,
    /// Transaction log (Windows NT/2000).
    TransactionLogLegacy = 2,
    /// Transaction log (new format, Windows 8.1+).
    TransactionLogNew = 6,
}

impl TryFrom<u32> for FileType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(FileType::Primary),
            1 => Ok(FileType::TransactionLog),
            2 => Ok(FileType::TransactionLogLegacy),
            6 => Ok(FileType::TransactionLogNew),
            _ => Err(Error::CorruptHive(format!("Unknown file type: {}", value))),
        }
    }
}

/// File format values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileFormat {
    /// Direct memory load.
    DirectMemoryLoad = 1,
}

impl TryFrom<u32> for FileFormat {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            1 => Ok(FileFormat::DirectMemoryLoad),
            _ => Err(Error::CorruptHive(format!("Unknown file format: {}", value))),
        }
    }
}

bitflags::bitflags! {
    /// Flags for the base block.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BaseBlockFlags: u32 {
        /// KTM locked the hive (pending or anticipated transactions).
        const KTM_LOCKED = 0x00000001;
        /// Hive has been defragmented / supports layered keys (Windows 10+).
        const DEFRAGMENTED_OR_LAYERED = 0x00000002;
    }
}

/// Offline Registry Library signature.
pub const OFRG_SIGNATURE: &[u8; 4] = b"OfRg";

/// Special bits in the Last reorganized timestamp field.
pub mod reorganized_bits {
    /// Hive was defragmented during the latest reorganization.
    pub const DEFRAGMENTED: u64 = 0x01;
    /// Access history of key nodes was cleared during the latest reorganization.
    pub const ACCESS_HISTORY_CLEARED: u64 = 0x02;
    /// Mask for special bits (first 2 bits).
    pub const SPECIAL_BITS_MASK: u64 = 0x03;
}

/// Offline Registry Library (offreg.dll) metadata.
/// These fields are written when a hive is serialized by the Offline Registry Library.
#[derive(Debug, Clone, Default)]
pub struct OfflineRegistryInfo {
    /// Whether OfRg signature was found.
    pub present: bool,
    /// Flags (typically 1).
    pub flags: u32,
    /// Serialization timestamp (FILETIME, at offset 512).
    pub serialization_timestamp: u64,
}

/// The base block (file header) of a registry hive.
///
/// This is the first 4096 bytes of a primary registry file.
#[derive(Debug, Clone)]
pub struct BaseBlock {
    /// Signature: "regf"
    pub signature: [u8; 4],
    /// Primary sequence number (incremented at start of write).
    pub primary_sequence: u32,
    /// Secondary sequence number (incremented at end of write).
    pub secondary_sequence: u32,
    /// Last written timestamp (FILETIME).
    pub last_written: u64,
    /// Major version of hive writer.
    pub major_version: u32,
    /// Minor version of hive writer.
    pub minor_version: u32,
    /// File type.
    pub file_type: u32,
    /// File format.
    pub file_format: u32,
    /// Offset of root cell relative to hive bins data.
    pub root_cell_offset: u32,
    /// Size of hive bins data in bytes.
    pub hive_bins_data_size: u32,
    /// Clustering factor (logical sector size / 512).
    pub clustering_factor: u32,
    /// File name (UTF-16LE, partial path or filename).
    pub file_name: [u8; 64],
    /// Resource Manager GUID (Windows Vista+).
    pub rm_id: [u8; 16],
    /// Log file GUID (Windows Vista+).
    pub log_id: [u8; 16],
    /// Flags (Windows Vista+).
    pub flags: u32,
    /// Transaction Manager GUID (Windows Vista+).
    pub tm_id: [u8; 16],
    /// GUID signature: "rmtm" (Windows Vista+).
    pub guid_signature: [u8; 4],
    /// Last reorganized timestamp (Windows 8+).
    pub last_reorganized: u64,
    /// Checksum of first 508 bytes.
    pub checksum: u32,
    /// Thaw Transaction Manager GUID (no meaning on disk, used for shadow copy recovery).
    pub thaw_tm_id: [u8; 16],
    /// Thaw Resource Manager GUID (no meaning on disk, used for shadow copy recovery).
    pub thaw_rm_id: [u8; 16],
    /// Thaw Log file GUID (no meaning on disk, used for shadow copy recovery).
    pub thaw_log_id: [u8; 16],
    /// Boot type (no meaning on disk).
    pub boot_type: u32,
    /// Boot recover (no meaning on disk).
    pub boot_recover: u32,
    /// Offline Registry Library metadata (if present).
    pub offline_registry: OfflineRegistryInfo,
}

impl Default for BaseBlock {
    fn default() -> Self {
        Self {
            signature: *REGF_SIGNATURE,
            primary_sequence: 1,
            secondary_sequence: 1,
            last_written: 0,
            major_version: 1,
            minor_version: 6,
            file_type: 0,
            file_format: 1,
            root_cell_offset: 32, // Typical offset after first hive bin header
            hive_bins_data_size: 4096,
            clustering_factor: 1,
            file_name: [0; 64],
            rm_id: [0; 16],
            log_id: [0; 16],
            flags: 0,
            tm_id: [0; 16],
            guid_signature: [0; 4],
            last_reorganized: 0,
            checksum: 0,
            thaw_tm_id: [0; 16],
            thaw_rm_id: [0; 16],
            thaw_log_id: [0; 16],
            boot_type: 0,
            boot_recover: 0,
            offline_registry: OfflineRegistryInfo::default(),
        }
    }
}

impl BaseBlock {
    /// Parse a base block from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < BASE_BLOCK_SIZE {
            return Err(Error::BufferTooSmall {
                needed: BASE_BLOCK_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        // Read signature
        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;

        if &signature != REGF_SIGNATURE {
            return Err(Error::InvalidSignature {
                expected: String::from_utf8_lossy(REGF_SIGNATURE).to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let primary_sequence = cursor.read_u32::<LittleEndian>()?;
        let secondary_sequence = cursor.read_u32::<LittleEndian>()?;
        let last_written = cursor.read_u64::<LittleEndian>()?;
        let major_version = cursor.read_u32::<LittleEndian>()?;
        let minor_version = cursor.read_u32::<LittleEndian>()?;
        let file_type = cursor.read_u32::<LittleEndian>()?;
        let file_format = cursor.read_u32::<LittleEndian>()?;
        let root_cell_offset = cursor.read_u32::<LittleEndian>()?;
        let hive_bins_data_size = cursor.read_u32::<LittleEndian>()?;
        let clustering_factor = cursor.read_u32::<LittleEndian>()?;

        let mut file_name = [0u8; 64];
        cursor.read_exact(&mut file_name)?;

        // Windows Vista+ fields (offset 112)
        let mut rm_id = [0u8; 16];
        cursor.read_exact(&mut rm_id)?;

        let mut log_id = [0u8; 16];
        cursor.read_exact(&mut log_id)?;

        let flags = cursor.read_u32::<LittleEndian>()?;

        let mut tm_id = [0u8; 16];
        cursor.read_exact(&mut tm_id)?;

        let mut guid_signature = [0u8; 4];
        cursor.read_exact(&mut guid_signature)?;

        let last_reorganized = cursor.read_u64::<LittleEndian>()?;

        // Skip to checksum at offset 508
        cursor.set_position(508);
        let checksum = cursor.read_u32::<LittleEndian>()?;

        // Verify checksum
        let calculated_checksum = calculate_checksum(data);
        if checksum != calculated_checksum {
            return Err(Error::ChecksumMismatch {
                expected: checksum,
                calculated: calculated_checksum,
            });
        }

        // Thaw GUIDs at offsets 4040, 4056, 4072 (used for shadow copy recovery)
        cursor.set_position(4040);
        let mut thaw_tm_id = [0u8; 16];
        cursor.read_exact(&mut thaw_tm_id)?;

        let mut thaw_rm_id = [0u8; 16];
        cursor.read_exact(&mut thaw_rm_id)?;

        let mut thaw_log_id = [0u8; 16];
        cursor.read_exact(&mut thaw_log_id)?;

        // Boot type and recover at offsets 4088 and 4092
        cursor.set_position(4088);
        let boot_type = cursor.read_u32::<LittleEndian>()?;
        let boot_recover = cursor.read_u32::<LittleEndian>()?;

        // Check for Offline Registry Library (OfRg) signature
        // Can be at offset 176 (current versions) or 168 (legacy versions)
        let mut offline_registry = OfflineRegistryInfo::default();
        
        // Try offset 176 first (current versions: 6.2, 6.3, 10.0)
        cursor.set_position(176);
        let mut ofrg_sig = [0u8; 4];
        cursor.read_exact(&mut ofrg_sig)?;
        
        if &ofrg_sig == OFRG_SIGNATURE {
            offline_registry.present = true;
            offline_registry.flags = cursor.read_u32::<LittleEndian>()?;
            // Serialization timestamp is at offset 512
            cursor.set_position(512);
            offline_registry.serialization_timestamp = cursor.read_u64::<LittleEndian>()?;
        } else {
            // Try offset 168 (legacy version: 6.1)
            cursor.set_position(168);
            cursor.read_exact(&mut ofrg_sig)?;
            if &ofrg_sig == OFRG_SIGNATURE {
                offline_registry.present = true;
                offline_registry.flags = cursor.read_u32::<LittleEndian>()?;
                cursor.set_position(512);
                offline_registry.serialization_timestamp = cursor.read_u64::<LittleEndian>()?;
            }
        }

        Ok(Self {
            signature,
            primary_sequence,
            secondary_sequence,
            last_written,
            major_version,
            minor_version,
            file_type,
            file_format,
            root_cell_offset,
            hive_bins_data_size,
            clustering_factor,
            file_name,
            rm_id,
            log_id,
            flags,
            tm_id,
            guid_signature,
            last_reorganized,
            checksum,
            thaw_tm_id,
            thaw_rm_id,
            thaw_log_id,
            boot_type,
            boot_recover,
            offline_registry,
        })
    }

    /// Write the base block to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buffer = vec![0u8; BASE_BLOCK_SIZE];

        {
            let mut cursor = Cursor::new(&mut buffer[..]);

            cursor.write_all(&self.signature)?;
            cursor.write_u32::<LittleEndian>(self.primary_sequence)?;
            cursor.write_u32::<LittleEndian>(self.secondary_sequence)?;
            cursor.write_u64::<LittleEndian>(self.last_written)?;
            cursor.write_u32::<LittleEndian>(self.major_version)?;
            cursor.write_u32::<LittleEndian>(self.minor_version)?;
            cursor.write_u32::<LittleEndian>(self.file_type)?;
            cursor.write_u32::<LittleEndian>(self.file_format)?;
            cursor.write_u32::<LittleEndian>(self.root_cell_offset)?;
            cursor.write_u32::<LittleEndian>(self.hive_bins_data_size)?;
            cursor.write_u32::<LittleEndian>(self.clustering_factor)?;
            cursor.write_all(&self.file_name)?;
            cursor.write_all(&self.rm_id)?;
            cursor.write_all(&self.log_id)?;
            cursor.write_u32::<LittleEndian>(self.flags)?;
            cursor.write_all(&self.tm_id)?;
            cursor.write_all(&self.guid_signature)?;
            cursor.write_u64::<LittleEndian>(self.last_reorganized)?;
        }

        // Calculate and write checksum
        let checksum = calculate_checksum(&buffer);
        buffer[508..512].copy_from_slice(&checksum.to_le_bytes());

        // Write thaw GUIDs at offsets 4040, 4056, 4072
        buffer[4040..4056].copy_from_slice(&self.thaw_tm_id);
        buffer[4056..4072].copy_from_slice(&self.thaw_rm_id);
        buffer[4072..4088].copy_from_slice(&self.thaw_log_id);

        // Write boot type and recover at the end
        buffer[4088..4092].copy_from_slice(&self.boot_type.to_le_bytes());
        buffer[4092..4096].copy_from_slice(&self.boot_recover.to_le_bytes());

        writer.write_all(&buffer)
    }

    /// Check if the hive is dirty (needs recovery).
    pub fn is_dirty(&self) -> bool {
        self.primary_sequence != self.secondary_sequence
    }

    /// Get the file type as an enum.
    pub fn get_file_type(&self) -> Result<FileType> {
        FileType::try_from(self.file_type)
    }

    /// Get the file format as an enum.
    pub fn get_file_format(&self) -> Result<FileFormat> {
        FileFormat::try_from(self.file_format)
    }

    /// Get the flags.
    pub fn get_flags(&self) -> BaseBlockFlags {
        BaseBlockFlags::from_bits_truncate(self.flags)
    }

    /// Get the file name as a string.
    pub fn get_file_name(&self) -> String {
        // UTF-16LE encoded, null-terminated
        let u16_values: Vec<u16> = self.file_name
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();

        String::from_utf16_lossy(&u16_values)
    }

    /// Set the file name from a string.
    pub fn set_file_name(&mut self, name: &str) {
        let mut file_name = [0u8; 64];
        let u16_values: Vec<u16> = name.encode_utf16().collect();

        for (i, &value) in u16_values.iter().take(31).enumerate() {
            let bytes = value.to_le_bytes();
            file_name[i * 2] = bytes[0];
            file_name[i * 2 + 1] = bytes[1];
        }

        self.file_name = file_name;
    }

    /// Update timestamps and sequence numbers before writing.
    pub fn prepare_for_write(&mut self) {
        use chrono::Utc;
        use crate::structures::datetime_to_filetime;

        self.primary_sequence = self.primary_sequence.wrapping_add(1);
        self.last_written = datetime_to_filetime(Utc::now());
    }

    /// Check if the hive was defragmented during the latest reorganization.
    /// (Based on bit 0 of the last_reorganized timestamp)
    pub fn was_defragmented(&self) -> bool {
        (self.last_reorganized & reorganized_bits::DEFRAGMENTED) != 0
    }

    /// Check if access history was cleared during the latest reorganization.
    /// (Based on bit 1 of the last_reorganized timestamp)
    pub fn was_access_history_cleared(&self) -> bool {
        (self.last_reorganized & reorganized_bits::ACCESS_HISTORY_CLEARED) != 0
    }

    /// Get the actual last reorganized timestamp (without special bits).
    pub fn get_last_reorganized_time(&self) -> u64 {
        self.last_reorganized & !reorganized_bits::SPECIAL_BITS_MASK
    }

    /// Check if the hive was created/serialized by the Offline Registry Library.
    pub fn is_offline_registry(&self) -> bool {
        self.offline_registry.present
    }

    /// Mark write as complete.
    pub fn complete_write(&mut self) {
        self.secondary_sequence = self.primary_sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_base_block() {
        let block = BaseBlock::default();
        assert_eq!(&block.signature, REGF_SIGNATURE);
        assert_eq!(block.major_version, 1);
        assert!(!block.is_dirty());
    }

    #[test]
    fn test_file_name() {
        let mut block = BaseBlock::default();
        block.set_file_name("SYSTEM");
        assert_eq!(block.get_file_name(), "SYSTEM");
    }
}

