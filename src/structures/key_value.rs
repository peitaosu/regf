//! Key value (vk) structure.
//!
//! Key values represent registry values within a key.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::{
    decode_ascii_string, decode_utf16le_string, encode_ascii_string, encode_utf16le_string,
    signatures, DataType, INVALID_OFFSET,
};

bitflags::bitflags! {
    /// Flags for key values.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyValueFlags: u16 {
        /// Value name is ASCII (not UTF-16).
        const VALUE_COMP_NAME = 0x0001;
        /// Tombstone value (layered keys, Windows 10 RS1+).
        /// A tombstone value must also have:
        /// - Data type = REG_NONE (0)
        /// - Data size = 0
        /// - Data offset = 0xFFFFFFFF
        const IS_TOMBSTONE = 0x0002;
    }
}

/// Bit mask for data size indicating resident data.
pub const DATA_IS_RESIDENT: u32 = 0x80000000;

/// Maximum size for resident data (stored directly in offset field).
pub const MAX_RESIDENT_DATA_SIZE: usize = 4;

/// Key value structure (vk).
#[derive(Debug, Clone)]
pub struct KeyValue {
    /// Signature: "vk"
    pub signature: [u8; 2],
    /// Value name length in bytes.
    pub name_length: u16,
    /// Data size (MSB set = resident data).
    pub data_size: u32,
    /// Data offset or data itself (if resident).
    pub data_offset: u32,
    /// Data type.
    pub data_type: u32,
    /// Flags.
    pub flags: u16,
    /// Spare (not used).
    pub spare: u16,
    /// Value name (ASCII or UTF-16 depending on VALUE_COMP_NAME flag).
    pub value_name: Vec<u8>,
}

impl KeyValue {
    /// Size of the fixed part of the key value (excluding name).
    pub const FIXED_SIZE: usize = 20;

    /// Parse a key value from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::FIXED_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::FIXED_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 2];
        cursor.read_exact(&mut signature)?;

        if &signature != signatures::KEY_VALUE {
            return Err(Error::InvalidSignature {
                expected: "vk".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let name_length = cursor.read_u16::<LittleEndian>()?;
        let data_size = cursor.read_u32::<LittleEndian>()?;
        let data_offset = cursor.read_u32::<LittleEndian>()?;
        let data_type = cursor.read_u32::<LittleEndian>()?;
        let flags = cursor.read_u16::<LittleEndian>()?;
        let spare = cursor.read_u16::<LittleEndian>()?;

        // Read value name
        let name_start = Self::FIXED_SIZE;
        let name_end = name_start + name_length as usize;

        if data.len() < name_end {
            return Err(Error::BufferTooSmall {
                needed: name_end,
                available: data.len(),
            });
        }

        let value_name = data[name_start..name_end].to_vec();

        Ok(Self {
            signature,
            name_length,
            data_size,
            data_offset,
            data_type,
            flags,
            spare,
            value_name,
        })
    }

    /// Write the key value to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.name_length)?;
        writer.write_u32::<LittleEndian>(self.data_size)?;
        writer.write_u32::<LittleEndian>(self.data_offset)?;
        writer.write_u32::<LittleEndian>(self.data_type)?;
        writer.write_u16::<LittleEndian>(self.flags)?;
        writer.write_u16::<LittleEndian>(self.spare)?;
        writer.write_all(&self.value_name)?;

        Ok(())
    }

    /// Get the value name as a string.
    pub fn name(&self) -> String {
        if self.name_length == 0 {
            // Default value (no name)
            return String::new();
        }

        let value_flags = self.get_flags();

        if value_flags.contains(KeyValueFlags::VALUE_COMP_NAME) {
            // ASCII name
            decode_ascii_string(&self.value_name)
        } else {
            // UTF-16LE name
            decode_utf16le_string(&self.value_name).unwrap_or_default()
        }
    }

    /// Set the value name.
    pub fn set_name(&mut self, name: &str) {
        if name.is_empty() {
            self.value_name = Vec::new();
            self.name_length = 0;
            self.flags &= !KeyValueFlags::VALUE_COMP_NAME.bits();
            return;
        }

        // Determine if we can use ASCII encoding
        let can_use_ascii = name.chars().all(|c| c as u32 <= 255);

        if can_use_ascii {
            self.value_name = encode_ascii_string(name);
            self.flags |= KeyValueFlags::VALUE_COMP_NAME.bits();
        } else {
            self.value_name = encode_utf16le_string(name);
            self.value_name.truncate(self.value_name.len() - 2); // Remove null terminator
            self.flags &= !KeyValueFlags::VALUE_COMP_NAME.bits();
        }

        self.name_length = self.value_name.len() as u16;
    }

    /// Get the flags.
    pub fn get_flags(&self) -> KeyValueFlags {
        KeyValueFlags::from_bits_truncate(self.flags)
    }

    /// Get the data type.
    pub fn get_data_type(&self) -> DataType {
        DataType::from(self.data_type)
    }

    /// Check if data is stored directly in the data_offset field.
    pub fn is_data_resident(&self) -> bool {
        (self.data_size & DATA_IS_RESIDENT) != 0
    }

    /// Get the actual data size (without the resident flag).
    pub fn actual_data_size(&self) -> u32 {
        self.data_size & !DATA_IS_RESIDENT
    }

    /// Get the resident data (if data is stored in offset field).
    pub fn get_resident_data(&self) -> Option<Vec<u8>> {
        if !self.is_data_resident() {
            return None;
        }

        let size = self.actual_data_size() as usize;
        if size > MAX_RESIDENT_DATA_SIZE {
            return None;
        }

        let bytes = self.data_offset.to_le_bytes();
        Some(bytes[..size].to_vec())
    }

    /// Set resident data.
    pub fn set_resident_data(&mut self, data: &[u8]) -> bool {
        if data.len() > MAX_RESIDENT_DATA_SIZE {
            return false;
        }

        let mut bytes = [0u8; 4];
        bytes[..data.len()].copy_from_slice(data);

        self.data_offset = u32::from_le_bytes(bytes);
        self.data_size = data.len() as u32 | DATA_IS_RESIDENT;

        true
    }

    /// Check if the tombstone flag is set.
    /// Note: A proper tombstone value should also satisfy:
    /// - Data type = REG_NONE (0)
    /// - Data size = 0
    /// - Data offset = 0xFFFFFFFF
    pub fn has_tombstone_flag(&self) -> bool {
        self.get_flags().contains(KeyValueFlags::IS_TOMBSTONE)
    }

    /// Check if this is a valid tombstone value (all conditions met per spec).
    /// A tombstone value must have:
    /// - IS_TOMBSTONE flag set
    /// - Data type = REG_NONE (0)
    /// - Data size = 0
    /// - Data offset = 0xFFFFFFFF
    pub fn is_tombstone(&self) -> bool {
        self.has_tombstone_flag()
            && self.data_type == 0 // REG_NONE
            && self.actual_data_size() == 0
            && self.data_offset == INVALID_OFFSET
    }

    /// Create a tombstone value.
    /// Tombstone values are used in layered keys (Windows 10 RS1+) to indicate
    /// that a value has been deleted in this layer.
    pub fn new_tombstone(name: &str) -> Self {
        let mut value = Self::new(name, DataType::None);
        value.flags |= KeyValueFlags::IS_TOMBSTONE.bits();
        value.data_type = 0; // REG_NONE
        value.data_size = 0;
        value.data_offset = INVALID_OFFSET;
        value
    }

    /// Check if this is the default value (empty name).
    pub fn is_default(&self) -> bool {
        self.name_length == 0
    }

    /// Create a new key value.
    pub fn new(name: &str, data_type: DataType) -> Self {
        let mut value = Self {
            signature: *signatures::KEY_VALUE,
            name_length: 0,
            data_size: 0,
            data_offset: INVALID_OFFSET,
            data_type: data_type.into(),
            flags: 0,
            spare: 0,
            value_name: Vec::new(),
        };

        value.set_name(name);
        value
    }

    /// Get the total size needed for this key value.
    pub fn total_size(&self) -> usize {
        Self::FIXED_SIZE + self.value_name.len()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_creation() {
        let value = KeyValue::new("TestValue", DataType::Dword);
        assert_eq!(value.name(), "TestValue");
        assert_eq!(value.get_data_type(), DataType::Dword);
    }

    #[test]
    fn test_resident_data() {
        let mut value = KeyValue::new("Test", DataType::Dword);
        assert!(value.set_resident_data(&[1, 2, 3, 4]));
        assert!(value.is_data_resident());
        assert_eq!(value.actual_data_size(), 4);
        assert_eq!(value.get_resident_data(), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_default_value() {
        let value = KeyValue::new("", DataType::String);
        assert!(value.is_default());
    }

    #[test]
    fn test_key_value_roundtrip() {
        let mut value = KeyValue::new("TestValue", DataType::Dword);
        value.set_resident_data(&[42, 0, 0, 0]);

        let bytes = value.to_bytes();
        let parsed = KeyValue::parse(&bytes).unwrap();

        assert_eq!(parsed.name(), value.name());
        assert_eq!(parsed.data_type, value.data_type);
        assert_eq!(parsed.get_resident_data(), value.get_resident_data());
    }
}

