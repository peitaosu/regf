//! Key security (sk) structure.
//!
//! Key security items contain security descriptors for registry keys.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::signatures;

/// Key security structure (sk).
#[derive(Debug, Clone)]
pub struct KeySecurity {
    /// Signature: "sk"
    pub signature: [u8; 2],
    /// Reserved.
    pub reserved: u16,
    /// Forward link to next security item.
    pub flink: u32,
    /// Backward link to previous security item.
    pub blink: u32,
    /// Reference count (number of keys using this security descriptor).
    pub reference_count: u32,
    /// Security descriptor size in bytes.
    pub security_descriptor_size: u32,
    /// Security descriptor data.
    pub security_descriptor: Vec<u8>,
}

impl KeySecurity {
    /// Size of the fixed part of the key security item (excluding descriptor).
    pub const FIXED_SIZE: usize = 20;

    /// Parse a key security item from a byte slice.
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

        if &signature != signatures::KEY_SECURITY {
            return Err(Error::InvalidSignature {
                expected: "sk".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let reserved = cursor.read_u16::<LittleEndian>()?;
        let flink = cursor.read_u32::<LittleEndian>()?;
        let blink = cursor.read_u32::<LittleEndian>()?;
        let reference_count = cursor.read_u32::<LittleEndian>()?;
        let security_descriptor_size = cursor.read_u32::<LittleEndian>()?;

        // Read security descriptor
        let sd_start = Self::FIXED_SIZE;
        let sd_end = sd_start + security_descriptor_size as usize;

        if data.len() < sd_end {
            return Err(Error::BufferTooSmall {
                needed: sd_end,
                available: data.len(),
            });
        }

        let security_descriptor = data[sd_start..sd_end].to_vec();

        Ok(Self {
            signature,
            reserved,
            flink,
            blink,
            reference_count,
            security_descriptor_size,
            security_descriptor,
        })
    }

    /// Write the key security item to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.reserved)?;
        writer.write_u32::<LittleEndian>(self.flink)?;
        writer.write_u32::<LittleEndian>(self.blink)?;
        writer.write_u32::<LittleEndian>(self.reference_count)?;
        writer.write_u32::<LittleEndian>(self.security_descriptor_size)?;
        writer.write_all(&self.security_descriptor)?;

        Ok(())
    }

    /// Create a new key security item.
    /// Note: flink and blink should be set to point to itself initially,
    /// representing a list header with no entries.
    pub fn new(security_descriptor: Vec<u8>) -> Self {
        let size = security_descriptor.len() as u32;

        Self {
            signature: *signatures::KEY_SECURITY,
            reserved: 0,
            // flink and blink are set to 0 initially, but should be updated
            // to point to the cell's own offset when placed in the hive.
            // For a list header with no entries, flink and blink point to itself.
            flink: 0,
            blink: 0,
            reference_count: 1,
            security_descriptor_size: size,
            security_descriptor,
        }
    }

    /// Create a new key security item with proper self-referencing flink/blink.
    /// The offset parameter should be the cell offset where this security item is stored.
    pub fn new_at_offset(security_descriptor: Vec<u8>, offset: u32) -> Self {
        let size = security_descriptor.len() as u32;

        Self {
            signature: *signatures::KEY_SECURITY,
            reserved: 0,
            // For a list header, flink and blink point to itself
            flink: offset,
            blink: offset,
            reference_count: 1,
            security_descriptor_size: size,
            security_descriptor,
        }
    }

    /// Update flink/blink to point to own offset (makes this a self-contained list header).
    pub fn set_self_referencing(&mut self, offset: u32) {
        self.flink = offset;
        self.blink = offset;
    }

    /// Link this security item into an existing list.
    /// This updates the item to be inserted after the item at `prev_offset`.
    pub fn link_after(&mut self, prev_offset: u32, next_offset: u32) {
        self.blink = prev_offset;
        self.flink = next_offset;
    }

    /// Create a minimal security descriptor allowing full access.
    pub fn new_default() -> Self {
        // This is a minimal self-relative security descriptor with:
        // - DACL present, allowing Everyone full access
        // - Owner: Administrators
        // - Group: Administrators

        // Minimal security descriptor structure
        let sd = vec![
            0x01, // Revision
            0x00, // Sbz1
            0x04, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT)
            0x14, 0x00, 0x00, 0x00, // Owner offset
            0x24, 0x00, 0x00, 0x00, // Group offset
            0x00, 0x00, 0x00, 0x00, // SACL offset (none)
            0x34, 0x00, 0x00, 0x00, // DACL offset
            // Owner SID (S-1-5-32-544 Administrators)
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00, // Group SID (S-1-5-32-544 Administrators)
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00, // DACL
            0x02, // AclRevision
            0x00, // Sbz1
            0x1C, 0x00, // AclSize
            0x01, 0x00, // AceCount
            0x00, 0x00, // Sbz2
            // ACE (Allow Everyone Full Access)
            0x00,       // AceType (ACCESS_ALLOWED_ACE_TYPE)
            0x00,       // AceFlags
            0x14, 0x00, // AceSize
            0xFF, 0x01, 0x1F, 0x00, // AccessMask (KEY_ALL_ACCESS)
            // SID (S-1-1-0 Everyone)
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        Self::new(sd)
    }

    /// Get the total size needed for this key security item.
    pub fn total_size(&self) -> usize {
        Self::FIXED_SIZE + self.security_descriptor.len()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }

    /// Increment reference count.
    pub fn add_ref(&mut self) {
        self.reference_count += 1;
    }

    /// Decrement reference count. Returns true if still referenced.
    pub fn release(&mut self) -> bool {
        if self.reference_count > 0 {
            self.reference_count -= 1;
        }
        self.reference_count > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_security_creation() {
        let sd = vec![1, 2, 3, 4, 5];
        let ks = KeySecurity::new(sd.clone());
        assert_eq!(ks.security_descriptor, sd);
        assert_eq!(ks.reference_count, 1);
    }

    #[test]
    fn test_key_security_roundtrip() {
        let ks = KeySecurity::new_default();
        let bytes = ks.to_bytes();
        let parsed = KeySecurity::parse(&bytes).unwrap();
        assert_eq!(parsed.security_descriptor, ks.security_descriptor);
    }

    #[test]
    fn test_reference_count() {
        let mut ks = KeySecurity::new_default();
        assert_eq!(ks.reference_count, 1);

        ks.add_ref();
        assert_eq!(ks.reference_count, 2);

        assert!(ks.release());
        assert_eq!(ks.reference_count, 1);

        assert!(!ks.release());
        assert_eq!(ks.reference_count, 0);
    }
}

