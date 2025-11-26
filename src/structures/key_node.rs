//! Key node (nk) structure.
//!
//! Key nodes represent registry keys in the hive.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::{decode_ascii_string, decode_utf16le_string, encode_ascii_string, 
    encode_utf16le_string, signatures, INVALID_OFFSET};

bitflags::bitflags! {
    /// Flags for key nodes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyNodeFlags: u16 {
        /// Key is volatile (not written to disk).
        /// A key node on disk isn't expected to have this flag set.
        const KEY_VOLATILE = 0x0001;
        /// Mount point of another hive.
        /// A key node on disk isn't expected to have this flag set.
        const KEY_HIVE_EXIT = 0x0002;
        /// Root key for this hive.
        const KEY_HIVE_ENTRY = 0x0004;
        /// Key cannot be deleted.
        const KEY_NO_DELETE = 0x0008;
        /// Key is a symbolic link.
        /// Target is specified as REG_LINK value named "SymbolicLinkValue".
        const KEY_SYM_LINK = 0x0010;
        /// Key name is ASCII (not UTF-16).
        const KEY_COMP_NAME = 0x0020;
        /// Predefined handle.
        /// When set, a handle is stored in the `num_values` field instead of the value count.
        const KEY_PREDEF_HANDLE = 0x0040;
        /// Key was virtualized at least once (Windows Vista+).
        const VIRTUAL_SOURCE = 0x0080;
        /// Key is virtual (Windows Vista+).
        const VIRTUAL_TARGET = 0x0100;
        /// Part of virtual store path (Windows Vista+).
        const VIRTUAL_STORE = 0x0200;
    }
}

bitflags::bitflags! {
    /// User flags (Wow64 flags) for key nodes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserFlags: u8 {
        /// 32-bit key (Wow64).
        const KEY_32BIT = 0x01;
        /// Created by reflection process.
        const REFLECTION_CREATED = 0x02;
        /// Disable reflection.
        const DISABLE_REFLECTION = 0x04;
        /// Extended flag.
        const EXTENDED = 0x08;
    }
}

bitflags::bitflags! {
    /// Virtualization control flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VirtualizationFlags: u8 {
        /// Disable registry write virtualization.
        const DONT_VIRTUALIZE = 0x02;
        /// Disable registry open virtualization.
        const DONT_SILENT_FAIL = 0x04;
        /// Propagate flags to child keys.
        const RECURSE_FLAG = 0x08;
    }
}

bitflags::bitflags! {
    /// Access bits for tracking key access.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessBits: u8 {
        /// Accessed before registry initialization during boot.
        const ACCESSED_BEFORE_INIT = 0x01;
        /// Accessed after registry initialization during boot.
        const ACCESSED_AFTER_INIT = 0x02;
    }
}

bitflags::bitflags! {
    /// Debug flags for key nodes.
    /// When CmpRegDebugBreakEnabled kernel variable is set to 1,
    /// a checked Windows kernel will execute int 3 on these events.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DebugFlags: u8 {
        /// Break when this key is opened.
        const BREAK_ON_OPEN = 0x01;
        /// Break when this key is deleted.
        const BREAK_ON_DELETE = 0x02;
        /// Break when security is changed for this key.
        const BREAK_ON_SECURITY_CHANGE = 0x04;
        /// Break when a subkey of this key is created.
        const BREAK_ON_CREATE_SUBKEY = 0x08;
        /// Break when a subkey of this key is deleted.
        const BREAK_ON_DELETE_SUBKEY = 0x10;
        /// Break when a value is set on this key.
        const BREAK_ON_SET_VALUE = 0x20;
        /// Break when a value is deleted from this key.
        const BREAK_ON_DELETE_VALUE = 0x40;
        /// Break when this key is virtualized.
        const BREAK_ON_KEY_VIRTUALIZE = 0x80;
    }
}

/// Layer semantics values for layered keys (Windows 10 RS1+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LayerSemantics {
    /// Key node and parent key nodes can be included in the layered key.
    None = 0,
    /// Tombstone key node: cannot be included in layered key (no class name, no subkeys, no values).
    IsTombstone = 1,
    /// Key node can be included, but parent key nodes cannot.
    IsSupersedeLocal = 2,
    /// Key node can be included, parent key nodes cannot; child key nodes must have same value.
    IsSupersedeTree = 3,
}

impl From<u8> for LayerSemantics {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0 => LayerSemantics::None,
            1 => LayerSemantics::IsTombstone,
            2 => LayerSemantics::IsSupersedeLocal,
            3 => LayerSemantics::IsSupersedeTree,
            _ => unreachable!(),
        }
    }
}

/// Layered key bit fields (Windows 10 RS1+).
/// These are stored in the second byte of the access_bits field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayeredKeyFlags {
    /// Raw byte value.
    raw: u8,
}

impl LayeredKeyFlags {
    /// Create from raw byte value.
    pub fn from_raw(raw: u8) -> Self {
        Self { raw }
    }

    /// Get the raw byte value.
    pub fn raw(&self) -> u8 {
        self.raw
    }

    /// Get the inherit class flag (bit 0, from MSB).
    /// If set, layered key inherits class name from parent key node.
    pub fn inherit_class(&self) -> bool {
        (self.raw & 0x80) != 0
    }

    /// Get the layer semantics (bits 6-7, from MSB).
    pub fn layer_semantics(&self) -> LayerSemantics {
        LayerSemantics::from(self.raw & 0x03)
    }
}

/// Key node structure (nk).
#[derive(Debug, Clone)]
pub struct KeyNode {
    /// Signature: "nk"
    pub signature: [u8; 2],
    /// Flags.
    pub flags: u16,
    /// Last written timestamp (FILETIME).
    pub last_written: u64,
    /// Access bits (byte 0, Windows 8+).
    pub access_bits: u8,
    /// Layered key bit fields (byte 1, Windows 10 RS1+).
    pub layered_key_flags: u8,
    /// Spare bytes (bytes 2-3).
    pub access_spare: u16,
    /// Offset of parent key node.
    pub parent: u32,
    /// Number of subkeys.
    pub num_subkeys: u32,
    /// Number of volatile subkeys.
    pub num_volatile_subkeys: u32,
    /// Offset of subkeys list.
    pub subkeys_list_offset: u32,
    /// Offset of volatile subkeys list (no meaning on disk).
    pub volatile_subkeys_list_offset: u32,
    /// Number of key values.
    pub num_values: u32,
    /// Offset of key values list.
    pub values_list_offset: u32,
    /// Offset of key security item.
    pub security_offset: u32,
    /// Offset of class name.
    pub class_name_offset: u32,
    /// Largest subkey name length (in bytes, as UTF-16).
    pub largest_subkey_name_length: u16,
    /// Virtualization control flags (4 bits).
    pub virtualization_flags: u8,
    /// User flags / Wow64 flags (4 bits).
    pub user_flags: u8,
    /// Debug field.
    pub debug: u8,
    /// Largest subkey class name length.
    pub largest_subkey_class_name_length: u32,
    /// Largest value name length (in bytes, as UTF-16).
    pub largest_value_name_length: u32,
    /// Largest value data size.
    pub largest_value_data_size: u32,
    /// WorkVar (cached index, not used since Windows XP).
    pub work_var: u32,
    /// Key name length in bytes.
    pub key_name_length: u16,
    /// Class name length in bytes.
    pub class_name_length: u16,
    /// Key name (ASCII or UTF-16 depending on KEY_COMP_NAME flag).
    pub key_name: Vec<u8>,
}

impl KeyNode {
    /// Size of the fixed part of the key node (excluding name).
    pub const FIXED_SIZE: usize = 76;

    /// Parse a key node from a byte slice.
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

        if &signature != signatures::KEY_NODE {
            return Err(Error::InvalidSignature {
                expected: "nk".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let flags = cursor.read_u16::<LittleEndian>()?;
        let last_written = cursor.read_u64::<LittleEndian>()?;
        // Access bits field is split: byte 0 = access bits, byte 1 = layered key flags, bytes 2-3 = spare
        let access_bits = cursor.read_u8()?;
        let layered_key_flags = cursor.read_u8()?;
        let access_spare = cursor.read_u16::<LittleEndian>()?;
        let parent = cursor.read_u32::<LittleEndian>()?;
        let num_subkeys = cursor.read_u32::<LittleEndian>()?;
        let num_volatile_subkeys = cursor.read_u32::<LittleEndian>()?;
        let subkeys_list_offset = cursor.read_u32::<LittleEndian>()?;
        let volatile_subkeys_list_offset = cursor.read_u32::<LittleEndian>()?;
        let num_values = cursor.read_u32::<LittleEndian>()?;
        let values_list_offset = cursor.read_u32::<LittleEndian>()?;
        let security_offset = cursor.read_u32::<LittleEndian>()?;
        let class_name_offset = cursor.read_u32::<LittleEndian>()?;

        // Read the combined field that contains multiple subfields
        let largest_subkey_name_combined = cursor.read_u32::<LittleEndian>()?;
        let largest_subkey_name_length = (largest_subkey_name_combined & 0xFFFF) as u16;
        let virtualization_flags = ((largest_subkey_name_combined >> 16) & 0x0F) as u8;
        let user_flags = ((largest_subkey_name_combined >> 20) & 0x0F) as u8;
        let debug = ((largest_subkey_name_combined >> 24) & 0xFF) as u8;

        let largest_subkey_class_name_length = cursor.read_u32::<LittleEndian>()?;
        let largest_value_name_length = cursor.read_u32::<LittleEndian>()?;
        let largest_value_data_size = cursor.read_u32::<LittleEndian>()?;
        let work_var = cursor.read_u32::<LittleEndian>()?;
        let key_name_length = cursor.read_u16::<LittleEndian>()?;
        let class_name_length = cursor.read_u16::<LittleEndian>()?;

        // Read key name
        let name_start = Self::FIXED_SIZE;
        let name_end = name_start + key_name_length as usize;

        if data.len() < name_end {
            return Err(Error::BufferTooSmall {
                needed: name_end,
                available: data.len(),
            });
        }

        let key_name = data[name_start..name_end].to_vec();

        Ok(Self {
            signature,
            flags,
            last_written,
            access_bits,
            layered_key_flags,
            access_spare,
            parent,
            num_subkeys,
            num_volatile_subkeys,
            subkeys_list_offset,
            volatile_subkeys_list_offset,
            num_values,
            values_list_offset,
            security_offset,
            class_name_offset,
            largest_subkey_name_length,
            virtualization_flags,
            user_flags,
            debug,
            largest_subkey_class_name_length,
            largest_value_name_length,
            largest_value_data_size,
            work_var,
            key_name_length,
            class_name_length,
            key_name,
        })
    }

    /// Write the key node to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.flags)?;
        writer.write_u64::<LittleEndian>(self.last_written)?;
        // Access bits field: byte 0 = access bits, byte 1 = layered key flags, bytes 2-3 = spare
        writer.write_u8(self.access_bits)?;
        writer.write_u8(self.layered_key_flags)?;
        writer.write_u16::<LittleEndian>(self.access_spare)?;
        writer.write_u32::<LittleEndian>(self.parent)?;
        writer.write_u32::<LittleEndian>(self.num_subkeys)?;
        writer.write_u32::<LittleEndian>(self.num_volatile_subkeys)?;
        writer.write_u32::<LittleEndian>(self.subkeys_list_offset)?;
        writer.write_u32::<LittleEndian>(self.volatile_subkeys_list_offset)?;
        writer.write_u32::<LittleEndian>(self.num_values)?;
        writer.write_u32::<LittleEndian>(self.values_list_offset)?;
        writer.write_u32::<LittleEndian>(self.security_offset)?;
        writer.write_u32::<LittleEndian>(self.class_name_offset)?;

        // Write combined field
        let combined = (self.largest_subkey_name_length as u32)
            | ((self.virtualization_flags as u32) << 16)
            | ((self.user_flags as u32) << 20)
            | ((self.debug as u32) << 24);
        writer.write_u32::<LittleEndian>(combined)?;

        writer.write_u32::<LittleEndian>(self.largest_subkey_class_name_length)?;
        writer.write_u32::<LittleEndian>(self.largest_value_name_length)?;
        writer.write_u32::<LittleEndian>(self.largest_value_data_size)?;
        writer.write_u32::<LittleEndian>(self.work_var)?;
        writer.write_u16::<LittleEndian>(self.key_name_length)?;
        writer.write_u16::<LittleEndian>(self.class_name_length)?;
        writer.write_all(&self.key_name)?;

        Ok(())
    }

    /// Get the key name as a string.
    pub fn name(&self) -> String {
        let key_flags = self.get_flags();

        if key_flags.contains(KeyNodeFlags::KEY_COMP_NAME) {
            // ASCII name
            decode_ascii_string(&self.key_name)
        } else {
            // UTF-16LE name
            decode_utf16le_string(&self.key_name).unwrap_or_default()
        }
    }

    /// Set the key name.
    pub fn set_name(&mut self, name: &str) {
        // Determine if we can use ASCII encoding
        let can_use_ascii = name.chars().all(|c| c as u32 <= 255);

        if can_use_ascii {
            self.key_name = encode_ascii_string(name);
            self.flags |= KeyNodeFlags::KEY_COMP_NAME.bits();
        } else {
            self.key_name = encode_utf16le_string(name);
            self.key_name.truncate(self.key_name.len() - 2); // Remove null terminator
            self.flags &= !KeyNodeFlags::KEY_COMP_NAME.bits();
        }

        self.key_name_length = self.key_name.len() as u16;
    }

    /// Get the flags.
    pub fn get_flags(&self) -> KeyNodeFlags {
        KeyNodeFlags::from_bits_truncate(self.flags)
    }

    /// Check if this is the root key.
    pub fn is_root(&self) -> bool {
        self.get_flags().contains(KeyNodeFlags::KEY_HIVE_ENTRY)
    }

    /// Check if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.get_flags().contains(KeyNodeFlags::KEY_SYM_LINK)
    }

    /// Check if this key has subkeys.
    pub fn has_subkeys(&self) -> bool {
        self.num_subkeys > 0 && self.subkeys_list_offset != INVALID_OFFSET
    }

    /// Check if this key has values.
    pub fn has_values(&self) -> bool {
        self.num_values > 0 && self.values_list_offset != INVALID_OFFSET
    }

    /// Get the access bits.
    pub fn get_access_bits(&self) -> AccessBits {
        AccessBits::from_bits_truncate(self.access_bits)
    }

    /// Get the layered key flags (Windows 10 RS1+).
    pub fn get_layered_key_flags(&self) -> LayeredKeyFlags {
        LayeredKeyFlags::from_raw(self.layered_key_flags)
    }

    /// Check if this is a tombstone key (layered keys feature).
    pub fn is_tombstone(&self) -> bool {
        self.get_layered_key_flags().layer_semantics() == LayerSemantics::IsTombstone
    }

    /// Get the debug flags.
    /// These control breakpoints in checked Windows kernels when CmpRegDebugBreakEnabled is set.
    pub fn get_debug_flags(&self) -> DebugFlags {
        DebugFlags::from_bits_truncate(self.debug)
    }

    /// Get the user flags (Wow64 flags).
    pub fn get_user_flags(&self) -> UserFlags {
        UserFlags::from_bits_truncate(self.user_flags)
    }

    /// Get the virtualization control flags.
    pub fn get_virtualization_flags(&self) -> VirtualizationFlags {
        VirtualizationFlags::from_bits_truncate(self.virtualization_flags)
    }

    /// Check if this key has a class name.
    pub fn has_class_name(&self) -> bool {
        self.class_name_offset != INVALID_OFFSET && self.class_name_length > 0
    }

    /// Check if this key is a predefined handle.
    /// When true, the `num_values` field contains a handle instead of a value count.
    pub fn is_predef_handle(&self) -> bool {
        self.get_flags().contains(KeyNodeFlags::KEY_PREDEF_HANDLE)
    }

    /// Get the predefined handle value (if this is a predefined handle key).
    /// Returns None if KEY_PREDEF_HANDLE flag is not set.
    pub fn get_predef_handle(&self) -> Option<u32> {
        if self.is_predef_handle() {
            Some(self.num_values)
        } else {
            None
        }
    }

    /// Create a new key node.
    pub fn new(name: &str, parent_offset: u32, is_root: bool) -> Self {
        let mut node = Self {
            signature: *signatures::KEY_NODE,
            flags: 0,
            last_written: 0,
            access_bits: 0,
            layered_key_flags: 0,
            access_spare: 0,
            parent: parent_offset,
            num_subkeys: 0,
            num_volatile_subkeys: 0,
            subkeys_list_offset: INVALID_OFFSET,
            volatile_subkeys_list_offset: INVALID_OFFSET,
            num_values: 0,
            values_list_offset: INVALID_OFFSET,
            security_offset: INVALID_OFFSET,
            class_name_offset: INVALID_OFFSET,
            largest_subkey_name_length: 0,
            virtualization_flags: 0,
            user_flags: 0,
            debug: 0,
            largest_subkey_class_name_length: 0,
            largest_value_name_length: 0,
            largest_value_data_size: 0,
            work_var: 0,
            key_name_length: 0,
            class_name_length: 0,
            key_name: Vec::new(),
        };

        node.set_name(name);

        if is_root {
            node.flags |= KeyNodeFlags::KEY_HIVE_ENTRY.bits();
        }

        node
    }

    /// Get the total size needed for this key node.
    pub fn total_size(&self) -> usize {
        Self::FIXED_SIZE + self.key_name.len()
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
    fn test_key_node_creation() {
        let node = KeyNode::new("TestKey", 0, false);
        assert_eq!(node.name(), "TestKey");
        assert!(!node.is_root());
    }

    #[test]
    fn test_key_node_root() {
        let node = KeyNode::new("CMI-CreateHive{...}", INVALID_OFFSET, true);
        assert!(node.is_root());
    }

    #[test]
    fn test_key_node_roundtrip() {
        let node = KeyNode::new("TestKey", 100, false);
        let bytes = node.to_bytes();
        let parsed = KeyNode::parse(&bytes).unwrap();
        assert_eq!(parsed.name(), node.name());
        assert_eq!(parsed.parent, node.parent);
    }
}

