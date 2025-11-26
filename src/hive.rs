//! High-level registry hive API.
//!
//! This module provides a user-friendly interface for working with registry hives.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use crate::error::{Error, Result};
use crate::parser::HiveParser;
use crate::structures::*;

/// A registry hive loaded into memory.
pub struct RegistryHive {
    /// The underlying parser.
    parser: HiveParser<Cursor<Vec<u8>>>,
    /// Cache of parsed key nodes (for future optimization).
    #[allow(dead_code)]
    key_cache: HashMap<u32, KeyNode>,
    /// Cache of parsed values (for future optimization).
    #[allow(dead_code)]
    value_cache: HashMap<u32, KeyValue>,
}

impl RegistryHive {
    /// Load a registry hive from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        Self::from_reader(&mut reader)
    }

    /// Load a registry hive from a reader.
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Self::from_bytes(data)
    }

    /// Load a registry hive from bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let cursor = Cursor::new(data);
        let parser = HiveParser::new(cursor)?;

        Ok(Self {
            parser,
            key_cache: HashMap::new(),
            value_cache: HashMap::new(),
        })
    }

    /// Create a new empty registry hive.
    pub fn new() -> Result<Self> {
        let mut data = vec![0u8; BASE_BLOCK_SIZE + MIN_HIVE_BIN_SIZE];

        // Create base block
        let mut base_block = BaseBlock::default();
        base_block.root_cell_offset = HIVE_BIN_HEADER_SIZE as u32; // First cell in first bin
        base_block.hive_bins_data_size = MIN_HIVE_BIN_SIZE as u32;

        {
            let mut cursor = Cursor::new(&mut data[..]);
            base_block.write(&mut cursor)?;
        }

        // Create first hive bin
        let bin = HiveBin::new(0, MIN_HIVE_BIN_SIZE as u32);
        {
            let mut cursor = Cursor::new(&mut data[BASE_BLOCK_SIZE..]);
            bin.write(&mut cursor)?;
        }

        // Create root key node
        let root_key = KeyNode::new("", INVALID_OFFSET, true);
        let root_bytes = root_key.to_bytes();
        let cell_size = required_cell_size(root_bytes.len());

        // Write root cell
        let cell_offset = BASE_BLOCK_SIZE + HIVE_BIN_HEADER_SIZE;
        let cell_size_value = -(cell_size as i32);
        data[cell_offset..cell_offset + 4].copy_from_slice(&cell_size_value.to_le_bytes());
        data[cell_offset + 4..cell_offset + 4 + root_bytes.len()].copy_from_slice(&root_bytes);

        // Write remaining free cell
        let free_offset = cell_offset + cell_size;
        let free_size = MIN_HIVE_BIN_SIZE - HIVE_BIN_HEADER_SIZE - cell_size;
        data[free_offset..free_offset + 4].copy_from_slice(&(free_size as i32).to_le_bytes());

        // Recalculate checksum
        let checksum = calculate_checksum(&data[..512]);
        data[508..512].copy_from_slice(&checksum.to_le_bytes());

        Self::from_bytes(data)
    }

    /// Get the base block.
    pub fn base_block(&self) -> &BaseBlock {
        self.parser.base_block()
    }

    /// Get the root key.
    pub fn root_key(&self) -> Result<RegistryKey> {
        let offset = self.parser.root_cell_offset();
        self.get_key_at_offset(offset)
    }

    /// Get a key at a specific offset.
    fn get_key_at_offset(&self, offset: u32) -> Result<RegistryKey> {
        let node = self.parser.read_key_node(offset)?;
        Ok(RegistryKey {
            hive: self,
            node,
            offset,
        })
    }

    /// Open a key by path.
    pub fn open_key(&self, path: &str) -> Result<RegistryKey> {
        let root = self.root_key()?;

        if path.is_empty() {
            return Ok(root);
        }

        let parts: Vec<&str> = path
            .trim_start_matches('\\')
            .trim_end_matches('\\')
            .split('\\')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = root;

        for part in parts {
            current = current.open_subkey(part)?;
        }

        Ok(current)
    }

    /// Check if the hive is dirty.
    pub fn is_dirty(&self) -> bool {
        self.parser.base_block().is_dirty()
    }

    /// Get the hive file name.
    pub fn file_name(&self) -> String {
        self.parser.base_block().get_file_name()
    }

    /// Get the hive version.
    pub fn version(&self) -> (u32, u32) {
        let bb = self.parser.base_block();
        (bb.major_version, bb.minor_version)
    }

    /// Get all key paths in the hive.
    pub fn enumerate_all_keys(&self) -> Result<Vec<String>> {
        let root = self.root_key()?;
        let mut paths = Vec::new();
        self.enumerate_keys_recursive(&root, String::new(), &mut paths)?;
        Ok(paths)
    }

    fn enumerate_keys_recursive(
        &self,
        key: &RegistryKey,
        current_path: String,
        paths: &mut Vec<String>,
    ) -> Result<()> {
        let path = if current_path.is_empty() {
            key.name()
        } else if key.name().is_empty() {
            current_path.clone()
        } else {
            format!("{}\\{}", current_path, key.name())
        };

        if !path.is_empty() {
            paths.push(path.clone());
        }

        for subkey in key.subkeys()? {
            self.enumerate_keys_recursive(&subkey, path.clone(), paths)?;
        }

        Ok(())
    }
}

impl Default for RegistryHive {
    fn default() -> Self {
        Self::new().expect("Failed to create default hive")
    }
}

/// A reference to a registry key within a hive.
pub struct RegistryKey<'a> {
    hive: &'a RegistryHive,
    node: KeyNode,
    offset: u32,
}

impl<'a> RegistryKey<'a> {
    /// Get the key name.
    pub fn name(&self) -> String {
        self.node.name()
    }

    /// Get the full path to this key.
    pub fn path(&self) -> Result<String> {
        let mut parts = vec![self.name()];
        let mut current_parent = self.node.parent;

        while current_parent != INVALID_OFFSET {
            match self.hive.parser.read_key_node(current_parent) {
                Ok(parent_node) => {
                    let name = parent_node.name();
                    if !name.is_empty() {
                        parts.push(name);
                    }
                    current_parent = parent_node.parent;
                }
                Err(_) => break,
            }
        }

        parts.reverse();
        Ok(parts.join("\\"))
    }

    /// Get the last written timestamp.
    pub fn last_written(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        filetime_to_datetime(self.node.last_written)
    }

    /// Check if this is the root key.
    pub fn is_root(&self) -> bool {
        self.node.is_root()
    }

    /// Get the number of subkeys.
    pub fn subkey_count(&self) -> u32 {
        self.node.num_subkeys
    }

    /// Get the number of values.
    pub fn value_count(&self) -> u32 {
        self.node.num_values
    }

    /// Get the class name.
    pub fn class_name(&self) -> Result<Option<String>> {
        if self.node.class_name_offset == INVALID_OFFSET || self.node.class_name_length == 0 {
            return Ok(None);
        }

        let cell = self.hive.parser.read_cell(self.node.class_name_offset)?;
        let name = decode_utf16le_string(&cell.data[..self.node.class_name_length as usize])?;
        Ok(Some(name))
    }

    /// Enumerate subkeys.
    pub fn subkeys(&self) -> Result<Vec<RegistryKey<'a>>> {
        if !self.node.has_subkeys() {
            return Ok(Vec::new());
        }

        let offsets = self.hive.parser.get_subkey_offsets(&self.node)?;
        let mut keys = Vec::with_capacity(offsets.len());

        for offset in offsets {
            let node = self.hive.parser.read_key_node(offset)?;
            keys.push(RegistryKey {
                hive: self.hive,
                node,
                offset,
            });
        }

        Ok(keys)
    }

    /// Open a subkey by name.
    pub fn open_subkey(&self, name: &str) -> Result<RegistryKey<'a>> {
        let subkeys = self.subkeys()?;
        let name_upper = name.to_uppercase();

        for key in subkeys {
            if key.name().to_uppercase() == name_upper {
                return Ok(key);
            }
        }

        Err(Error::KeyNotFound(name.to_string()))
    }

    /// Enumerate values.
    pub fn values(&self) -> Result<Vec<RegistryValueEntry<'a>>> {
        if !self.node.has_values() {
            return Ok(Vec::new());
        }

        let offsets = self.hive.parser.get_value_offsets(&self.node)?;
        let mut values = Vec::with_capacity(offsets.len());

        for offset in offsets {
            let value = self.hive.parser.read_key_value(offset)?;
            values.push(RegistryValueEntry {
                hive: self.hive,
                value,
                offset,
            });
        }

        Ok(values)
    }

    /// Get a value by name.
    pub fn value(&self, name: &str) -> Result<RegistryValueEntry<'a>> {
        let values = self.values()?;
        let name_upper = name.to_uppercase();

        for value in values {
            if value.name().to_uppercase() == name_upper {
                return Ok(value);
            }
        }

        Err(Error::ValueNotFound(name.to_string()))
    }

    /// Get the default value.
    pub fn default_value(&self) -> Result<RegistryValueEntry<'a>> {
        self.value("")
    }

    /// Get the raw key node.
    pub fn raw_node(&self) -> &KeyNode {
        &self.node
    }

    /// Get the cell offset.
    pub fn offset(&self) -> u32 {
        self.offset
    }
}

/// A registry value entry.
pub struct RegistryValueEntry<'a> {
    hive: &'a RegistryHive,
    value: KeyValue,
    offset: u32,
}

impl<'a> RegistryValueEntry<'a> {
    /// Get the value name.
    pub fn name(&self) -> String {
        self.value.name()
    }

    /// Check if this is the default value.
    pub fn is_default(&self) -> bool {
        self.value.is_default()
    }

    /// Get the data type.
    pub fn data_type(&self) -> DataType {
        self.value.get_data_type()
    }

    /// Get the raw data type value.
    pub fn raw_data_type(&self) -> u32 {
        self.value.data_type
    }

    /// Get the data size.
    pub fn data_size(&self) -> u32 {
        self.value.actual_data_size()
    }

    /// Get the raw data bytes.
    pub fn raw_data(&self) -> Result<Vec<u8>> {
        if self.value.is_data_resident() {
            return Ok(self.value.get_resident_data().unwrap_or_default());
        }

        if self.value.data_offset == INVALID_OFFSET {
            return Ok(Vec::new());
        }

        self.hive
            .parser
            .read_value_data(self.value.data_offset, self.value.actual_data_size())
    }

    /// Get the data as a parsed RegistryValue.
    pub fn data(&self) -> Result<RegistryValue> {
        let raw_data = self.raw_data()?;
        Ok(RegistryValue::from_bytes(self.data_type(), &raw_data))
    }

    /// Get the data as a string.
    pub fn string_data(&self) -> Result<String> {
        let data = self.data()?;
        match data {
            RegistryValue::String(s) => Ok(s),
            _ => Err(Error::InvalidDataType(self.value.data_type)),
        }
    }

    /// Get the data as a DWORD.
    pub fn dword_data(&self) -> Result<u32> {
        let data = self.data()?;
        match data {
            RegistryValue::Dword(v) => Ok(v),
            RegistryValue::DwordBigEndian(v) => Ok(v),
            _ => Err(Error::InvalidDataType(self.value.data_type)),
        }
    }

    /// Get the data as a QWORD.
    pub fn qword_data(&self) -> Result<u64> {
        let data = self.data()?;
        match data {
            RegistryValue::Qword(v) => Ok(v),
            _ => Err(Error::InvalidDataType(self.value.data_type)),
        }
    }

    /// Get the raw key value.
    pub fn raw_value(&self) -> &KeyValue {
        &self.value
    }

    /// Get the cell offset.
    pub fn offset(&self) -> u32 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_new_hive() {
        let hive = RegistryHive::new().unwrap();
        let root = hive.root_key().unwrap();
        assert!(root.is_root());
    }

    #[test]
    fn test_hive_version() {
        let hive = RegistryHive::new().unwrap();
        let (major, minor) = hive.version();
        assert_eq!(major, 1);
        assert!(minor >= 3);
    }
}

