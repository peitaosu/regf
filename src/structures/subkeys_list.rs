//! Subkeys list structures (li, lf, lh, ri).
//!
//! These structures store lists of subkeys for key nodes.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::signatures;

/// Index leaf element (li).
#[derive(Debug, Clone, Copy)]
pub struct IndexLeafElement {
    /// Offset of key node.
    pub key_node_offset: u32,
}

/// Fast leaf element (lf).
///
/// The name hint contains the first 4 ASCII characters of the key name.
/// Per the spec:
/// - If a key name is less than 4 characters, unused bytes are null-padded
/// - UTF-16LE characters are converted to ASCII (extended ASCII if code < 256)
/// - If any character cannot be converted to ASCII, the first byte is null
#[derive(Debug, Clone, Copy)]
pub struct FastLeafElement {
    /// Offset of key node.
    pub key_node_offset: u32,
    /// First 4 characters of key name as ASCII (hint for lookups).
    pub name_hint: [u8; 4],
}

impl FastLeafElement {
    /// Create a name hint from a key name string.
    ///
    /// The hint contains the first 4 ASCII characters of the name.
    /// If any character is not ASCII-compatible (code >= 256), the first byte
    /// is set to null as per the specification.
    pub fn create_name_hint(name: &str) -> [u8; 4] {
        let mut hint = [0u8; 4];
        for (i, c) in name.chars().take(4).enumerate() {
            let code = c as u32;
            if code <= 255 {
                hint[i] = code as u8;
            } else {
                // If any char is not ASCII-compatible, null the first byte per spec
                hint[0] = 0;
                break;
            }
        }
        hint
    }

    /// Get the name hint as a string (for display/debugging).
    pub fn hint_as_string(&self) -> String {
        self.name_hint
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect()
    }

    /// Check if the name hint potentially matches a key name.
    /// This is used for quick lookups - a mismatch means definite no match,
    /// but a match requires full name comparison.
    pub fn hint_matches(&self, name: &str) -> bool {
        let target_hint = Self::create_name_hint(name);

        // If either hint has null first byte, can't use for matching
        if self.name_hint[0] == 0 || target_hint[0] == 0 {
            return true; // Must do full comparison
        }

        self.name_hint == target_hint
    }
}

/// Hash leaf element (lh).
#[derive(Debug, Clone, Copy)]
pub struct HashLeafElement {
    /// Offset of key node.
    pub key_node_offset: u32,
    /// Hash of key name.
    pub name_hash: u32,
}

/// Index root element (ri).
#[derive(Debug, Clone, Copy)]
pub struct IndexRootElement {
    /// Offset of subkeys list.
    pub subkeys_list_offset: u32,
}

/// Index leaf list (li).
#[derive(Debug, Clone)]
pub struct IndexLeaf {
    /// Signature: "li"
    pub signature: [u8; 2],
    /// Number of elements.
    pub num_elements: u16,
    /// List elements.
    pub elements: Vec<IndexLeafElement>,
}

impl IndexLeaf {
    /// Fixed header size.
    pub const HEADER_SIZE: usize = 4;

    /// Parse an index leaf from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 2];
        cursor.read_exact(&mut signature)?;

        if &signature != signatures::INDEX_LEAF {
            return Err(Error::InvalidSignature {
                expected: "li".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let num_elements = cursor.read_u16::<LittleEndian>()?;

        let needed = Self::HEADER_SIZE + (num_elements as usize * 4);
        if data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: data.len(),
            });
        }

        let mut elements = Vec::with_capacity(num_elements as usize);
        for _ in 0..num_elements {
            let key_node_offset = cursor.read_u32::<LittleEndian>()?;
            elements.push(IndexLeafElement { key_node_offset });
        }

        Ok(Self {
            signature,
            num_elements,
            elements,
        })
    }

    /// Write the index leaf to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.num_elements)?;
        for elem in &self.elements {
            writer.write_u32::<LittleEndian>(elem.key_node_offset)?;
        }
        Ok(())
    }

    /// Create a new index leaf.
    pub fn new() -> Self {
        Self {
            signature: *signatures::INDEX_LEAF,
            num_elements: 0,
            elements: Vec::new(),
        }
    }

    /// Get the total size.
    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE + (self.elements.len() * 4)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

impl Default for IndexLeaf {
    fn default() -> Self {
        Self::new()
    }
}

/// Fast leaf list (lf).
#[derive(Debug, Clone)]
pub struct FastLeaf {
    /// Signature: "lf"
    pub signature: [u8; 2],
    /// Number of elements.
    pub num_elements: u16,
    /// List elements.
    pub elements: Vec<FastLeafElement>,
}

impl FastLeaf {
    /// Fixed header size.
    pub const HEADER_SIZE: usize = 4;

    /// Parse a fast leaf from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 2];
        cursor.read_exact(&mut signature)?;

        if &signature != signatures::FAST_LEAF {
            return Err(Error::InvalidSignature {
                expected: "lf".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let num_elements = cursor.read_u16::<LittleEndian>()?;

        let needed = Self::HEADER_SIZE + (num_elements as usize * 8);
        if data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: data.len(),
            });
        }

        let mut elements = Vec::with_capacity(num_elements as usize);
        for _ in 0..num_elements {
            let key_node_offset = cursor.read_u32::<LittleEndian>()?;
            let mut name_hint = [0u8; 4];
            cursor.read_exact(&mut name_hint)?;
            elements.push(FastLeafElement {
                key_node_offset,
                name_hint,
            });
        }

        Ok(Self {
            signature,
            num_elements,
            elements,
        })
    }

    /// Write the fast leaf to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.num_elements)?;
        for elem in &self.elements {
            writer.write_u32::<LittleEndian>(elem.key_node_offset)?;
            writer.write_all(&elem.name_hint)?;
        }
        Ok(())
    }

    /// Create a new fast leaf.
    pub fn new() -> Self {
        Self {
            signature: *signatures::FAST_LEAF,
            num_elements: 0,
            elements: Vec::new(),
        }
    }

    /// Get the total size.
    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE + (self.elements.len() * 8)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

impl Default for FastLeaf {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash leaf list (lh).
#[derive(Debug, Clone)]
pub struct HashLeaf {
    /// Signature: "lh"
    pub signature: [u8; 2],
    /// Number of elements.
    pub num_elements: u16,
    /// List elements.
    pub elements: Vec<HashLeafElement>,
}

impl HashLeaf {
    /// Fixed header size.
    pub const HEADER_SIZE: usize = 4;

    /// Parse a hash leaf from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 2];
        cursor.read_exact(&mut signature)?;

        if &signature != signatures::HASH_LEAF {
            return Err(Error::InvalidSignature {
                expected: "lh".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let num_elements = cursor.read_u16::<LittleEndian>()?;

        let needed = Self::HEADER_SIZE + (num_elements as usize * 8);
        if data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: data.len(),
            });
        }

        let mut elements = Vec::with_capacity(num_elements as usize);
        for _ in 0..num_elements {
            let key_node_offset = cursor.read_u32::<LittleEndian>()?;
            let name_hash = cursor.read_u32::<LittleEndian>()?;
            elements.push(HashLeafElement {
                key_node_offset,
                name_hash,
            });
        }

        Ok(Self {
            signature,
            num_elements,
            elements,
        })
    }

    /// Write the hash leaf to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.num_elements)?;
        for elem in &self.elements {
            writer.write_u32::<LittleEndian>(elem.key_node_offset)?;
            writer.write_u32::<LittleEndian>(elem.name_hash)?;
        }
        Ok(())
    }

    /// Create a new hash leaf.
    pub fn new() -> Self {
        Self {
            signature: *signatures::HASH_LEAF,
            num_elements: 0,
            elements: Vec::new(),
        }
    }

    /// Get the total size.
    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE + (self.elements.len() * 8)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

impl Default for HashLeaf {
    fn default() -> Self {
        Self::new()
    }
}

/// Index root list (ri).
#[derive(Debug, Clone)]
pub struct IndexRoot {
    /// Signature: "ri"
    pub signature: [u8; 2],
    /// Number of elements.
    pub num_elements: u16,
    /// List elements.
    pub elements: Vec<IndexRootElement>,
}

impl IndexRoot {
    /// Fixed header size.
    pub const HEADER_SIZE: usize = 4;

    /// Parse an index root from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::BufferTooSmall {
                needed: Self::HEADER_SIZE,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 2];
        cursor.read_exact(&mut signature)?;

        if &signature != signatures::INDEX_ROOT {
            return Err(Error::InvalidSignature {
                expected: "ri".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let num_elements = cursor.read_u16::<LittleEndian>()?;

        let needed = Self::HEADER_SIZE + (num_elements as usize * 4);
        if data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: data.len(),
            });
        }

        let mut elements = Vec::with_capacity(num_elements as usize);
        for _ in 0..num_elements {
            let subkeys_list_offset = cursor.read_u32::<LittleEndian>()?;
            elements.push(IndexRootElement { subkeys_list_offset });
        }

        Ok(Self {
            signature,
            num_elements,
            elements,
        })
    }

    /// Write the index root to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.num_elements)?;
        for elem in &self.elements {
            writer.write_u32::<LittleEndian>(elem.subkeys_list_offset)?;
        }
        Ok(())
    }

    /// Create a new index root.
    pub fn new() -> Self {
        Self {
            signature: *signatures::INDEX_ROOT,
            num_elements: 0,
            elements: Vec::new(),
        }
    }

    /// Get the total size.
    pub fn total_size(&self) -> usize {
        Self::HEADER_SIZE + (self.elements.len() * 4)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

impl Default for IndexRoot {
    fn default() -> Self {
        Self::new()
    }
}

/// Enumeration of all subkeys list types.
#[derive(Debug, Clone)]
pub enum SubkeysList {
    /// Index leaf (li).
    IndexLeaf(IndexLeaf),
    /// Fast leaf (lf).
    FastLeaf(FastLeaf),
    /// Hash leaf (lh).
    HashLeaf(HashLeaf),
    /// Index root (ri).
    IndexRoot(IndexRoot),
}

impl SubkeysList {
    /// Parse a subkeys list from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::BufferTooSmall {
                needed: 2,
                available: data.len(),
            });
        }

        let sig: [u8; 2] = [data[0], data[1]];

        match &sig {
            b"li" => Ok(SubkeysList::IndexLeaf(IndexLeaf::parse(data)?)),
            b"lf" => Ok(SubkeysList::FastLeaf(FastLeaf::parse(data)?)),
            b"lh" => Ok(SubkeysList::HashLeaf(HashLeaf::parse(data)?)),
            b"ri" => Ok(SubkeysList::IndexRoot(IndexRoot::parse(data)?)),
            _ => Err(Error::UnknownCellType(sig)),
        }
    }

    /// Get all key node offsets from this list.
    pub fn get_offsets(&self) -> Vec<u32> {
        match self {
            SubkeysList::IndexLeaf(il) => il.elements.iter().map(|e| e.key_node_offset).collect(),
            SubkeysList::FastLeaf(fl) => fl.elements.iter().map(|e| e.key_node_offset).collect(),
            SubkeysList::HashLeaf(hl) => hl.elements.iter().map(|e| e.key_node_offset).collect(),
            SubkeysList::IndexRoot(ir) => ir.elements.iter().map(|e| e.subkeys_list_offset).collect(),
        }
    }

    /// Check if this is an index root.
    pub fn is_index_root(&self) -> bool {
        matches!(self, SubkeysList::IndexRoot(_))
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SubkeysList::IndexLeaf(il) => il.to_bytes(),
            SubkeysList::FastLeaf(fl) => fl.to_bytes(),
            SubkeysList::HashLeaf(hl) => hl.to_bytes(),
            SubkeysList::IndexRoot(ir) => ir.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_leaf() {
        let mut il = IndexLeaf::new();
        il.elements.push(IndexLeafElement { key_node_offset: 100 });
        il.elements.push(IndexLeafElement { key_node_offset: 200 });
        il.num_elements = il.elements.len() as u16;

        let bytes = il.to_bytes();
        let parsed = IndexLeaf::parse(&bytes).unwrap();

        assert_eq!(parsed.num_elements, 2);
        assert_eq!(parsed.elements[0].key_node_offset, 100);
        assert_eq!(parsed.elements[1].key_node_offset, 200);
    }

    #[test]
    fn test_hash_leaf() {
        let mut hl = HashLeaf::new();
        hl.elements.push(HashLeafElement {
            key_node_offset: 100,
            name_hash: 12345,
        });
        hl.num_elements = hl.elements.len() as u16;

        let bytes = hl.to_bytes();
        let parsed = HashLeaf::parse(&bytes).unwrap();

        assert_eq!(parsed.num_elements, 1);
        assert_eq!(parsed.elements[0].key_node_offset, 100);
        assert_eq!(parsed.elements[0].name_hash, 12345);
    }
}

