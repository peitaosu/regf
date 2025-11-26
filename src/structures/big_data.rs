//! Big data (db) structure.
//!
//! Big data is used to store values larger than 16344 bytes.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

use crate::error::{Error, Result};
use crate::structures::{signatures, MAX_DATA_SEGMENT_SIZE};

/// Big data structure (db).
#[derive(Debug, Clone)]
pub struct BigData {
    /// Signature: "db"
    pub signature: [u8; 2],
    /// Number of segments.
    pub num_segments: u16,
    /// Offset of list of segments.
    pub segments_list_offset: u32,
}

impl BigData {
    /// Size of the big data header.
    pub const HEADER_SIZE: usize = 8;

    /// Parse a big data structure from a byte slice.
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

        if &signature != signatures::BIG_DATA {
            return Err(Error::InvalidSignature {
                expected: "db".to_string(),
                found: String::from_utf8_lossy(&signature).to_string(),
            });
        }

        let num_segments = cursor.read_u16::<LittleEndian>()?;
        let segments_list_offset = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            signature,
            num_segments,
            segments_list_offset,
        })
    }

    /// Write the big data structure to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.signature)?;
        writer.write_u16::<LittleEndian>(self.num_segments)?;
        writer.write_u32::<LittleEndian>(self.segments_list_offset)?;
        Ok(())
    }

    /// Create a new big data structure.
    pub fn new(num_segments: u16, segments_list_offset: u32) -> Self {
        Self {
            signature: *signatures::BIG_DATA,
            num_segments,
            segments_list_offset,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }

    /// Calculate number of segments needed for given data size.
    pub fn segments_needed(data_size: usize) -> u16 {
        ((data_size + MAX_DATA_SEGMENT_SIZE - 1) / MAX_DATA_SEGMENT_SIZE) as u16
    }
}

/// List of data segment offsets.
#[derive(Debug, Clone)]
pub struct DataSegmentsList {
    /// List of segment offsets.
    pub offsets: Vec<u32>,
}

impl DataSegmentsList {
    /// Parse a data segments list from a byte slice.
    pub fn parse(data: &[u8], num_segments: u16) -> Result<Self> {
        let needed = num_segments as usize * 4;
        if data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let mut offsets = Vec::with_capacity(num_segments as usize);

        for _ in 0..num_segments {
            let offset = cursor.read_u32::<LittleEndian>()?;
            offsets.push(offset);
        }

        Ok(Self { offsets })
    }

    /// Write the data segments list to a writer.
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for &offset in &self.offsets {
            writer.write_u32::<LittleEndian>(offset)?;
        }
        Ok(())
    }

    /// Create a new data segments list.
    pub fn new() -> Self {
        Self { offsets: Vec::new() }
    }

    /// Get the total size.
    pub fn total_size(&self) -> usize {
        self.offsets.len() * 4
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write(&mut buffer).unwrap();
        buffer
    }
}

impl Default for DataSegmentsList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_data() {
        let bd = BigData::new(3, 100);
        let bytes = bd.to_bytes();
        let parsed = BigData::parse(&bytes).unwrap();

        assert_eq!(parsed.num_segments, 3);
        assert_eq!(parsed.segments_list_offset, 100);
    }

    #[test]
    fn test_segments_needed() {
        assert_eq!(BigData::segments_needed(16344), 1);
        assert_eq!(BigData::segments_needed(16345), 2);
        assert_eq!(BigData::segments_needed(32688), 2);
        assert_eq!(BigData::segments_needed(32689), 3);
    }

    #[test]
    fn test_data_segments_list() {
        let mut list = DataSegmentsList::new();
        list.offsets.push(100);
        list.offsets.push(200);
        list.offsets.push(300);

        let bytes = list.to_bytes();
        let parsed = DataSegmentsList::parse(&bytes, 3).unwrap();

        assert_eq!(parsed.offsets, vec![100, 200, 300]);
    }
}

