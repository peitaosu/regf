//! Low-level parser for registry hive files.
//!
//! This module handles reading and parsing the raw binary data of registry hives.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Error, Result};
use crate::structures::*;

/// Low-level parser for registry hive files.
pub struct HiveParser<R> {
    reader: R,
    base_block: BaseBlock,
    hive_bins: Vec<HiveBin>,
    /// Map from cell offset to hive bin index.
    #[allow(dead_code)]
    cell_to_bin: HashMap<u32, usize>,
}

impl<R: Read + Seek> HiveParser<R> {
    /// Create a new parser from a reader.
    pub fn new(mut reader: R) -> Result<Self> {
        // Read base block
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        reader.read_exact(&mut base_block_data)?;
        let base_block = BaseBlock::parse(&base_block_data)?;

        // Check version
        // We support versions 1.3-1.6 (NT 4.0 through Windows 11)
        // Versions 1.1-1.2 (NT 3.1, NT 3.5) have different cell structure and aren't supported
        if base_block.major_version != 1 || base_block.minor_version < 3 {
            return Err(Error::UnsupportedVersion {
                major: base_block.major_version,
                minor: base_block.minor_version,
            });
        }

        // Note: Version 1.3 doesn't support Fast Leaf
        // Version 1.4 doesn't support Hash Leaf or Big Data
        // We handle these gracefully during parsing

        // Read hive bins
        let mut hive_bins = Vec::new();
        let mut cell_to_bin = HashMap::new();
        let mut offset = 0u32;

        while offset < base_block.hive_bins_data_size {
            // Seek to bin position
            reader.seek(SeekFrom::Start(BASE_BLOCK_SIZE as u64 + offset as u64))?;

            // Read bin header first to get size
            let mut header_data = vec![0u8; HIVE_BIN_HEADER_SIZE];
            reader.read_exact(&mut header_data)?;

            // Check signature
            if &header_data[0..4] != HBIN_SIGNATURE {
                break;
            }

            let bin_size = u32::from_le_bytes([
                header_data[8],
                header_data[9],
                header_data[10],
                header_data[11],
            ]);

            // Read full bin
            reader.seek(SeekFrom::Start(BASE_BLOCK_SIZE as u64 + offset as u64))?;
            let mut bin_data = vec![0u8; bin_size as usize];
            reader.read_exact(&mut bin_data)?;

            let bin = HiveBin::parse(&bin_data)?;
            let bin_idx = hive_bins.len();

            // Map cells in this bin
            let mut cell_offset = 0;
            while cell_offset < bin.data.len() {
                let cell_abs_offset = offset + HIVE_BIN_HEADER_SIZE as u32 + cell_offset as u32;
                cell_to_bin.insert(cell_abs_offset, bin_idx);

                // Read cell size
                if cell_offset + 4 > bin.data.len() {
                    break;
                }

                let cell_size = i32::from_le_bytes([
                    bin.data[cell_offset],
                    bin.data[cell_offset + 1],
                    bin.data[cell_offset + 2],
                    bin.data[cell_offset + 3],
                ]);

                let abs_cell_size = cell_size.abs() as usize;
                if abs_cell_size < 8 || cell_offset + abs_cell_size > bin.data.len() {
                    break;
                }

                cell_offset += abs_cell_size;
            }

            hive_bins.push(bin);
            offset += bin_size;
        }

        Ok(Self {
            reader,
            base_block,
            hive_bins,
            cell_to_bin,
        })
    }

    /// Get the base block.
    pub fn base_block(&self) -> &BaseBlock {
        &self.base_block
    }

    /// Get a mutable reference to the base block.
    pub fn base_block_mut(&mut self) -> &mut BaseBlock {
        &mut self.base_block
    }

    /// Get the hive bins.
    pub fn hive_bins(&self) -> &[HiveBin] {
        &self.hive_bins
    }

    /// Get the root cell offset.
    pub fn root_cell_offset(&self) -> u32 {
        self.base_block.root_cell_offset
    }

    /// Read a cell at the given offset.
    pub fn read_cell(&self, offset: u32) -> Result<RawCell> {
        if offset == INVALID_OFFSET {
            return Err(Error::InvalidCellOffset(offset));
        }

        // Find which bin contains this cell
        let (bin_idx, local_offset) = self.find_bin_for_offset(offset)?;
        let bin = &self.hive_bins[bin_idx];

        if local_offset >= bin.data.len() {
            return Err(Error::InvalidCellOffset(offset));
        }

        RawCell::parse(&bin.data[local_offset..], offset)
    }

    /// Find the bin index and local offset for a cell offset.
    fn find_bin_for_offset(&self, offset: u32) -> Result<(usize, usize)> {
        // Cell offset is relative to start of hive bins data
        let mut current_offset = 0u32;

        for (idx, bin) in self.hive_bins.iter().enumerate() {
            let bin_end = current_offset + bin.header.size;

            if offset >= current_offset && offset < bin_end {
                let local_offset = (offset - current_offset) as usize;
                if local_offset < HIVE_BIN_HEADER_SIZE {
                    return Err(Error::InvalidCellOffset(offset));
                }
                return Ok((idx, local_offset - HIVE_BIN_HEADER_SIZE));
            }

            current_offset = bin_end;
        }

        Err(Error::InvalidCellOffset(offset))
    }

    /// Read a key node at the given offset.
    pub fn read_key_node(&self, offset: u32) -> Result<KeyNode> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        KeyNode::parse(&cell.data)
    }

    /// Read a key value at the given offset.
    pub fn read_key_value(&self, offset: u32) -> Result<KeyValue> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        KeyValue::parse(&cell.data)
    }

    /// Read a key security item at the given offset.
    pub fn read_key_security(&self, offset: u32) -> Result<KeySecurity> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        KeySecurity::parse(&cell.data)
    }

    /// Read a subkeys list at the given offset.
    pub fn read_subkeys_list(&self, offset: u32) -> Result<SubkeysList> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        SubkeysList::parse(&cell.data)
    }

    /// Read a key values list at the given offset.
    pub fn read_values_list(&self, offset: u32, count: u32) -> Result<Vec<u32>> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        let needed = (count as usize) * 4;
        if cell.data.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                available: cell.data.len(),
            });
        }

        let mut offsets = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let o = i * 4;
            let value_offset = u32::from_le_bytes([
                cell.data[o],
                cell.data[o + 1],
                cell.data[o + 2],
                cell.data[o + 3],
            ]);
            offsets.push(value_offset);
        }

        Ok(offsets)
    }

    /// Read value data at the given offset with the specified size.
    pub fn read_value_data(&self, offset: u32, size: u32) -> Result<Vec<u8>> {
        let cell = self.read_cell(offset)?;

        if !cell.is_allocated() {
            return Err(Error::UnallocatedCell(offset));
        }

        // Check for big data
        if cell.data.len() >= 2 && &cell.data[0..2] == signatures::BIG_DATA {
            return self.read_big_data(&cell.data);
        }

        let data_size = size.min(cell.data.len() as u32) as usize;
        Ok(cell.data[..data_size].to_vec())
    }

    /// Read big data.
    fn read_big_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let big_data = BigData::parse(data)?;
        let segments_list_cell = self.read_cell(big_data.segments_list_offset)?;
        let segments_list = DataSegmentsList::parse(&segments_list_cell.data, big_data.num_segments)?;

        let mut result = Vec::new();

        for &segment_offset in &segments_list.offsets {
            let segment_cell = self.read_cell(segment_offset)?;
            result.extend_from_slice(&segment_cell.data);
        }

        Ok(result)
    }

    /// Get all subkey offsets for a key node.
    pub fn get_subkey_offsets(&self, key_node: &KeyNode) -> Result<Vec<u32>> {
        if !key_node.has_subkeys() {
            return Ok(Vec::new());
        }

        let list = self.read_subkeys_list(key_node.subkeys_list_offset)?;
        self.collect_subkey_offsets(&list)
    }

    /// Recursively collect subkey offsets from a subkeys list.
    fn collect_subkey_offsets(&self, list: &SubkeysList) -> Result<Vec<u32>> {
        if let SubkeysList::IndexRoot(ir) = list {
            // Recursively collect from sub-lists
            let mut offsets = Vec::new();
            for elem in &ir.elements {
                let sub_list = self.read_subkeys_list(elem.subkeys_list_offset)?;
                offsets.extend(self.collect_subkey_offsets(&sub_list)?);
            }
            Ok(offsets)
        } else {
            Ok(list.get_offsets())
        }
    }

    /// Get all value offsets for a key node.
    pub fn get_value_offsets(&self, key_node: &KeyNode) -> Result<Vec<u32>> {
        if !key_node.has_values() {
            return Ok(Vec::new());
        }

        self.read_values_list(key_node.values_list_offset, key_node.num_values)
    }

    /// Get the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_minimal_hive() -> Vec<u8> {
        let mut data = vec![0u8; 8192]; // Base block + one hive bin

        // Base block
        data[0..4].copy_from_slice(b"regf");
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // Primary sequence
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // Secondary sequence
        data[20..24].copy_from_slice(&1u32.to_le_bytes()); // Major version
        data[24..28].copy_from_slice(&6u32.to_le_bytes()); // Minor version
        data[28..32].copy_from_slice(&0u32.to_le_bytes()); // File type
        data[32..36].copy_from_slice(&1u32.to_le_bytes()); // File format
        data[36..40].copy_from_slice(&32u32.to_le_bytes()); // Root cell offset
        data[40..44].copy_from_slice(&4096u32.to_le_bytes()); // Hive bins data size
        data[44..48].copy_from_slice(&1u32.to_le_bytes()); // Clustering factor

        // Calculate and set checksum
        let checksum = calculate_checksum(&data[..512]);
        data[508..512].copy_from_slice(&checksum.to_le_bytes());

        // Hive bin header at offset 4096
        let bin_offset = 4096;
        data[bin_offset..bin_offset + 4].copy_from_slice(b"hbin");
        data[bin_offset + 4..bin_offset + 8].copy_from_slice(&0u32.to_le_bytes()); // Offset
        data[bin_offset + 8..bin_offset + 12].copy_from_slice(&4096u32.to_le_bytes()); // Size

        // Root key node cell at offset 32
        let cell_offset = bin_offset + 32;
        let cell_size: i32 = -88; // Negative = allocated
        data[cell_offset..cell_offset + 4].copy_from_slice(&cell_size.to_le_bytes());

        // Key node data
        let nk_offset = cell_offset + 4;
        data[nk_offset..nk_offset + 2].copy_from_slice(b"nk");
        data[nk_offset + 2..nk_offset + 4].copy_from_slice(&4u16.to_le_bytes()); // Flags: KEY_HIVE_ENTRY
        // ... rest of key node fields would go here

        data
    }

    #[test]
    fn test_parse_minimal_hive() {
        let data = create_minimal_hive();
        let cursor = Cursor::new(data);
        let parser = HiveParser::new(cursor).unwrap();

        assert_eq!(parser.base_block().major_version, 1);
        assert_eq!(parser.base_block().minor_version, 6);
        assert_eq!(parser.hive_bins().len(), 1);
    }
}

