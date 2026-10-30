//! Low-level parser for registry hive files.
//!
//! This module handles reading and parsing the raw binary data of registry hives.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use crate::error::{Error, Result};
use crate::structures::*;

/// Low-level parser for registry hive files.
pub struct HiveParser<R> {
    reader: R,
    base_block: BaseBlock,
    hive_bins: Vec<HiveBin>,
    cell_offsets: HashSet<u32>,
}

impl<R: Read + Seek> HiveParser<R> {
    /// Create a new parser from a reader.
    pub fn new(mut reader: R) -> Result<Self> {
        // Read base block
        let mut base_block_data = vec![0u8; BASE_BLOCK_SIZE];
        reader.read_exact(&mut base_block_data)?;
        let base_block = BaseBlock::parse(&base_block_data)?;

        if base_block.major_version != 1 || !(3..=6).contains(&base_block.minor_version) {
            return Err(Error::UnsupportedVersion {
                major: base_block.major_version,
                minor: base_block.minor_version,
            });
        }

        if base_block.file_type != FileType::Primary as u32 {
            return Err(Error::CorruptHive(format!(
                "Invalid primary file type: {}",
                base_block.file_type
            )));
        }
        if base_block.file_format != FileFormat::DirectMemoryLoad as u32 {
            return Err(Error::CorruptHive(format!(
                "Invalid primary file format: {}",
                base_block.file_format
            )));
        }
        if base_block.root_cell_offset == INVALID_OFFSET {
            return Err(Error::InvalidCellOffset(base_block.root_cell_offset));
        }
        if base_block.hive_bins_data_size == 0
            || base_block.hive_bins_data_size % MIN_HIVE_BIN_SIZE as u32 != 0
        {
            return Err(Error::CorruptHive(format!(
                "Invalid hive bins data size: {}",
                base_block.hive_bins_data_size
            )));
        }

        let file_size = reader.seek(SeekFrom::End(0))?;
        let required_file_size = BASE_BLOCK_SIZE as u64 + base_block.hive_bins_data_size as u64;
        if file_size < required_file_size {
            return Err(Error::BufferTooSmall {
                needed: required_file_size as usize,
                available: file_size as usize,
            });
        }

        let mut hive_bins = Vec::new();
        let mut cell_offsets = HashSet::new();
        let mut offset = 0u32;

        while offset < base_block.hive_bins_data_size {
            reader.seek(SeekFrom::Start(BASE_BLOCK_SIZE as u64 + offset as u64))?;

            let mut header_data = vec![0u8; HIVE_BIN_HEADER_SIZE];
            reader.read_exact(&mut header_data)?;
            let header = HiveBinHeader::parse(&header_data)?;
            if header.offset != offset {
                return Err(Error::InvalidHiveBin {
                    offset,
                    message: format!("Declared offset is {}", header.offset),
                });
            }
            let remaining = base_block
                .hive_bins_data_size
                .checked_sub(offset)
                .ok_or_else(|| Error::CorruptHive("Hive bin offset overflow".to_string()))?;
            if header.size > remaining {
                return Err(Error::InvalidHiveBin {
                    offset,
                    message: format!("Size {} exceeds remaining {}", header.size, remaining),
                });
            }

            reader.seek(SeekFrom::Start(BASE_BLOCK_SIZE as u64 + offset as u64))?;
            let mut bin_data = vec![0u8; header.size as usize];
            reader.read_exact(&mut bin_data)?;

            let bin = HiveBin::parse(&bin_data)?;
            let mut local_offset = 0usize;
            while local_offset < bin.data.len() {
                let cell_offset = offset
                    .checked_add(HIVE_BIN_HEADER_SIZE as u32)
                    .and_then(|value| value.checked_add(local_offset as u32))
                    .ok_or_else(|| Error::CorruptHive("Cell offset overflow".to_string()))?;
                let cell = RawCell::parse(&bin.data[local_offset..], cell_offset)?;
                if !cell_offsets.insert(cell_offset) {
                    return Err(Error::CorruptHive(format!(
                        "Duplicate cell offset: {cell_offset:#010x}"
                    )));
                }
                local_offset = local_offset
                    .checked_add(cell.abs_size())
                    .ok_or_else(|| Error::CorruptHive("Cell size overflow".to_string()))?;
            }
            if local_offset != bin.data.len() {
                return Err(Error::InvalidHiveBin {
                    offset,
                    message: "Cells do not exactly fill the hive bin".to_string(),
                });
            }
            hive_bins.push(bin);
            offset = offset
                .checked_add(header.size)
                .ok_or_else(|| Error::CorruptHive("Hive bin size overflow".to_string()))?;
        }

        let parser = Self {
            reader,
            base_block,
            hive_bins,
            cell_offsets,
        };
        let root = parser.read_key_node(parser.base_block.root_cell_offset)?;
        if !root.is_root() {
            return Err(Error::CorruptHive(
                "Root cell is not marked as a hive entry".to_string(),
            ));
        }
        parser.validate_key_graph(parser.base_block.root_cell_offset)?;

        Ok(parser)
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
        if offset == INVALID_OFFSET || !self.cell_offsets.contains(&offset) {
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
        let idx = find_bin_index(&self.hive_bins, offset)
            .ok_or(Error::InvalidCellOffset(offset))?;
        let bin = self.hive_bins[idx].extent();
        let local_offset = (offset - bin.offset) as usize;
        if local_offset < HIVE_BIN_HEADER_SIZE {
            return Err(Error::InvalidCellOffset(offset));
        }
        Ok((idx, local_offset - HIVE_BIN_HEADER_SIZE))
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

        if size as usize > BIG_DATA_THRESHOLD && self.base_block.minor_version > 3 {
            return self.read_big_data(&cell.data, size);
        }

        let data_size = size as usize;
        if cell.data.len() < data_size {
            return Err(Error::BufferTooSmall {
                needed: data_size,
                available: cell.data.len(),
            });
        }
        Ok(cell.data[..data_size].to_vec())
    }

    /// Read big data.
    fn read_big_data(&self, data: &[u8], size: u32) -> Result<Vec<u8>> {
        let big_data = BigData::parse(data)?;
        let segments_list_cell = self.read_cell(big_data.segments_list_offset)?;
        if !segments_list_cell.is_allocated() {
            return Err(Error::UnallocatedCell(big_data.segments_list_offset));
        }
        let segments_list =
            DataSegmentsList::parse(&segments_list_cell.data, big_data.num_segments)?;
        let expected_segments = (size as usize).div_ceil(MAX_DATA_SEGMENT_SIZE);
        if expected_segments != big_data.num_segments as usize {
            return Err(Error::CorruptHive(format!(
                "Big data segment count is {}, expected {}",
                big_data.num_segments, expected_segments
            )));
        }

        let mut result = Vec::with_capacity(size as usize);
        let mut remaining = size as usize;

        for &segment_offset in &segments_list.offsets {
            let segment_cell = self.read_cell(segment_offset)?;
            if !segment_cell.is_allocated() {
                return Err(Error::UnallocatedCell(segment_offset));
            }
            let segment_size = remaining.min(MAX_DATA_SEGMENT_SIZE);
            if segment_cell.data.len() < segment_size {
                return Err(Error::BufferTooSmall {
                    needed: segment_size,
                    available: segment_cell.data.len(),
                });
            }
            result.extend_from_slice(&segment_cell.data[..segment_size]);
            remaining -= segment_size;
        }

        if remaining != 0 {
            return Err(Error::CorruptHive(format!(
                "Big data is missing {remaining} bytes"
            )));
        }
        Ok(result)
    }

    /// Get all subkey offsets for a key node.
    pub fn get_subkey_offsets(&self, key_node: &KeyNode) -> Result<Vec<u32>> {
        if !key_node.has_subkeys() {
            return Ok(Vec::new());
        }

        let list = self.read_subkeys_list(key_node.subkeys_list_offset)?;
        self.validate_subkey_list_records(&list)?;
        let mut visited = HashSet::new();
        visited.insert(key_node.subkeys_list_offset);
        let offsets = self.collect_subkey_offsets(&list, &mut visited, false)?;
        if offsets.len() != key_node.num_subkeys as usize {
            return Err(Error::CorruptHive(format!(
                "Subkey count is {}, expected {}",
                offsets.len(),
                key_node.num_subkeys
            )));
        }
        let mut previous_name: Option<Vec<u16>> = None;
        for offset in &offsets {
            let node = self.read_key_node(*offset)?;
            let name = node
                .name()
                .to_uppercase()
                .encode_utf16()
                .collect::<Vec<_>>();
            if previous_name
                .as_ref()
                .is_some_and(|previous| previous >= &name)
            {
                return Err(Error::CorruptHive(
                    "Subkey list is not strictly sorted".to_string(),
                ));
            }
            previous_name = Some(name);
        }
        Ok(offsets)
    }

    fn validate_subkey_list_records(&self, list: &SubkeysList) -> Result<()> {
        match list {
            SubkeysList::HashLeaf(hash_leaf) => {
                if self.base_block.minor_version <= 4 {
                    return Err(Error::CorruptHive(
                        "Hash leaf is not supported by this hive version".to_string(),
                    ));
                }
                for element in &hash_leaf.elements {
                    let key = self.read_key_node(element.key_node_offset)?;
                    let expected_hash = calculate_name_hash(&key.name());
                    if element.name_hash != expected_hash {
                        return Err(Error::CorruptHive(format!(
                            "Invalid hash for key {:#010x}",
                            element.key_node_offset
                        )));
                    }
                }
                Ok(())
            }
            SubkeysList::IndexRoot(index_root) => {
                for element in &index_root.elements {
                    let child = self.read_subkeys_list(element.subkeys_list_offset)?;
                    if matches!(child, SubkeysList::IndexRoot(_)) {
                        return Err(Error::CorruptHive(
                            "Index root points to another index root".to_string(),
                        ));
                    }
                    self.validate_subkey_list_records(&child)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Recursively collect subkey offsets from a subkeys list.
    fn collect_subkey_offsets(
        &self,
        list: &SubkeysList,
        visited: &mut HashSet<u32>,
        below_index_root: bool,
    ) -> Result<Vec<u32>> {
        if let SubkeysList::IndexRoot(ir) = list {
            if below_index_root {
                return Err(Error::CorruptHive(
                    "Index root points to another index root".to_string(),
                ));
            }
            let mut offsets = Vec::new();
            for elem in &ir.elements {
                if !visited.insert(elem.subkeys_list_offset) {
                    return Err(Error::CorruptHive(format!(
                        "Subkey list cycle at {:#010x}",
                        elem.subkeys_list_offset
                    )));
                }
                let sub_list = self.read_subkeys_list(elem.subkeys_list_offset)?;
                offsets.extend(self.collect_subkey_offsets(&sub_list, visited, true)?);
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

    fn validate_key_graph(&self, root_offset: u32) -> Result<()> {
        let mut pending = vec![root_offset];
        let mut visited = HashSet::new();
        let mut security_references = HashMap::<u32, u32>::new();

        while let Some(key_offset) = pending.pop() {
            if !visited.insert(key_offset) {
                return Err(Error::CorruptHive(format!(
                    "Key graph cycle or duplicate at {key_offset:#010x}"
                )));
            }
            let key = self.read_key_node(key_offset)?;
            if key.num_subkeys > 0 && key.subkeys_list_offset == INVALID_OFFSET {
                return Err(Error::InvalidCellOffset(key.subkeys_list_offset));
            }
            if !key.is_predef_handle()
                && key.num_values > 0
                && key.values_list_offset == INVALID_OFFSET
            {
                return Err(Error::InvalidCellOffset(key.values_list_offset));
            }
            if key.class_name_length > 0 {
                if key.class_name_offset == INVALID_OFFSET {
                    return Err(Error::InvalidCellOffset(key.class_name_offset));
                }
                let class_cell = self.read_cell(key.class_name_offset)?;
                let class_length = key.class_name_length as usize;
                if !class_cell.is_allocated()
                    || !class_length.is_multiple_of(2)
                    || class_length > class_cell.data.len()
                {
                    return Err(Error::CorruptHive(format!(
                        "Invalid class name for key {key_offset:#010x}"
                    )));
                }
                decode_utf16le_string(&class_cell.data[..class_length])?;
            }
            if key.security_offset == INVALID_OFFSET {
                return Err(Error::InvalidCellOffset(key.security_offset));
            }
            self.read_key_security(key.security_offset)?;
            let reference_count = security_references.entry(key.security_offset).or_default();
            *reference_count = reference_count.checked_add(1).ok_or_else(|| {
                Error::CorruptHive("Security reference count overflow".to_string())
            })?;

            for child_offset in self.get_subkey_offsets(&key)? {
                let child = self.read_key_node(child_offset)?;
                if child.parent != key_offset {
                    return Err(Error::CorruptHive(format!(
                        "Key {child_offset:#010x} has parent {:#010x}, expected {key_offset:#010x}",
                        child.parent
                    )));
                }
                pending.push(child_offset);
            }

            if !key.is_predef_handle() {
                for value_offset in self.get_value_offsets(&key)? {
                    let value = self.read_key_value(value_offset)?;
                    if value.is_data_resident() {
                        value.get_resident_data().ok_or_else(|| {
                            Error::CorruptHive("Invalid resident value data".to_string())
                        })?;
                    } else if value.actual_data_size() > 0 {
                        if value.data_offset == INVALID_OFFSET {
                            return Err(Error::InvalidCellOffset(value.data_offset));
                        }
                        self.read_value_data(value.data_offset, value.actual_data_size())?;
                    }
                }
            }
        }

        for (security_offset, incoming_count) in security_references {
            let security = self.read_key_security(security_offset)?;
            if security.reference_count != incoming_count {
                return Err(Error::CorruptHive(format!(
                    "Security item {security_offset:#010x} has reference count {}, expected {incoming_count}",
                    security.reference_count
                )));
            }
            let next = self.read_key_security(security.flink)?;
            let previous = self.read_key_security(security.blink)?;
            if next.blink != security_offset || previous.flink != security_offset {
                return Err(Error::CorruptHive(format!(
                    "Broken security links at {security_offset:#010x}"
                )));
            }
        }

        Ok(())
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
        crate::writer::HiveBuilder::new()
            .unwrap()
            .to_bytes()
            .unwrap()
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

    #[test]
    fn rejects_invalid_primary_header_and_bin_chain() {
        let data = create_minimal_hive();

        let mut unsupported_version = data.clone();
        unsupported_version[24..28].copy_from_slice(&7u32.to_le_bytes());
        let checksum = calculate_checksum(&unsupported_version);
        unsupported_version[508..512].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            HiveParser::new(Cursor::new(unsupported_version)),
            Err(Error::UnsupportedVersion { minor: 7, .. })
        ));

        let mut wrong_type = data.clone();
        wrong_type[28..32].copy_from_slice(&1u32.to_le_bytes());
        let checksum = calculate_checksum(&wrong_type);
        wrong_type[508..512].copy_from_slice(&checksum.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(wrong_type)).is_err());

        let mut wrong_bin_offset = data.clone();
        wrong_bin_offset[4100..4104].copy_from_slice(&4096u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(wrong_bin_offset)).is_err());

        let mut oversized_bin = data;
        oversized_bin[4104..4108].copy_from_slice(&0xFFFFF000u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(oversized_bin)).is_err());

        let mut builder = crate::writer::HiveBuilder::new().unwrap();
        let root_offset = builder.root_offset();
        builder
            .add_value(root_offset, "Data", DataType::Binary, &vec![1; 16_345])
            .unwrap();
        let mut multiple_bins = builder.to_bytes().unwrap();
        multiple_bins[8192..8196].copy_from_slice(b"bad!");
        assert!(HiveParser::new(Cursor::new(multiple_bins)).is_err());
    }

    #[test]
    fn rejects_invalid_class_and_security_metadata() {
        let data = create_minimal_hive();
        let root_offset =
            u32::from_le_bytes(data[36..40].try_into().unwrap()) as usize + BASE_BLOCK_SIZE;
        let security_offset =
            u32::from_le_bytes(data[root_offset + 48..root_offset + 52].try_into().unwrap())
                as usize
                + BASE_BLOCK_SIZE;

        let mut invalid_class = data.clone();
        invalid_class[root_offset + 52..root_offset + 56].copy_from_slice(&32u32.to_le_bytes());
        invalid_class[root_offset + 78..root_offset + 80].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(invalid_class)).is_err());

        let mut invalid_security = data;
        invalid_security[security_offset + 16..security_offset + 20]
            .copy_from_slice(&2u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(invalid_security)).is_err());

        let mut broken_security_link = create_minimal_hive();
        let root_offset = u32::from_le_bytes(broken_security_link[36..40].try_into().unwrap())
            as usize
            + BASE_BLOCK_SIZE;
        let security_offset = u32::from_le_bytes(
            broken_security_link[root_offset + 48..root_offset + 52]
                .try_into()
                .unwrap(),
        ) as usize
            + BASE_BLOCK_SIZE;
        broken_security_link[security_offset + 8..security_offset + 12]
            .copy_from_slice(&INVALID_OFFSET.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(broken_security_link)).is_err());
    }

    #[test]
    fn rejects_subkey_count_mismatch_and_index_root_cycle() {
        let mut builder = crate::writer::HiveBuilder::new().unwrap();
        let root_builder_offset = builder.root_offset();
        builder.add_key(root_builder_offset, "Child").unwrap();
        let data = builder.to_bytes().unwrap();
        let root_offset =
            u32::from_le_bytes(data[36..40].try_into().unwrap()) as usize + BASE_BLOCK_SIZE;
        let list_offset =
            u32::from_le_bytes(data[root_offset + 32..root_offset + 36].try_into().unwrap())
                as usize;

        let mut count_mismatch = data.clone();
        count_mismatch[root_offset + 24..root_offset + 28].copy_from_slice(&2u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(count_mismatch)).is_err());

        let mut missing_subkeys_list = data.clone();
        missing_subkeys_list[root_offset + 32..root_offset + 36]
            .copy_from_slice(&INVALID_OFFSET.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(missing_subkeys_list)).is_err());

        let list_file_offset = BASE_BLOCK_SIZE + list_offset;
        let mut invalid_hash = data.clone();
        invalid_hash[list_file_offset + 12..list_file_offset + 16]
            .copy_from_slice(&0u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(invalid_hash)).is_err());

        let mut cycle = data;
        cycle[list_file_offset + 4..list_file_offset + 6].copy_from_slice(b"ri");
        cycle[list_file_offset + 8..list_file_offset + 12]
            .copy_from_slice(&(list_offset as u32).to_le_bytes());
        assert!(HiveParser::new(Cursor::new(cycle)).is_err());

        let mut missing_values_list = create_minimal_hive();
        let root_offset = u32::from_le_bytes(
            missing_values_list[36..40].try_into().unwrap(),
        ) as usize
            + BASE_BLOCK_SIZE;
        missing_values_list[root_offset + 40..root_offset + 44]
            .copy_from_slice(&1u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(missing_values_list)).is_err());
    }

    #[test]
    fn only_reads_indexed_cell_starts() {
        let parser = HiveParser::new(Cursor::new(create_minimal_hive())).unwrap();
        assert!(parser
            .read_cell(parser.root_cell_offset().saturating_add(8))
            .is_err());
    }

    #[test]
    fn reads_big_data_without_cell_padding() {
        for size in [16_344usize, 16_345, 32_688, 32_689] {
            let expected = (0..size).map(|index| index as u8).collect::<Vec<_>>();
            let mut builder = crate::writer::HiveBuilder::new().unwrap();
            let root_offset = builder.root_offset();
            builder
                .add_value(root_offset, "Data", DataType::Binary, &expected)
                .unwrap();
            let hive = crate::hive::RegistryHive::from_bytes(builder.to_bytes().unwrap()).unwrap();
            let actual = hive
                .root_key()
                .unwrap()
                .value("Data")
                .unwrap()
                .raw_data()
                .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn ordinary_data_starting_with_db_is_not_big_data() {
        let expected = b"dbordinary".to_vec();
        let mut builder = crate::writer::HiveBuilder::new().unwrap();
        let root_offset = builder.root_offset();
        builder
            .add_value(root_offset, "Data", DataType::Binary, &expected)
            .unwrap();
        let hive = crate::hive::RegistryHive::from_bytes(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(
            hive.root_key()
                .unwrap()
                .value("Data")
                .unwrap()
                .raw_data()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_truncated_value_data_and_wrong_segment_count() {
        let mut ordinary_builder = crate::writer::HiveBuilder::new().unwrap();
        let ordinary_root = ordinary_builder.root_offset();
        ordinary_builder
            .add_value(ordinary_root, "Data", DataType::Binary, &[1, 2, 3, 4, 5])
            .unwrap();
        let mut ordinary_data = ordinary_builder.to_bytes().unwrap();
        let ordinary_parser = HiveParser::new(Cursor::new(ordinary_data.clone())).unwrap();
        let root = ordinary_parser
            .read_key_node(ordinary_parser.root_cell_offset())
            .unwrap();
        let value_offset = ordinary_parser.get_value_offsets(&root).unwrap()[0] as usize;
        ordinary_data[BASE_BLOCK_SIZE + value_offset + 8..BASE_BLOCK_SIZE + value_offset + 12]
            .copy_from_slice(&100u32.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(ordinary_data)).is_err());

        let mut big_builder = crate::writer::HiveBuilder::new().unwrap();
        let big_root = big_builder.root_offset();
        big_builder
            .add_value(big_root, "Data", DataType::Binary, &vec![1; 16_345])
            .unwrap();
        let mut big_data = big_builder.to_bytes().unwrap();
        let big_parser = HiveParser::new(Cursor::new(big_data.clone())).unwrap();
        let root = big_parser
            .read_key_node(big_parser.root_cell_offset())
            .unwrap();
        let value_offset = big_parser.get_value_offsets(&root).unwrap()[0];
        let value = big_parser.read_key_value(value_offset).unwrap();
        let big_data_offset = value.data_offset as usize;
        big_data[BASE_BLOCK_SIZE + big_data_offset + 6..BASE_BLOCK_SIZE + big_data_offset + 8]
            .copy_from_slice(&1u16.to_le_bytes());
        assert!(HiveParser::new(Cursor::new(big_data)).is_err());
    }

    #[test]
    fn checksum_failure_is_loadable_as_dirty() {
        let mut data = create_minimal_hive();
        data[508] ^= 0xFF;
        let parser = HiveParser::new(Cursor::new(data)).unwrap();
        assert!(parser.base_block().is_dirty());
    }
}

