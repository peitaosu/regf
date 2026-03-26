//! Registry hive writer.
//!
//! This module handles writing registry hives to files.
//!
//! ## Building Hives
//!
//! For optimal file sizes, use the tree-based approach:
//!
//! ```ignore
//! use regf::writer::{HiveBuilder, KeyTreeNode, KeyTreeValue};
//!
//! // Build tree structure first
//! let mut root = KeyTreeNode::new("ROOT");
//! let mut software = KeyTreeNode::new("Software");
//! software.values.push(KeyTreeValue {
//!     name: "Version".to_string(),
//!     data_type: DataType::String,
//!     data: b"1.0\0\0".to_vec(),
//! });
//! root.children.push(software);
//!
//! // Build hive from tree (allocates with known sizes)
//! let mut builder = HiveBuilder::from_tree(root);
//! builder.write_to_file("output.dat")?;
//! ```
//!
//! ## Incremental Building
//!
//! For dynamic hive construction, use the incremental approach:
//!
//! ```ignore
//! use regf::writer::HiveBuilder;
//!
//! let mut builder = HiveBuilder::new();
//! let root = builder.root_offset();
//! let software = builder.add_key(root, "Software")?;
//! builder.add_value(software, "Version", DataType::String, &data)?;
//! builder.write_to_file("output.dat")?;
//! ```

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Cursor, Seek, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::structures::*;

/// Encode a string to UTF-16LE with null terminator.
fn encode_utf16le_string(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    // Add null terminator
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

fn align_up_u32(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    let mask = alignment - 1;
    (value + mask) & !mask
}

/// A value in the key tree.
#[derive(Debug, Clone)]
pub struct KeyTreeValue {
    /// Value name (empty string for default value).
    pub name: String,
    /// Value data type.
    pub data_type: DataType,
    /// Raw value data.
    pub data: Vec<u8>,
}

/// A node in the key tree representing a registry key.
#[derive(Debug, Clone)]
pub struct KeyTreeNode {
    /// Key name.
    pub name: String,
    /// Values under this key.
    pub values: Vec<KeyTreeValue>,
    /// Child keys (subkeys).
    pub children: Vec<KeyTreeNode>,
}

impl KeyTreeNode {
    /// Create a new key tree node.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            values: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Add or get a child key by path (creates intermediate keys if needed).
    pub fn get_or_create_path(&mut self, path: &str) -> &mut KeyTreeNode {
        if path.is_empty() {
            return self;
        }

        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current = self;

        for part in parts {
            // Find or create child
            let idx = current.children.iter().position(|c| c.name.eq_ignore_ascii_case(part));
            if let Some(idx) = idx {
                current = &mut current.children[idx];
            } else {
                current.children.push(KeyTreeNode::new(part));
                let len = current.children.len();
                current = &mut current.children[len - 1];
            }
        }

        current
    }

    /// Sort children recursively by name (required by registry format).
    pub fn sort_recursive(&mut self) {
        self.children.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
        for child in &mut self.children {
            child.sort_recursive();
        }
    }

    /// Count total keys (including self).
    pub fn count_keys(&self) -> usize {
        1 + self.children.iter().map(|c| c.count_keys()).sum::<usize>()
    }

    /// Count total values.
    pub fn count_values(&self) -> usize {
        self.values.len() + self.children.iter().map(|c| c.count_values()).sum::<usize>()
    }
}

/// Builder for creating and modifying registry hives.
pub struct HiveBuilder {
    /// Base block.
    base_block: BaseBlock,
    /// Allocated cells with their data.
    cells: Vec<CellEntry>,
    /// Free space tracker.
    free_cells: Vec<FreeCell>,
    /// Current hive bins data size.
    hive_bins_size: u32,
    /// Hive bin layout. Bins are contiguous and ordered by offset.
    bins: Vec<BinExtent>,
    /// Root key offset.
    root_offset: u32,
    /// Security descriptor cache (for deduplication, future use).
    #[allow(dead_code)]
    security_cache: HashMap<Vec<u8>, u32>,
    /// Next available offset in current bin.
    next_offset: u32,
    /// Minor version of hive (affects feature availability).
    /// - Version > 4: Use HashLeaf for subkeys lists
    /// - Version > 3: Support for Big Data
    /// - Version <= 4: Use FastLeaf for subkeys lists
    /// - Version <= 3: No Big Data support (max value size 16344 bytes)
    minor_version: u32,
}

/// A cell entry in the builder.
#[derive(Debug, Clone)]
struct CellEntry {
    /// Offset of this cell.
    offset: u32,
    /// Cell data (including signature, excluding size).
    data: Vec<u8>,
    /// Allocated size for this cell.
    allocated_size: usize,
}

/// A free cell.
#[derive(Debug, Clone)]
struct FreeCell {
    /// Offset of this free cell.
    offset: u32,
    /// Size of this free cell.
    size: u32,
}


impl HiveBuilder {
    /// Create a new hive builder with default version (1.6).
    pub fn new() -> Self {
        Self::with_version(1, 6)
    }

    /// Create a new hive builder with a custom root name.
    pub fn new_with_name(root_name: &str) -> Self {
        Self::with_version_and_name(1, 6, root_name)
    }

    /// Create a new hive builder with a custom root name and version.
    pub fn new_with_version(root_name: &str, minor_version: u32) -> Self {
        Self::with_version_and_name(1, minor_version, root_name)
    }

    /// Create a new hive builder with specific version.
    /// 
    /// Version compatibility:
    /// - 1.3: Basic format, no FastLeaf, no BigData
    /// - 1.4: FastLeaf supported
    /// - 1.5: HashLeaf supported, BigData supported
    /// - 1.6: Current format (recommended)
    pub fn with_version(major: u32, minor: u32) -> Self {
        Self::with_version_and_name(major, minor, "")
    }

    /// Create a new hive builder with specific version and root name.
    fn with_version_and_name(major: u32, minor: u32, root_name: &str) -> Self {
        let mut builder = Self {
            base_block: BaseBlock::default(),
            cells: Vec::new(),
            free_cells: Vec::new(),
            hive_bins_size: MIN_HIVE_BIN_SIZE as u32,
            bins: vec![BinExtent::default()],
            root_offset: HIVE_BIN_HEADER_SIZE as u32,
            security_cache: HashMap::new(),
            next_offset: HIVE_BIN_HEADER_SIZE as u32,
            minor_version: minor,
        };

        builder.base_block.major_version = major;
        builder.base_block.minor_version = minor;

        // Pre-calculate security cell offset - it will be the first allocated cell
        // after the hive bin header (offset 32 in hive bins data)
        let security_offset = HIVE_BIN_HEADER_SIZE as u32;

        // Create security descriptor with proper self-referencing flink/blink
        // For a list header with no other entries, flink and blink point to itself
        let mut security = KeySecurity::new_default();
        security.set_self_referencing(security_offset);
        let security_bytes = security.to_bytes();
        let actual_security_offset = builder.allocate_cell(&security_bytes);
        debug_assert_eq!(actual_security_offset, security_offset);

        // Create root key
        let mut root_key = KeyNode::new(root_name, INVALID_OFFSET, true);
        root_key.security_offset = actual_security_offset;
        let root_bytes = root_key.to_bytes();
        builder.root_offset = builder.allocate_cell(&root_bytes);

        builder.base_block.root_cell_offset = builder.root_offset;

        builder
    }

    /// Build a hive from a pre-built tree structure.
    /// 
    /// This method produces the most compact hive because it knows the final
    /// size of each subkeys list and values list before allocation.
    /// 
    /// # Example
    /// ```ignore
    /// let mut root = KeyTreeNode::new("ROOT");
    /// root.children.push(KeyTreeNode::new("Software"));
    /// let builder = HiveBuilder::from_tree(root);
    /// builder.write_to_file("output.dat")?;
    /// ```
    pub fn from_tree(tree: KeyTreeNode) -> Self {
        Self::from_tree_with_version(tree, 1, 6)
    }

    /// Build a hive from a pre-built tree structure with specific version.
    pub fn from_tree_with_version(mut tree: KeyTreeNode, major: u32, minor: u32) -> Self {
        // Sort the tree first (required by registry format)
        tree.sort_recursive();

        let mut builder = Self {
            base_block: BaseBlock::default(),
            cells: Vec::new(),
            free_cells: Vec::new(),
            hive_bins_size: MIN_HIVE_BIN_SIZE as u32,
            bins: vec![BinExtent::default()],
            root_offset: HIVE_BIN_HEADER_SIZE as u32,
            security_cache: HashMap::new(),
            next_offset: HIVE_BIN_HEADER_SIZE as u32,
            minor_version: minor,
        };

        builder.base_block.major_version = major;
        builder.base_block.minor_version = minor;

        // Create security descriptor
        let security_offset = HIVE_BIN_HEADER_SIZE as u32;
        let mut security = KeySecurity::new_default();
        security.set_self_referencing(security_offset);
        let security_bytes = security.to_bytes();
        let actual_security_offset = builder.allocate_cell(&security_bytes);
        debug_assert_eq!(actual_security_offset, security_offset);

        // Build the tree recursively, depth-first
        // This ensures children are allocated before parents need their offsets
        let root_offset = builder.build_key_node(&tree, INVALID_OFFSET, actual_security_offset, true);
        builder.root_offset = root_offset;
        builder.base_block.root_cell_offset = root_offset;

        builder
    }

    /// Build a key node from a tree node (recursive, depth-first).
    fn build_key_node(
        &mut self, 
        tree_node: &KeyTreeNode, 
        parent_offset: u32,
        security_offset: u32,
        is_root: bool,
    ) -> u32 {
        let use_hash_leaf = self.supports_hash_leaf();

        // First, recursively build all children to get their offsets
        let mut child_offsets: Vec<(u32, String)> = Vec::with_capacity(tree_node.children.len());
        for child in &tree_node.children {
            // Pass INVALID_OFFSET as parent for now, we'll update it later
            let child_offset = self.build_key_node(child, INVALID_OFFSET, security_offset, false);
            child_offsets.push((child_offset, child.name.to_uppercase()));
        }

        // Build values list if there are values
        let values_list_offset = if tree_node.values.is_empty() {
            INVALID_OFFSET
        } else {
            let mut offsets = Vec::with_capacity(tree_node.values.len());
            for value in &tree_node.values {
                let value_offset = self.build_value_cell(value);
                offsets.push(value_offset);
            }
            // Create values list with exact size
            let list_bytes: Vec<u8> = offsets.iter()
                .flat_map(|&o| o.to_le_bytes())
                .collect();
            self.allocate_cell(&list_bytes)
        };

        // Build subkeys list if there are children (already sorted)
        let subkeys_list_offset = if child_offsets.is_empty() {
            INVALID_OFFSET
        } else if child_offsets.len() <= Self::MAX_LEAF_ELEMENTS {
            // Single leaf list
            let list_bytes = if use_hash_leaf {
                let mut hash_leaf = HashLeaf::new();
                hash_leaf.elements = child_offsets
                    .iter()
                    .map(|(offset, name)| HashLeafElement {
                        key_node_offset: *offset,
                        name_hash: calculate_name_hash(name),
                    })
                    .collect();
                hash_leaf.num_elements = hash_leaf.elements.len() as u16;
                hash_leaf.to_bytes()
            } else {
                let mut fast_leaf = FastLeaf::new();
                fast_leaf.elements = child_offsets
                    .iter()
                    .enumerate()
                    .map(|(i, (offset, _))| {
                        FastLeafElement {
                            key_node_offset: *offset,
                            name_hint: Self::create_name_hint(&tree_node.children[i].name),
                        }
                    })
                    .collect();
                fast_leaf.num_elements = fast_leaf.elements.len() as u16;
                fast_leaf.to_bytes()
            };
            self.allocate_cell(&list_bytes)
        } else {
            // Need Index Root with multiple leaf lists
            let mut index_root = IndexRoot::new();
            let mut leaf_offsets = Vec::new();

            for chunk in child_offsets.chunks(Self::MAX_LEAF_ELEMENTS) {
                let chunk_start_idx = leaf_offsets.len() * Self::MAX_LEAF_ELEMENTS;
                let leaf_bytes = if use_hash_leaf {
                    let mut hash_leaf = HashLeaf::new();
                    hash_leaf.elements = chunk
                        .iter()
                        .map(|(offset, name)| HashLeafElement {
                            key_node_offset: *offset,
                            name_hash: calculate_name_hash(name),
                        })
                        .collect();
                    hash_leaf.num_elements = hash_leaf.elements.len() as u16;
                    hash_leaf.to_bytes()
                } else {
                    let mut fast_leaf = FastLeaf::new();
                    fast_leaf.elements = chunk
                        .iter()
                        .enumerate()
                        .map(|(i, (offset, _))| {
                            let child_idx = chunk_start_idx + i;
                            FastLeafElement {
                                key_node_offset: *offset,
                                name_hint: Self::create_name_hint(&tree_node.children[child_idx].name),
                            }
                        })
                        .collect();
                    fast_leaf.num_elements = fast_leaf.elements.len() as u16;
                    fast_leaf.to_bytes()
                };

                let leaf_offset = self.allocate_cell(&leaf_bytes);
                leaf_offsets.push(leaf_offset);
            }

            index_root.elements = leaf_offsets
                .iter()
                .map(|&offset| IndexRootElement { subkeys_list_offset: offset })
                .collect();
            index_root.num_elements = index_root.elements.len() as u16;

            let root_bytes = index_root.to_bytes();
            self.allocate_cell(&root_bytes)
        };

        // Create the key node
        let mut key_node = KeyNode::new(&tree_node.name, parent_offset, is_root);
        key_node.security_offset = security_offset;
        key_node.num_subkeys = tree_node.children.len() as u32;
        key_node.subkeys_list_offset = subkeys_list_offset;
        key_node.num_values = tree_node.values.len() as u32;
        key_node.values_list_offset = values_list_offset;

        // Calculate size tracking fields
        if !tree_node.children.is_empty() {
            key_node.largest_subkey_name_length = tree_node.children
                .iter()
                .map(|c| (c.name.len() * 2) as u16)
                .max()
                .unwrap_or(0);
        }
        if !tree_node.values.is_empty() {
            key_node.largest_value_name_length = tree_node.values
                .iter()
                .map(|v| (v.name.len() * 2) as u32)
                .max()
                .unwrap_or(0);
            key_node.largest_value_data_size = tree_node.values
                .iter()
                .map(|v| v.data.len() as u32)
                .max()
                .unwrap_or(0);
        }

        let key_bytes = key_node.to_bytes();
        let key_offset = self.allocate_cell(&key_bytes);

        // Update children's parent offset
        for (child_offset, _) in &child_offsets {
            if let Some(cell) = self.cells.iter_mut().find(|c| c.offset == *child_offset) {
                // Parse, update parent, and re-serialize
                if let Ok(mut child_node) = KeyNode::parse(&cell.data) {
                    child_node.parent = key_offset;
                    cell.data = child_node.to_bytes();
                }
            }
        }

        key_offset
    }

    /// Build a value cell from a tree value.
    fn build_value_cell(&mut self, value: &KeyTreeValue) -> u32 {
        let mut key_value = KeyValue::new(&value.name, value.data_type);

        // Store data
        if value.data.len() <= MAX_RESIDENT_DATA_SIZE {
            key_value.set_resident_data(&value.data);
        } else if value.data.len() <= BIG_DATA_THRESHOLD {
            let data_offset = self.allocate_cell(&value.data);
            key_value.data_offset = data_offset;
            key_value.data_size = value.data.len() as u32;
        } else if self.supports_big_data() {
            // Big data
            if let Ok(data_offset) = self.allocate_big_data(&value.data) {
                key_value.data_offset = data_offset;
                key_value.data_size = value.data.len() as u32;
            }
        }
        // If data is too large and big data not supported, we just don't set it

        let value_bytes = key_value.to_bytes();
        self.allocate_cell(&value_bytes)
    }

    /// Check if HashLeaf is supported (minor version > 4).
    fn supports_hash_leaf(&self) -> bool {
        self.minor_version > 4
    }

    /// Check if BigData is supported (minor version > 3).
    fn supports_big_data(&self) -> bool {
        self.minor_version > 3
    }

    /// Allocate a cell and return its offset.
    fn allocate_cell(&mut self, data: &[u8]) -> u32 {
        self.allocate_cell_with_min_size(data, required_cell_size(data.len()))
    }

    /// Calculate the end of the current bin for a given offset.
    fn bin_end_for_offset(&self, offset: u32) -> u32 {
        find_bin(&self.bins, offset)
            .map(|bin| bin.end())
            .unwrap_or(self.hive_bins_size)
    }

    /// Calculate the start of the data area in the bin for a given offset.
    /// This is after the 32-byte bin header.
    fn bin_data_start_for_offset(&self, offset: u32) -> u32 {
        find_bin(&self.bins, offset)
            .map(|bin| bin.offset + HIVE_BIN_HEADER_SIZE as u32)
            .unwrap_or(offset)
    }

    /// Check if an offset is valid (not within bin header area).
    fn is_valid_cell_offset(&self, offset: u32) -> bool {
        if let Some(bin) = find_bin(&self.bins, offset) {
            offset >= bin.offset + HIVE_BIN_HEADER_SIZE as u32
        } else {
            false
        }
    }

    /// Ensure an offset is past the bin header. Returns adjusted offset if needed.
    fn ensure_past_bin_header(&self, offset: u32) -> u32 {
        let data_start = self.bin_data_start_for_offset(offset);
        if offset < data_start {
            data_start
        } else {
            offset
        }
    }

    /// Allocate a cell with a minimum size (for cells that may grow).
    fn allocate_cell_with_min_size(&mut self, data: &[u8], min_size: usize) -> u32 {
        let cell_size = min_size.max(required_cell_size(data.len()));
        let max_cell_in_bin = MIN_HIVE_BIN_SIZE - HIVE_BIN_HEADER_SIZE;

        // Oversized cells can never fit in a standard bin payload area,
        // so skip free-list scanning and go straight to dedicated-bin allocation.
        if cell_size > max_cell_in_bin {
            // Preserve any remaining space in the current bin before switching
            // to a dedicated large-bin allocation path.
            let offset = self.ensure_past_bin_header(self.next_offset);
            let bin_end = self.bin_end_for_offset(offset);
            if offset < bin_end {
                let leftover = bin_end - offset;
                if leftover >= 8 {
                    self.free_cells.push(FreeCell {
                        offset,
                        size: leftover,
                    });
                }
            }
            return self.allocate_large_cell(data, cell_size);
        }

        // Try to find a free cell that fits using best-fit strategy
        // (find the smallest free cell that fits to minimize fragmentation)
        let mut best_fit_idx: Option<usize> = None;
        let mut best_fit_size: u32 = u32::MAX;
        
        for i in 0..self.free_cells.len() {
            let free = &self.free_cells[i];
            if free.size >= cell_size as u32 && free.size < best_fit_size {
                let offset = free.offset;
                
                // Skip free cells that are within bin headers (shouldn't happen, but be safe)
                if !self.is_valid_cell_offset(offset) {
                    continue;
                }
                
                let bin_end = self.bin_end_for_offset(offset);
                
                // Check if cell would span bin boundary
                if offset + cell_size as u32 > bin_end {
                    continue; // Skip this free cell, try next one
                }
                
                best_fit_idx = Some(i);
                best_fit_size = free.size;
                
                // Perfect fit - no need to search further
                if free.size == cell_size as u32 {
                    break;
                }
            }
        }
        
        if let Some(i) = best_fit_idx {
            let free = &self.free_cells[i];
            let offset = free.offset;
            let actual_size = free.size as usize;

            if free.size > cell_size as u32 + 8 {
                // Split the free cell
                let remaining_offset = offset + cell_size as u32;
                let remaining_size = free.size - cell_size as u32;
                
                // Only keep the remaining free cell if it's valid
                if self.is_valid_cell_offset(remaining_offset) {
                    self.free_cells[i] = FreeCell {
                        offset: remaining_offset,
                        size: remaining_size,
                    };
                } else {
                    self.free_cells.remove(i);
                }
                
                self.cells.push(CellEntry {
                    offset,
                    data: data.to_vec(),
                    allocated_size: cell_size,
                });
            } else {
                // Use the whole cell
                self.free_cells.remove(i);
                
                self.cells.push(CellEntry {
                    offset,
                    data: data.to_vec(),
                    allocated_size: actual_size,
                });
            }

            return offset;
        }

        // No suitable free cell, allocate new space
        // First, ensure we're past any bin header
        let mut offset = self.ensure_past_bin_header(self.next_offset);

        // Check if cell would span bin boundary
        loop {
            // Ensure offset is past bin header
            offset = self.ensure_past_bin_header(offset);
            
            let bin_end = self.bin_end_for_offset(offset);
            if offset + cell_size as u32 <= bin_end {
                break; // Cell fits in current bin
            }
            
            // Add the leftover space at end of current bin to free list
            let leftover = bin_end - offset;
            if leftover >= 8 {
                // Minimum cell size is 8 bytes
                self.free_cells.push(FreeCell {
                    offset,
                    size: leftover,
                });
            }
            
            // Move to next bin's data area (after header)
            if bin_end >= self.hive_bins_size {
                self.grow_hive();
            }
            offset = bin_end + HIVE_BIN_HEADER_SIZE as u32;
            self.next_offset = offset;
        }
        
        // Final validation - offset must be valid
        debug_assert!(self.is_valid_cell_offset(offset), 
            "Invalid cell offset {} - within bin header", offset);

        // Check if we need to grow the hive
        while offset + cell_size as u32 > self.hive_bins_size {
            self.grow_hive();
        }

        self.cells.push(CellEntry {
            offset,
            data: data.to_vec(),
            allocated_size: cell_size,
        });

        self.next_offset = offset + cell_size as u32;

        offset
    }

    /// Allocate an oversized cell by creating a dedicated larger bin.
    fn allocate_large_cell(&mut self, data: &[u8], cell_size: usize) -> u32 {
        let min_bin_size = HIVE_BIN_HEADER_SIZE as u32 + cell_size as u32;
        let bin_size = align_up_u32(min_bin_size, MIN_HIVE_BIN_SIZE as u32);
        let bin_start = self.hive_bins_size;
        self.bins.push(BinExtent {
            offset: bin_start,
            size: bin_size,
        });
        self.hive_bins_size += bin_size;

        let offset = bin_start + HIVE_BIN_HEADER_SIZE as u32;
        self.cells.push(CellEntry {
            offset,
            data: data.to_vec(),
            allocated_size: cell_size,
        });

        let used = HIVE_BIN_HEADER_SIZE as u32 + cell_size as u32;
        let leftover = bin_size.saturating_sub(used);
        if leftover >= 8 {
            self.free_cells.push(FreeCell {
                offset: offset + cell_size as u32,
                size: leftover,
            });
        }

        // Continue normal allocation after this dedicated bin.
        self.next_offset = self.hive_bins_size;
        offset
    }

    /// Grow the hive by adding a new bin.
    fn grow_hive(&mut self) {
        self.grow_hive_with_size(MIN_HIVE_BIN_SIZE as u32);
    }

    /// Grow the hive by appending a bin of `size` bytes.
    fn grow_hive_with_size(&mut self, size: u32) {
        // Don't add remaining space as free cell here - it will be handled
        // when writing the hive. This avoids conflicts when free cells are
        // reused (which doesn't update next_offset).
        debug_assert!(size >= MIN_HIVE_BIN_SIZE as u32);
        debug_assert_eq!(size % MIN_HIVE_BIN_SIZE as u32, 0);

        let new_bin_start = self.hive_bins_size;
        self.bins.push(BinExtent {
            offset: new_bin_start,
            size,
        });
        self.hive_bins_size += size;
        self.next_offset = new_bin_start + HIVE_BIN_HEADER_SIZE as u32;
    }

    /// Add a subkey to a parent key.
    pub fn add_key(&mut self, parent_offset: u32, name: &str) -> Result<u32> {
        // Get security offset from parent
        let security_offset = if parent_offset != INVALID_OFFSET {
            let parent_cell = self.find_cell(parent_offset)?;
            let parent_node = KeyNode::parse(&parent_cell.data)?;
            parent_node.security_offset
        } else {
            INVALID_OFFSET
        };

        // Create key node
        let mut key_node = KeyNode::new(name, parent_offset, false);
        key_node.security_offset = security_offset;

        let key_bytes = key_node.to_bytes();
        let key_offset = self.allocate_cell(&key_bytes);

        // Update parent's subkeys list
        if parent_offset != INVALID_OFFSET {
            self.add_subkey_to_parent(parent_offset, key_offset, name)?;
        }

        Ok(key_offset)
    }

    /// Create a name hint for FastLeaf (first 4 ASCII characters of name).
    fn create_name_hint(name: &str) -> [u8; 4] {
        let mut hint = [0u8; 4];
        for (i, c) in name.chars().take(4).enumerate() {
            // UTF-16LE to ASCII conversion: if char > 255, set first byte to null
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

    /// Maximum elements per leaf list (to fit in one cell, ~4KB)
    /// Each hash/fast leaf element is 8 bytes, header is 4 bytes
    /// Max cell = 4096 - 32 (bin header) = 4064 bytes total
    /// Cell = 4 bytes size + data, so max data = 4060 bytes
    /// required_cell_size(n) = (n + 4 + 7) & !7
    /// For list: data = 4 (header) + 8*n (elements)
    /// So: (4 + 8*n + 4 + 7) & !7 <= 4064
    /// 8*n + 15 <= 4064 => n <= 506
    /// Use 500 for safety margin
    const MAX_LEAF_ELEMENTS: usize = 500;

    /// Add a subkey reference to parent's subkeys list.
    fn add_subkey_to_parent(&mut self, parent_offset: u32, child_offset: u32, name: &str) -> Result<()> {
        let parent_cell = self.find_cell(parent_offset)?;
        let mut parent_node = KeyNode::parse(&parent_cell.data)?;

        let name_upper = name.to_uppercase();
        let use_hash_leaf = self.supports_hash_leaf();

        // Collect all existing subkeys
        let mut elements_with_names: Vec<(u32, String)> = Vec::new();
        
        if parent_node.subkeys_list_offset != INVALID_OFFSET {
            let list_offset = parent_node.subkeys_list_offset;
            let list_cell = self.find_cell(list_offset)?;
            let list = SubkeysList::parse(&list_cell.data)?;

            // Collect existing elements
            if list.is_index_root() {
                for sublist_offset in list.get_offsets() {
                    if let Ok(sub_cell) = self.find_cell(sublist_offset) {
                        if let Ok(sub_list) = SubkeysList::parse(&sub_cell.data) {
                            for key_offset in sub_list.get_offsets() {
                                if let Ok(node) = self.find_cell(key_offset).and_then(|c| KeyNode::parse(&c.data)) {
                                    elements_with_names.push((key_offset, node.name().to_uppercase()));
                                }
                            }
                        }
                    }
                }
            } else {
                for offset in list.get_offsets() {
                    if let Ok(node) = self.find_cell(offset).and_then(|c| KeyNode::parse(&c.data)) {
                        elements_with_names.push((offset, node.name().to_uppercase()));
                    }
                }
            }
        }

        // Add new element
        elements_with_names.push((child_offset, name_upper));

        // Sort by uppercase name (per spec requirement)
        elements_with_names.sort_by(|a, b| a.1.cmp(&b.1));

        // Create the appropriate list structure based on size
        let new_list_offset = if elements_with_names.len() <= Self::MAX_LEAF_ELEMENTS {
            // Single leaf list
            let list_bytes = if use_hash_leaf {
                let mut hash_leaf = HashLeaf::new();
                hash_leaf.elements = elements_with_names
                    .iter()
                    .map(|(offset, name)| HashLeafElement {
                        key_node_offset: *offset,
                        name_hash: calculate_name_hash(name),
                    })
                    .collect();
                hash_leaf.num_elements = hash_leaf.elements.len() as u16;
                hash_leaf.to_bytes()
            } else {
                let mut fast_leaf = FastLeaf::new();
                fast_leaf.elements = elements_with_names
                    .iter()
                    .filter_map(|(offset, _)| {
                        if *offset == child_offset {
                            Some(FastLeafElement {
                                key_node_offset: *offset,
                                name_hint: Self::create_name_hint(name),
                            })
                        } else {
                            self.find_cell(*offset)
                                .ok()
                                .and_then(|c| KeyNode::parse(&c.data).ok())
                                .map(|node| FastLeafElement {
                                    key_node_offset: *offset,
                                    name_hint: Self::create_name_hint(&node.name()),
                                })
                        }
                    })
                    .collect();
                fast_leaf.num_elements = fast_leaf.elements.len() as u16;
                fast_leaf.to_bytes()
            };
            
            // Exact-fit allocation
            self.allocate_cell(&list_bytes)
        } else {
            // Need Index Root with multiple leaf lists
            let mut index_root = IndexRoot::new();
            let mut leaf_offsets = Vec::new();
            
            // Split into chunks
            for chunk in elements_with_names.chunks(Self::MAX_LEAF_ELEMENTS) {
                let leaf_bytes = if use_hash_leaf {
                    let mut hash_leaf = HashLeaf::new();
                    hash_leaf.elements = chunk
                        .iter()
                        .map(|(offset, name)| HashLeafElement {
                            key_node_offset: *offset,
                            name_hash: calculate_name_hash(name),
                        })
                        .collect();
                    hash_leaf.num_elements = hash_leaf.elements.len() as u16;
                    hash_leaf.to_bytes()
                } else {
                    let mut fast_leaf = FastLeaf::new();
                    fast_leaf.elements = chunk
                        .iter()
                        .filter_map(|(offset, _)| {
                            if *offset == child_offset {
                                Some(FastLeafElement {
                                    key_node_offset: *offset,
                                    name_hint: Self::create_name_hint(name),
                                })
                            } else {
                                self.find_cell(*offset)
                                    .ok()
                                    .and_then(|c| KeyNode::parse(&c.data).ok())
                                    .map(|node| FastLeafElement {
                                        key_node_offset: *offset,
                                        name_hint: Self::create_name_hint(&node.name()),
                                    })
                            }
                        })
                        .collect();
                    fast_leaf.num_elements = fast_leaf.elements.len() as u16;
                    fast_leaf.to_bytes()
                };
                
                let leaf_offset = self.allocate_cell(&leaf_bytes);
                leaf_offsets.push(leaf_offset);
            }
            
            // Create index root
            index_root.elements = leaf_offsets
                .iter()
                .map(|&offset| IndexRootElement { subkeys_list_offset: offset })
                .collect();
            index_root.num_elements = index_root.elements.len() as u16;
            
            let root_bytes = index_root.to_bytes();
            self.allocate_cell(&root_bytes)
        };

        parent_node.subkeys_list_offset = new_list_offset;
        parent_node.num_subkeys += 1;

        // Update name length tracking
        let name_len_utf16 = (name.len() * 2) as u16;
        if name_len_utf16 > parent_node.largest_subkey_name_length {
            parent_node.largest_subkey_name_length = name_len_utf16;
        }

        let parent_bytes = parent_node.to_bytes();
        self.update_cell(parent_offset, &parent_bytes)?;

        Ok(())
    }

    /// Add a value to a key.
    pub fn add_value(
        &mut self,
        key_offset: u32,
        name: &str,
        data_type: DataType,
        data: &[u8],
    ) -> Result<u32> {
        // Create key value
        let mut key_value = KeyValue::new(name, data_type);

        // Store data
        if data.len() <= MAX_RESIDENT_DATA_SIZE {
            key_value.set_resident_data(data);
        } else if data.len() <= BIG_DATA_THRESHOLD {
            let data_offset = self.allocate_cell(data);
            key_value.data_offset = data_offset;
            key_value.data_size = data.len() as u32;
        } else if self.supports_big_data() {
            // Big data (only supported in minor version > 3)
            let data_offset = self.allocate_big_data(data)?;
            key_value.data_offset = data_offset;
            key_value.data_size = data.len() as u32;
        } else {
            // Big data not supported in this version
            return Err(Error::DataTooLarge {
                size: data.len(),
                max: BIG_DATA_THRESHOLD,
            });
        }

        let value_bytes = key_value.to_bytes();
        let value_offset = self.allocate_cell(&value_bytes);

        // Update key's values list
        self.add_value_to_key(key_offset, value_offset, name, data.len())?;

        Ok(value_offset)
    }

    /// Allocate big data.
    fn allocate_big_data(&mut self, data: &[u8]) -> Result<u32> {
        let num_segments = BigData::segments_needed(data.len());
        let mut segment_offsets = Vec::with_capacity(num_segments as usize);

        // Allocate data segments
        for i in 0..num_segments as usize {
            let start = i * MAX_DATA_SEGMENT_SIZE;
            let end = ((i + 1) * MAX_DATA_SEGMENT_SIZE).min(data.len());
            let segment = &data[start..end];
            let segment_offset = self.allocate_cell(segment);
            segment_offsets.push(segment_offset);
        }

        // Create segments list
        let mut segments_list = DataSegmentsList::new();
        segments_list.offsets = segment_offsets;
        let list_bytes = segments_list.to_bytes();
        let list_offset = self.allocate_cell(&list_bytes);

        // Create big data header
        let big_data = BigData::new(num_segments, list_offset);
        let bd_bytes = big_data.to_bytes();
        let bd_offset = self.allocate_cell(&bd_bytes);

        Ok(bd_offset)
    }

    /// Add a value reference to key's values list.
    fn add_value_to_key(
        &mut self,
        key_offset: u32,
        value_offset: u32,
        name: &str,
        data_size: usize,
    ) -> Result<()> {
        let key_cell = self.find_cell(key_offset)?;
        let mut key_node = KeyNode::parse(&key_cell.data)?;

        if key_node.values_list_offset == INVALID_OFFSET {
            // Create new values list with exact-fit allocation
            let list_bytes = value_offset.to_le_bytes().to_vec();
            let list_offset = self.allocate_cell(&list_bytes);
            key_node.values_list_offset = list_offset;
        } else {
            // Append to existing list
            let list_offset = key_node.values_list_offset;
            let list_cell = self.find_cell(list_offset)?;

            let mut values: Vec<u32> = list_cell
                .data
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();

            values.push(value_offset);

            let new_bytes: Vec<u8> = values
                .iter()
                .flat_map(|&v| v.to_le_bytes())
                .collect();

            // Update cell - may reallocate in compact mode
            let new_list_offset = self.update_cell(list_offset, &new_bytes)?;
            if new_list_offset != list_offset {
                // List was reallocated - update the key node reference
                key_node.values_list_offset = new_list_offset;
            }
        }

        key_node.num_values += 1;

        // Update size tracking
        let name_len_utf16 = (name.len() * 2) as u32;
        if name_len_utf16 > key_node.largest_value_name_length {
            key_node.largest_value_name_length = name_len_utf16;
        }
        if (data_size as u32) > key_node.largest_value_data_size {
            key_node.largest_value_data_size = data_size as u32;
        }

        let key_bytes = key_node.to_bytes();
        self.update_cell(key_offset, &key_bytes)?;

        Ok(())
    }

    /// Find a cell by offset.
    fn find_cell(&self, offset: u32) -> Result<&CellEntry> {
        self.cells
            .iter()
            .find(|c| c.offset == offset)
            .ok_or_else(|| Error::InvalidCellOffset(offset))
    }

    /// Update a cell's data. If data doesn't fit in compact mode, reallocates.
    fn update_cell(&mut self, offset: u32, data: &[u8]) -> Result<u32> {
        let new_size = required_cell_size(data.len());
        
        // Find the cell index first
        let cell_idx = self.cells
            .iter()
            .position(|c| c.offset == offset)
            .ok_or_else(|| Error::InvalidCellOffset(offset))?;
        
        if new_size <= self.cells[cell_idx].allocated_size {
            // Data fits in existing allocation
            self.cells[cell_idx].data = data.to_vec();
            Ok(offset)
        } else {
            // Data doesn't fit - reallocate
            let old_size = self.cells[cell_idx].allocated_size;
            
            // Mark old cell as free
            self.free_cells.push(FreeCell {
                offset,
                size: old_size as u32,
            });
            
            // Remove the old cell
            self.cells.remove(cell_idx);
            
            // Allocate new cell with exact fit
            let new_offset = self.allocate_cell(data);
            
            Ok(new_offset)
        }
    }

    /// Get the root key offset.
    pub fn root_offset(&self) -> u32 {
        self.root_offset
    }

    /// Set the root key name.
    pub fn set_root_name(&mut self, name: &str) {
        if let Some(cell) = self.cells.iter_mut().find(|c| c.offset == self.root_offset) {
            if let Ok(mut root_node) = KeyNode::parse(&cell.data) {
                root_node.set_name(name);
                cell.data = root_node.to_bytes();
            }
        }
    }

    /// Find a key by path (e.g., "Software\\Microsoft\\Windows").
    /// Returns the key offset if found.
    pub fn find_key(&self, path: &str) -> Result<u32> {
        if path.is_empty() {
            return Ok(self.root_offset);
        }

        let components: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current_offset = self.root_offset;

        for component in components {
            current_offset = self.find_subkey(current_offset, component)?;
        }

        Ok(current_offset)
    }

    /// Find a subkey by name. Handles all subkeys list types including Index Root.
    fn find_subkey(&self, parent_offset: u32, name: &str) -> Result<u32> {
        let parent_cell = self.find_cell(parent_offset)?;
        let parent_node = KeyNode::parse(&parent_cell.data)?;

        if parent_node.subkeys_list_offset == INVALID_OFFSET {
            return Err(Error::KeyNotFound(name.to_string()));
        }

        let list_cell = self.find_cell(parent_node.subkeys_list_offset)?;
        let name_upper = name.to_uppercase();

        // Parse the subkeys list
        let list = SubkeysList::parse(&list_cell.data)?;

        // Collect all key node offsets (handling Index Root recursively)
        let key_offsets = self.get_all_key_offsets_from_list(&list)?;

        // Search for the key by name
        for offset in key_offsets {
            if let Ok(cell) = self.find_cell(offset) {
                if let Ok(node) = KeyNode::parse(&cell.data) {
                    if node.name().to_uppercase() == name_upper {
                        return Ok(offset);
                    }
                }
            }
        }

        Err(Error::KeyNotFound(name.to_string()))
    }

    /// Get all key node offsets from a subkeys list, handling Index Root.
    fn get_all_key_offsets_from_list(&self, list: &SubkeysList) -> Result<Vec<u32>> {
        match list {
            SubkeysList::IndexRoot(ir) => {
                let mut all_offsets = Vec::new();
                for elem in &ir.elements {
                    if let Ok(sub_cell) = self.find_cell(elem.subkeys_list_offset) {
                        if let Ok(sub_list) = SubkeysList::parse(&sub_cell.data) {
                            // Per spec: Index Root can't point to another Index Root
                            let sub_offsets = sub_list.get_offsets();
                            all_offsets.extend(sub_offsets);
                        }
                    }
                }
                Ok(all_offsets)
            }
            _ => Ok(list.get_offsets()),
        }
    }

    /// Create a key at the given path, creating parent keys as needed.
    /// Returns the offset of the created (or existing) key.
    pub fn create_key(&mut self, path: &str) -> Result<u32> {
        if path.is_empty() {
            return Ok(self.root_offset);
        }

        let components: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current_offset = self.root_offset;

        for component in components {
            match self.find_subkey(current_offset, component) {
                Ok(offset) => {
                    current_offset = offset;
                }
                Err(Error::KeyNotFound(_)) => {
                    current_offset = self.add_key(current_offset, component)?;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(current_offset)
    }

    /// Add a string value to a key by path.
    pub fn add_value_string(&mut self, key_path: &str, name: Option<&str>, value: &str) -> Result<u32> {
        let key_offset = self.find_key(key_path)?;
        let data = encode_utf16le_string(value);
        self.add_value(key_offset, name.unwrap_or(""), DataType::String, &data)
    }

    /// Add a DWORD value to a key by path.
    pub fn add_value_dword(&mut self, key_path: &str, name: Option<&str>, value: u32) -> Result<u32> {
        let key_offset = self.find_key(key_path)?;
        self.add_value(key_offset, name.unwrap_or(""), DataType::Dword, &value.to_le_bytes())
    }

    /// Add a QWORD value to a key by path.
    pub fn add_value_qword(&mut self, key_path: &str, name: Option<&str>, value: u64) -> Result<u32> {
        let key_offset = self.find_key(key_path)?;
        self.add_value(key_offset, name.unwrap_or(""), DataType::Qword, &value.to_le_bytes())
    }

    /// Add a binary value to a key by path.
    pub fn add_value_binary(&mut self, key_path: &str, name: Option<&str>, data: &[u8]) -> Result<u32> {
        let key_offset = self.find_key(key_path)?;
        self.add_value(key_offset, name.unwrap_or(""), DataType::Binary, data)
    }

    /// Add a value with a specific type to a key by path.
    pub fn add_value_with_type(
        &mut self,
        key_path: &str,
        name: Option<&str>,
        data: &[u8],
        data_type: DataType,
    ) -> Result<u32> {
        let key_offset = self.find_key(key_path)?;
        self.add_value(key_offset, name.unwrap_or(""), data_type, data)
    }

    /// Build and return the hive as bytes.
    pub fn build(&mut self) -> Result<Vec<u8>> {
        self.to_bytes().map_err(Error::Io)
    }

    /// Build and write the hive to a writer.
    pub fn build_to_writer<W: Write + Seek>(&mut self, writer: &mut W) -> io::Result<()> {
        let mut actual_hive_size = self
            .bins
            .first()
            .map(|bin| bin.end())
            .unwrap_or(self.hive_bins_size);

        // Validate all cell offsets before writing
        for cell in &self.cells {
            let Some(bin) = find_bin(&self.bins, cell.offset) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cell at offset 0x{:08x} is outside known hive bins",
                        cell.offset
                    ),
                ));
            };
            let header_end = bin.offset + HIVE_BIN_HEADER_SIZE as u32;
            if cell.offset < header_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cell at offset 0x{:08x} is within bin header (bin starts at 0x{:08x}, data starts at 0x{:08x})",
                        cell.offset, bin.offset, header_end
                    ),
                ));
            }
            let cell_end = cell.offset + cell.allocated_size as u32;
            let bin_end = bin.end();
            if cell_end > bin_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cell at offset 0x{:08x} with size {} exceeds bin end 0x{:08x}",
                        cell.offset, cell.allocated_size, bin_end
                    ),
                ));
            }

            actual_hive_size = actual_hive_size.max(bin_end);
        }
        // Update base block with actual size (not pre-allocated size)
        self.base_block.hive_bins_data_size = actual_hive_size;
        self.base_block.root_cell_offset = self.root_offset;
        self.base_block.prepare_for_write();
        self.base_block.complete_write();

        // Write base block
        self.base_block.write(writer)?;

        // Build hive bins (only bins that are needed)
        for bin in self
            .bins
            .iter()
            .filter(|bin| bin.offset < actual_hive_size)
            .copied()
        {
            let bin_header = HiveBinHeader::new(bin.offset, bin.size);
            bin_header.write(writer)?;

            // Write cells in this bin
            let bin_end = bin.end();
            let mut cell_offset = bin.offset + HIVE_BIN_HEADER_SIZE as u32;

            // Collect cells in this bin
            let cells_in_bin: Vec<_> = self
                .cells
                .iter()
                .filter(|c| c.offset >= cell_offset && c.offset < bin_end)
                .cloned()
                .collect();

            // Sort by offset
            let mut sorted_cells = cells_in_bin;
            sorted_cells.sort_by_key(|c| c.offset);

            for cell in &sorted_cells {
                // Verify cell fits in this bin
                let cell_end = cell.offset + cell.allocated_size as u32;
                if cell_end > bin_end {
                    // Cell exceeds bin boundary - this is a bug in allocation
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Cell at offset {} with size {} exceeds bin boundary {}",
                            cell.offset, cell.allocated_size, bin_end)
                    ));
                }
                
                // Write any free space before this cell
                if cell.offset > cell_offset {
                    let free_size = cell.offset - cell_offset;
                    writer.write_all(&(free_size as i32).to_le_bytes())?;
                    writer.write_all(&vec![0u8; free_size as usize - 4])?;
                }

                // Write cell using the allocated size
                let cell_size = cell.allocated_size;
                let size_value = -(cell_size as i32);
                writer.write_all(&size_value.to_le_bytes())?;
                writer.write_all(&cell.data)?;

                // Padding to fill allocated size
                let padding = cell_size - 4 - cell.data.len();
                if padding > 0 {
                    writer.write_all(&vec![0u8; padding])?;
                }

                cell_offset = cell.offset + cell_size as u32;
            }

            // Write remaining free space in bin
            if cell_offset < bin_end {
                let free_size = bin_end - cell_offset;
                writer.write_all(&(free_size as i32).to_le_bytes())?;
                writer.write_all(&vec![0u8; free_size as usize - 4])?;
            }

        }

        writer.flush()?;
        Ok(())
    }

    /// Build and write the hive to a file.
    pub fn write_to_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        self.build_to_writer(&mut writer)
    }

    /// Build and return the hive as bytes.
    pub fn to_bytes(&mut self) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        self.build_to_writer(&mut cursor)?;
        Ok(buffer)
    }
}

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive::RegistryHive;

    #[test]
    fn test_create_empty_hive() {
        let mut builder = HiveBuilder::new();
        let bytes = builder.to_bytes().unwrap();

        // Should be able to parse the created hive
        let hive = RegistryHive::from_bytes(bytes).unwrap();
        let root = hive.root_key().unwrap();
        assert!(root.is_root());
    }

    #[test]
    fn test_add_key() {
        let mut builder = HiveBuilder::new();
        let root_offset = builder.root_offset();

        let software_offset = builder.add_key(root_offset, "Software").unwrap();
        assert!(software_offset > 0);

        let bytes = builder.to_bytes().unwrap();
        let hive = RegistryHive::from_bytes(bytes).unwrap();

        let root = hive.root_key().unwrap();
        let subkeys = root.subkeys().unwrap();
        assert_eq!(subkeys.len(), 1);
        assert_eq!(subkeys[0].name(), "Software");
    }

    #[test]
    fn test_add_value() {
        let mut builder = HiveBuilder::new();
        let root_offset = builder.root_offset();

        builder
            .add_value(root_offset, "TestValue", DataType::Dword, &42u32.to_le_bytes())
            .unwrap();

        let bytes = builder.to_bytes().unwrap();
        let hive = RegistryHive::from_bytes(bytes).unwrap();

        let root = hive.root_key().unwrap();
        let values = root.values().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name(), "TestValue");
        assert_eq!(values[0].dword_data().unwrap(), 42);
    }

    #[test]
    fn test_nested_keys() {
        let mut builder = HiveBuilder::new();
        let root_offset = builder.root_offset();

        let software_offset = builder.add_key(root_offset, "Software").unwrap();
        let microsoft_offset = builder.add_key(software_offset, "Microsoft").unwrap();
        builder.add_key(microsoft_offset, "Windows").unwrap();

        let bytes = builder.to_bytes().unwrap();
        let hive = RegistryHive::from_bytes(bytes).unwrap();

        let key = hive.open_key("Software\\Microsoft\\Windows").unwrap();
        assert_eq!(key.name(), "Windows");
    }

    #[test]
    fn test_tree_builder() {
        let mut root = KeyTreeNode::new("ROOT");
        
        let mut software = KeyTreeNode::new("Software");
        software.values.push(KeyTreeValue {
            name: "Version".to_string(),
            data_type: DataType::String,
            data: encode_utf16le_string("1.0.0"),
        });
        
        let mut microsoft = KeyTreeNode::new("Microsoft");
        microsoft.values.push(KeyTreeValue {
            name: "ProductID".to_string(),
            data_type: DataType::Dword,
            data: 12345u32.to_le_bytes().to_vec(),
        });
        software.children.push(microsoft);
        
        root.children.push(software);
        
        let mut builder = HiveBuilder::from_tree(root);
        let bytes = builder.to_bytes().unwrap();
        
        let hive = RegistryHive::from_bytes(bytes).unwrap();
        let root_key = hive.root_key().unwrap();
        assert_eq!(root_key.name(), "ROOT");
        
        let software_key = hive.open_key("Software").unwrap();
        assert_eq!(software_key.name(), "Software");
        
        let values = software_key.values().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name(), "Version");
        
        let microsoft_key = hive.open_key("Software\\Microsoft").unwrap();
        let ms_values = microsoft_key.values().unwrap();
        assert_eq!(ms_values.len(), 1);
        assert_eq!(ms_values[0].name(), "ProductID");
        assert_eq!(ms_values[0].dword_data().unwrap(), 12345);
    }

    #[test]
    fn test_version_constructors() {
        // Test different version constructors
        let builder1 = HiveBuilder::new();
        assert!(builder1.root_offset() > 0);

        let builder2 = HiveBuilder::with_version(1, 5);
        assert!(builder2.root_offset() > 0);

        let mut builder3 = HiveBuilder::new_with_name("TestRoot");
        let bytes = builder3.to_bytes().unwrap();
        let hive = RegistryHive::from_bytes(bytes).unwrap();
        assert_eq!(hive.root_key().unwrap().name(), "TestRoot");
    }

    #[test]
    fn test_key_tree_path_creation() {
        let mut root = KeyTreeNode::new("ROOT");
        
        // Create nested path
        let leaf = root.get_or_create_path("Software\\Microsoft\\Windows\\CurrentVersion");
        leaf.values.push(KeyTreeValue {
            name: "Version".to_string(),
            data_type: DataType::Dword,
            data: 10u32.to_le_bytes().to_vec(),
        });
        
        // Verify structure
        assert_eq!(root.count_keys(), 5); // ROOT + Software + Microsoft + Windows + CurrentVersion
        assert_eq!(root.count_values(), 1);
        
        let mut builder = HiveBuilder::from_tree(root);
        let bytes = builder.to_bytes().unwrap();
        let hive = RegistryHive::from_bytes(bytes).unwrap();
        
        let key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion").unwrap();
        let values = key.values().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].dword_data().unwrap(), 10);
    }
}
