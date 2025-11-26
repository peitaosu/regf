//! Import .reg text files to binary registry hives.
//!
//! This module provides functionality to convert standard Windows .reg files
//! (text format) into binary registry hive files (.dat/.regf).
//!
//! # Example
//!
//! ```no_run
//! use regf::reg_import::{RegImporter, RegImportOptions};
//!
//! // Import from a .reg file
//! let importer = RegImporter::from_file("settings.reg").unwrap();
//! let hive_bytes = importer.build_hive().unwrap();
//!
//! // Or with custom options
//! let options = RegImportOptions {
//!     root_name: "ImportedRoot".to_string(),
//!     ..Default::default()
//! };
//! let importer = RegImporter::from_file_with_options("settings.reg", options).unwrap();
//! importer.build_hive_to_file("output.dat").unwrap();
//! ```

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::reg_export::{RegEntry, RegParser};
use crate::writer::{HiveBuilder, KeyTreeNode, KeyTreeValue};

/// Options for .reg import.
#[derive(Debug, Clone)]
pub struct RegImportOptions {
    /// Name for the root key in the hive.
    /// If empty, uses the first key component from the .reg file.
    pub root_name: String,
    /// Strip this prefix from all key paths.
    /// E.g., "HKEY_LOCAL_MACHINE\\SOFTWARE" will make all keys relative to SOFTWARE.
    pub strip_prefix: Option<String>,
    /// Hive minor version (3=XP, 4=Vista, 5=Win7, 6=Win10).
    pub minor_version: u32,
}

impl Default for RegImportOptions {
    fn default() -> Self {
        Self {
            root_name: String::new(),
            strip_prefix: None,
            minor_version: 6,
        }
    }
}

/// Import .reg files to binary hive format.
pub struct RegImporter {
    entries: Vec<RegEntry>,
    options: RegImportOptions,
}

impl RegImporter {
    /// Create a new importer from parsed entries.
    pub fn new(entries: Vec<RegEntry>, options: RegImportOptions) -> Self {
        Self { entries, options }
    }

    /// Create an importer from .reg file content string.
    pub fn from_string(content: &str) -> Self {
        let parser = RegParser::new(content.to_string());
        Self::new(parser.parse(), RegImportOptions::default())
    }

    /// Create an importer from .reg file content with options.
    pub fn from_string_with_options(content: &str, options: RegImportOptions) -> Self {
        let parser = RegParser::new(content.to_string());
        Self::new(parser.parse(), options)
    }

    /// Create an importer from a .reg file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let parser = RegParser::from_file(path)?;
        Ok(Self::new(parser.parse(), RegImportOptions::default()))
    }

    /// Create an importer from a .reg file with options.
    pub fn from_file_with_options<P: AsRef<Path>>(
        path: P,
        options: RegImportOptions,
    ) -> io::Result<Self> {
        let parser = RegParser::from_file(path)?;
        Ok(Self::new(parser.parse(), options))
    }

    /// Determine the common root prefix from all entries.
    fn detect_common_prefix(&self) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }

        // Get first entry's path components
        let first_path = &self.entries[0].key_path;
        let components: Vec<&str> = first_path.split('\\').collect();

        if components.is_empty() {
            return None;
        }

        // Find common prefix across all entries
        let mut common_len = components.len();
        for entry in &self.entries[1..] {
            let entry_components: Vec<&str> = entry.key_path.split('\\').collect();
            let matching = components
                .iter()
                .zip(entry_components.iter())
                .take_while(|(a, b)| a == b)
                .count();
            common_len = common_len.min(matching);
        }

        if common_len == 0 {
            None
        } else {
            Some(components[..common_len].join("\\"))
        }
    }

    /// Strip prefix from a key path.
    fn strip_path_prefix<'a>(&self, path: &'a str, prefix: &str) -> &'a str {
        if path == prefix {
            ""
        } else if path.starts_with(prefix) {
            let stripped = &path[prefix.len()..];
            // Remove leading backslash if present
            stripped.strip_prefix('\\').unwrap_or(stripped)
        } else {
            path
        }
    }

    /// Build the binary hive from the parsed entries.
    /// 
    /// Uses tree-based building for allocation with known sizes
    /// so cells are allocated with exact-fit.
    pub fn build_hive(&self) -> Result<Vec<u8>> {
        if self.entries.is_empty() {
            return Err(Error::InvalidPath("No registry entries to import".into()));
        }

        // Determine prefix to strip
        let prefix = self
            .options
            .strip_prefix
            .clone()
            .or_else(|| self.detect_common_prefix())
            .unwrap_or_default();

        // Determine root name
        let root_name = if !self.options.root_name.is_empty() {
            self.options.root_name.clone()
        } else if !prefix.is_empty() {
            // Use last component of prefix as root name
            prefix
                .rsplit('\\')
                .next()
                .unwrap_or("Root")
                .to_string()
        } else {
            "Root".to_string()
        };

        // Build tree structure for optimal allocation
        let mut root = KeyTreeNode::new(&root_name);

        for entry in &self.entries {
            let stripped = self.strip_path_prefix(&entry.key_path, &prefix);
            
            // Get or create the key node at this path
            let key_node = root.get_or_create_path(stripped);

            // Add values to this key
            for value in &entry.values {
                key_node.values.push(KeyTreeValue {
                    name: value.name.clone(),
                    data_type: value.data_type,
                    data: value.data.clone(),
                });
            }
        }

        // Build hive from tree
        let mut builder = HiveBuilder::from_tree_with_version(root, 1, self.options.minor_version);

        // Build and return the hive bytes
        builder.build()
    }

    /// Build the hive and write it to a file.
    pub fn build_hive_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let hive_bytes = self.build_hive()?;
        let mut file = File::create(path)?;
        file.write_all(&hive_bytes)?;
        Ok(())
    }

    /// Get the parsed entries.
    pub fn entries(&self) -> &[RegEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Convenience function to convert a .reg file to a binary hive.
pub fn reg_to_hive<P: AsRef<Path>>(reg_path: P) -> Result<Vec<u8>> {
    let importer = RegImporter::from_file(reg_path).map_err(Error::Io)?;
    importer.build_hive()
}

/// Convenience function to convert a .reg file to a binary hive file.
pub fn reg_file_to_hive_file<P: AsRef<Path>, Q: AsRef<Path>>(
    reg_path: P,
    hive_path: Q,
) -> Result<()> {
    let importer = RegImporter::from_file(reg_path).map_err(Error::Io)?;
    importer.build_hive_to_file(hive_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive::RegistryHive;

    #[test]
    fn test_simple_import() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"StringValue"="Hello World"
"DwordValue"=dword:0000002a

"#;

        let importer = RegImporter::from_string(content);
        let hive_bytes = importer.build_hive().unwrap();

        // Verify the hive can be read
        let hive = RegistryHive::from_bytes(hive_bytes).unwrap();
        let root = hive.root_key().unwrap();
        
        // The root should be "Test"
        assert_eq!(root.name(), "Test");
        
        // Check values
        let values = root.values().unwrap();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn test_nested_keys_import() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Company]

[HKEY_LOCAL_MACHINE\SOFTWARE\Company\Product]
"Name"="TestProduct"
"Version"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Company\Product\Settings]
"Debug"=dword:00000000

"#;

        let importer = RegImporter::from_string(content);
        let hive_bytes = importer.build_hive().unwrap();

        let hive = RegistryHive::from_bytes(hive_bytes).unwrap();
        let root = hive.root_key().unwrap();
        
        // Should have Company or SOFTWARE as root
        let subkeys = root.subkeys().unwrap();
        assert!(!subkeys.is_empty());
    }

    #[test]
    fn test_custom_root_name() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"Value"="Test"

"#;

        let options = RegImportOptions {
            root_name: "CustomRoot".to_string(),
            ..Default::default()
        };
        
        let importer = RegImporter::from_string_with_options(content, options);
        let hive_bytes = importer.build_hive().unwrap();

        let hive = RegistryHive::from_bytes(hive_bytes).unwrap();
        let root = hive.root_key().unwrap();
        
        assert_eq!(root.name(), "CustomRoot");
    }

    #[test]
    fn test_binary_value_import() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"BinaryData"=hex:00,01,02,03,04,05

"#;

        let importer = RegImporter::from_string(content);
        let hive_bytes = importer.build_hive().unwrap();

        let hive = RegistryHive::from_bytes(hive_bytes).unwrap();
        let root = hive.root_key().unwrap();
        let values = root.values().unwrap();
        
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name(), "BinaryData");
    }

    #[test]
    fn test_strip_prefix() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion]
"ProgramFilesDir"="C:\\Program Files"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"App"="C:\\App\\app.exe"

"#;

        let options = RegImportOptions {
            strip_prefix: Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows".to_string()),
            root_name: "Windows".to_string(),
            ..Default::default()
        };
        
        let importer = RegImporter::from_string_with_options(content, options);
        let hive_bytes = importer.build_hive().unwrap();

        let hive = RegistryHive::from_bytes(hive_bytes).unwrap();
        let root = hive.root_key().unwrap();
        
        assert_eq!(root.name(), "Windows");
        
        // Should have CurrentVersion as a subkey
        let subkeys = root.subkeys().unwrap();
        assert_eq!(subkeys.len(), 1);
        assert_eq!(subkeys[0].name(), "CurrentVersion");
    }
}

