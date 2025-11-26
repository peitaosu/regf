//! # regf - Windows Registry Hive File Parser
//!
//! This crate provides functionality for parsing, manipulating, and writing
//! Windows Registry hive files (regf format).
//!
//! ## Features
//!
//! - Parse regf/dat registry hive files
//! - Read and modify registry keys and values
//! - Write registry data back to disk
//! - Export to .reg text format
//! - Import from .reg text format
//!
//! ## Example
//!
//! ```no_run
//! use regf::RegistryHive;
//!
//! // Load a registry hive
//! let hive = RegistryHive::from_file("NTUSER.DAT").unwrap();
//!
//! // Get the root key
//! let root = hive.root_key().unwrap();
//!
//! // Iterate through subkeys
//! for subkey in root.subkeys().unwrap() {
//!     println!("Key: {}", subkey.name());
//! }
//! ```

pub mod error;
pub mod structures;
pub mod parser;
pub mod hive;
pub mod reg_export;
pub mod reg_import;
pub mod writer;
pub mod transaction_log;

pub use error::{Error, Result};
pub use hive::RegistryHive;
pub use structures::*;
pub use transaction_log::TransactionLog;
pub use reg_import::{RegImporter, RegImportOptions, reg_to_hive, reg_file_to_hive_file};
pub use writer::{HiveBuilder, KeyTreeNode, KeyTreeValue};

