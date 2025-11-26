//! Error types for the regf crate.

use std::io;
use thiserror::Error;

/// The main error type for this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// IO error occurred while reading or writing.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Invalid signature in header or structure.
    #[error("Invalid signature: expected '{expected}', found '{found}'")]
    InvalidSignature { expected: String, found: String },

    /// Checksum mismatch.
    #[error("Checksum mismatch: expected {expected:#010x}, calculated {calculated:#010x}")]
    ChecksumMismatch { expected: u32, calculated: u32 },

    /// Sequence number mismatch (dirty hive).
    #[error("Sequence number mismatch: primary={primary}, secondary={secondary}")]
    SequenceMismatch { primary: u32, secondary: u32 },

    /// Invalid cell offset.
    #[error("Invalid cell offset: {0:#010x}")]
    InvalidCellOffset(u32),

    /// Invalid cell size.
    #[error("Invalid cell size: {0}")]
    InvalidCellSize(i32),

    /// Cell is unallocated.
    #[error("Cell at offset {0:#010x} is unallocated")]
    UnallocatedCell(u32),

    /// Unknown cell type.
    #[error("Unknown cell type: {0:?}")]
    UnknownCellType([u8; 2]),

    /// Invalid hive bin.
    #[error("Invalid hive bin at offset {offset:#010x}: {message}")]
    InvalidHiveBin { offset: u32, message: String },

    /// Key not found.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Value not found.
    #[error("Value not found: {0}")]
    ValueNotFound(String),

    /// Invalid UTF-16 string.
    #[error("Invalid UTF-16 string")]
    InvalidUtf16String,

    /// Invalid data type.
    #[error("Invalid data type: {0}")]
    InvalidDataType(u32),

    /// Data too large.
    #[error("Data too large: {size} bytes (max: {max})")]
    DataTooLarge { size: usize, max: usize },

    /// Buffer too small.
    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    /// Unsupported version.
    /// This crate supports versions 1.3-1.6 (Windows NT 4.0 through Windows 11).
    /// Versions 1.1-1.2 (Windows NT 3.1/3.5) have a different cell structure.
    #[error("Unsupported hive version: {major}.{minor} (supported: 1.3-1.6)")]
    UnsupportedVersion { major: u32, minor: u32 },

    /// Corrupt hive.
    #[error("Corrupt hive: {0}")]
    CorruptHive(String),

    /// Path parsing error.
    #[error("Invalid registry path: {0}")]
    InvalidPath(String),
}

/// Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

