//! Export registry hives to .reg text format.
//!
//! This module provides functionality to export registry data to the
//! standard Windows .reg file format that can be imported with regedit.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::error::Result;
use crate::hive::{RegistryHive, RegistryKey, RegistryValueEntry};
use crate::structures::DataType;

/// Version of .reg file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegVersion {
    /// Windows 2000/XP format (Unicode).
    Version5,
    /// Legacy Windows 9x format (ANSI).
    Version4,
}

impl RegVersion {
    /// Get the header line for this version.
    pub fn header(&self) -> &'static str {
        match self {
            RegVersion::Version5 => "Windows Registry Editor Version 5.00",
            RegVersion::Version4 => "REGEDIT4",
        }
    }
}

/// Options for .reg export.
#[derive(Debug, Clone)]
pub struct RegExportOptions {
    /// Version of .reg format.
    pub version: RegVersion,
    /// Root path prefix (e.g., "HKEY_LOCAL_MACHINE\\SOFTWARE").
    pub root_path: String,
    /// Include empty keys.
    pub include_empty_keys: bool,
    /// Export recursively.
    pub recursive: bool,
}

impl Default for RegExportOptions {
    fn default() -> Self {
        Self {
            version: RegVersion::Version5,
            root_path: String::new(),
            include_empty_keys: true,
            recursive: true,
        }
    }
}

/// Export a registry hive to .reg format.
pub struct RegExporter<'a> {
    hive: &'a RegistryHive,
    options: RegExportOptions,
}

impl<'a> RegExporter<'a> {
    /// Create a new exporter for the given hive.
    pub fn new(hive: &'a RegistryHive, options: RegExportOptions) -> Self {
        Self { hive, options }
    }

    /// Export the hive to a writer.
    pub fn export<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write BOM for Unicode files
        if self.options.version == RegVersion::Version5 {
            writer.write_all(&[0xFF, 0xFE])?;
        }

        // Write header
        self.write_line(writer, self.options.version.header())?;
        self.write_line(writer, "")?;

        // Export from root
        let root = self.hive.root_key()?;
        self.export_key(writer, &root, &self.options.root_path)?;

        Ok(())
    }

    /// Export a single key and optionally its subkeys.
    fn export_key<W: Write>(&self, writer: &mut W, key: &RegistryKey, path: &str) -> Result<()> {
        // Determine the key path for this key
        // If the key name matches the last component of the path, don't append it
        let key_path = if path.is_empty() {
            key.name()
        } else if key.name().is_empty() {
            path.to_string()
        } else {
            // Check if path already ends with this key's name
            let path_last_component = path.rsplit('\\').next().unwrap_or("");
            if path_last_component.eq_ignore_ascii_case(&key.name()) {
                // Root key case: path already contains the key name
                path.to_string()
            } else {
                format!("{}\\{}", path, key.name())
            }
        };

        let values = key.values()?;
        let should_export = !values.is_empty() || self.options.include_empty_keys;

        if should_export && !key_path.is_empty() {
            // Write key header
            self.write_line(writer, &format!("[{}]", key_path))?;

            // Write values
            for value in &values {
                self.export_value(writer, value)?;
            }

            self.write_line(writer, "")?;
        }

        // Export subkeys recursively
        if self.options.recursive {
            for subkey in key.subkeys()? {
                self.export_key(writer, &subkey, &key_path)?;
            }
        }

        Ok(())
    }

    /// Export a single value.
    fn export_value<W: Write>(&self, writer: &mut W, value: &RegistryValueEntry) -> Result<()> {
        let name = if value.is_default() {
            "@".to_string()
        } else {
            format!("\"{}\"", escape_string(&value.name()))
        };

        let data = value.raw_data()?;
        let data_type = value.data_type();

        let value_str = match data_type {
            DataType::String => {
                let s = decode_reg_string(&data);
                format!("{}=\"{}\"", name, escape_string(&s))
            }

            DataType::ExpandString => {
                let s = decode_reg_string(&data);
                format!("{}=hex(2):{}", name, format_hex_data(&encode_reg_string(&s)))
            }

            DataType::Dword => {
                let v = if data.len() >= 4 {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                } else {
                    0
                };
                format!("{}=dword:{:08x}", name, v)
            }

            DataType::DwordBigEndian => {
                format!("{}=hex(5):{}", name, format_hex_data(&data))
            }

            DataType::Qword => {
                format!("{}=hex(b):{}", name, format_hex_data(&data))
            }

            DataType::MultiString => {
                format!("{}=hex(7):{}", name, format_hex_data(&data))
            }

            DataType::Binary => {
                format!("{}=hex:{}", name, format_hex_data(&data))
            }

            DataType::Link => {
                format!("{}=hex(6):{}", name, format_hex_data(&data))
            }

            DataType::None => {
                format!("{}=hex(0):{}", name, format_hex_data(&data))
            }

            _ => {
                // Generic hex format for other types
                format!(
                    "{}=hex({:x}):{}", 
                    name, 
                    value.raw_data_type(), 
                    format_hex_data(&data)
                )
            }
        };

        self.write_line(writer, &value_str)?;
        Ok(())
    }

    /// Write a line in the appropriate encoding.
    fn write_line<W: Write>(&self, writer: &mut W, line: &str) -> io::Result<()> {
        if self.options.version == RegVersion::Version5 {
            // UTF-16LE encoding
            for c in line.encode_utf16() {
                writer.write_all(&c.to_le_bytes())?;
            }
            // CRLF
            writer.write_all(&[0x0D, 0x00, 0x0A, 0x00])?;
        } else {
            // ASCII/ANSI
            writeln!(writer, "{}", line)?;
        }
        Ok(())
    }

    /// Export to a file.
    pub fn export_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        self.export(&mut writer)
    }
}

/// Escape a string for .reg file format.
fn escape_string(s: &str) -> String {
    let mut result = String::new();

    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\0' => result.push_str("\\0"),
            _ => result.push(c),
        }
    }

    result
}

/// Decode a UTF-16LE string from registry data.
fn decode_reg_string(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let u16_values: Vec<u16> = data
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some(u16::from_le_bytes([chunk[0], chunk[1]]))
            } else {
                None
            }
        })
        .collect();

    // Find null terminator
    let end = u16_values.iter().position(|&c| c == 0).unwrap_or(u16_values.len());

    String::from_utf16_lossy(&u16_values[..end])
}

/// Encode a string to UTF-16LE for registry format.
fn encode_reg_string(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Add null terminator
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

/// Format binary data as hex string for .reg format.
fn format_hex_data(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let hex_values: Vec<String> = data.iter().map(|b| format!("{:02x}", b)).collect();

    // Split into lines of ~80 characters
    let mut result = String::new();
    let mut line_len = 0;
    const MAX_LINE_LEN: usize = 76;

    for (i, hex) in hex_values.iter().enumerate() {
        if i > 0 {
            result.push(',');
            line_len += 1;
        }

        if line_len + hex.len() > MAX_LINE_LEN {
            result.push_str("\\\r\n  ");
            line_len = 2;
        }

        result.push_str(hex);
        line_len += hex.len();
    }

    result
}

/// Parse a .reg file and return the data.
pub struct RegParser {
    content: String,
}

impl RegParser {
    /// Create a new parser from .reg file content.
    pub fn new(content: String) -> Self {
        Self { content }
    }

    /// Read a .reg file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;

        // Detect encoding (check for UTF-16 BOM)
        let content = if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            // UTF-16LE
            let u16_values: Vec<u16> = bytes[2..]
                .chunks(2)
                .filter_map(|c| {
                    if c.len() == 2 {
                        Some(u16::from_le_bytes([c[0], c[1]]))
                    } else {
                        None
                    }
                })
                .collect();
            String::from_utf16_lossy(&u16_values)
        } else {
            // ASCII/UTF-8
            String::from_utf8_lossy(&bytes).to_string()
        };

        Ok(Self { content })
    }

    /// Parse the .reg file content.
    pub fn parse(&self) -> Vec<RegEntry> {
        let mut entries = Vec::new();
        let mut current_key: Option<String> = None;
        let mut current_values = Vec::new();

        for line in self.content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            // Skip header lines
            if line.starts_with("Windows Registry Editor")
                || line.starts_with("REGEDIT")
            {
                continue;
            }

            // Key line
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous key
                if let Some(key) = current_key.take() {
                    entries.push(RegEntry {
                        key_path: key,
                        values: std::mem::take(&mut current_values),
                    });
                }

                current_key = Some(line[1..line.len() - 1].to_string());
                continue;
            }

            // Value line
            if current_key.is_some() {
                if let Some(value) = parse_value_line(line) {
                    current_values.push(value);
                }
            }
        }

        // Save last key
        if let Some(key) = current_key {
            entries.push(RegEntry {
                key_path: key,
                values: current_values,
            });
        }

        entries
    }
}

/// A registry entry from a .reg file.
#[derive(Debug, Clone)]
pub struct RegEntry {
    /// Full key path (e.g., "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test").
    pub key_path: String,
    /// Values under this key.
    pub values: Vec<RegValue>,
}

/// A registry value from a .reg file.
#[derive(Debug, Clone)]
pub struct RegValue {
    /// Value name (empty for default value).
    pub name: String,
    /// Data type.
    pub data_type: DataType,
    /// Raw data bytes.
    pub data: Vec<u8>,
}

/// Parse a value line from a .reg file.
fn parse_value_line(line: &str) -> Option<RegValue> {
    let line = line.trim();

    // Handle line continuation
    let line = if line.ends_with('\\') {
        &line[..line.len() - 1]
    } else {
        line
    };

    // Find the = separator
    let eq_pos = line.find('=')?;
    let name_part = &line[..eq_pos];
    let value_part = &line[eq_pos + 1..];

    // Parse name
    let name = if name_part == "@" {
        String::new()
    } else if name_part.starts_with('"') && name_part.ends_with('"') {
        unescape_string(&name_part[1..name_part.len() - 1])
    } else {
        return None;
    };

    // Parse value
    let (data_type, data) = if value_part.starts_with('"') {
        // String value
        let end_quote = value_part.rfind('"')?;
        let s = unescape_string(&value_part[1..end_quote]);
        (DataType::String, encode_reg_string(&s))
    } else if value_part.starts_with("dword:") {
        let hex = &value_part[6..];
        let v = u32::from_str_radix(hex, 16).ok()?;
        (DataType::Dword, v.to_le_bytes().to_vec())
    } else if value_part.starts_with("hex:") {
        let hex_data = parse_hex_data(&value_part[4..])?;
        (DataType::Binary, hex_data)
    } else if value_part.starts_with("hex(") {
        let end_paren = value_part.find(')')?;
        let type_hex = &value_part[4..end_paren];
        let type_num = u32::from_str_radix(type_hex, 16).ok()?;
        let data_type = DataType::from(type_num);

        let hex_data = if end_paren + 2 < value_part.len() {
            parse_hex_data(&value_part[end_paren + 2..])?
        } else {
            Vec::new()
        };

        (data_type, hex_data)
    } else {
        return None;
    };

    Some(RegValue {
        name,
        data_type,
        data,
    })
}

/// Unescape a string from .reg format.
fn unescape_string(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('0') => result.push('\0'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Parse hex data from a .reg hex string.
fn parse_hex_data(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.replace(|c: char| c.is_whitespace() || c == '\\', "");
    let parts: Vec<&str> = hex.split(',').filter(|s| !s.is_empty()).collect();

    let mut data = Vec::with_capacity(parts.len());
    for part in parts {
        let byte = u8::from_str_radix(part.trim(), 16).ok()?;
        data.push(byte);
    }

    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_string() {
        assert_eq!(escape_string("test"), "test");
        assert_eq!(escape_string("test\\path"), "test\\\\path");
        assert_eq!(escape_string("say \"hello\""), "say \\\"hello\\\"");
    }

    #[test]
    fn test_format_hex_data() {
        assert_eq!(format_hex_data(&[0x00]), "00");
        assert_eq!(format_hex_data(&[0x00, 0xFF]), "00,ff");
        assert_eq!(format_hex_data(&[]), "");
    }

    #[test]
    fn test_parse_value_line() {
        let value = parse_value_line("\"Test\"=\"Hello\"").unwrap();
        assert_eq!(value.name, "Test");
        assert_eq!(value.data_type, DataType::String);

        let value = parse_value_line("@=dword:0000002a").unwrap();
        assert_eq!(value.name, "");
        assert_eq!(value.data_type, DataType::Dword);
        assert_eq!(value.data, vec![42, 0, 0, 0]);
    }

    #[test]
    fn test_reg_parser() {
        let content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"StringValue"="Hello"
"DwordValue"=dword:0000002a
"#;

        let parser = RegParser::new(content.to_string());
        let entries = parser.parse();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test");
        assert_eq!(entries[0].values.len(), 2);
    }
}

