//! Registry data types.

use crate::error::{Error, Result};

/// Registry value data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// No type (REG_NONE).
    None,
    /// String (REG_SZ).
    String,
    /// Expandable string with environment variables (REG_EXPAND_SZ).
    ExpandString,
    /// Binary data (REG_BINARY).
    Binary,
    /// 32-bit little-endian integer (REG_DWORD, REG_DWORD_LITTLE_ENDIAN).
    Dword,
    /// 32-bit big-endian integer (REG_DWORD_BIG_ENDIAN).
    DwordBigEndian,
    /// Symbolic link (REG_LINK).
    Link,
    /// Multi-string (REG_MULTI_SZ).
    MultiString,
    /// Resource list (REG_RESOURCE_LIST).
    ResourceList,
    /// Full resource descriptor (REG_FULL_RESOURCE_DESCRIPTOR).
    FullResourceDescriptor,
    /// Resource requirements list (REG_RESOURCE_REQUIREMENTS_LIST).
    ResourceRequirementsList,
    /// 64-bit little-endian integer (REG_QWORD, REG_QWORD_LITTLE_ENDIAN).
    Qword,
    /// Unknown/custom data type (stores the raw type value).
    Unknown(u32),
}

impl DataType {
    /// Get the type name for display.
    pub fn name(&self) -> &'static str {
        match self {
            DataType::None => "REG_NONE",
            DataType::String => "REG_SZ",
            DataType::ExpandString => "REG_EXPAND_SZ",
            DataType::Binary => "REG_BINARY",
            DataType::Dword => "REG_DWORD",
            DataType::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            DataType::Link => "REG_LINK",
            DataType::MultiString => "REG_MULTI_SZ",
            DataType::ResourceList => "REG_RESOURCE_LIST",
            DataType::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            DataType::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            DataType::Qword => "REG_QWORD",
            DataType::Unknown(_) => "REG_UNKNOWN",
        }
    }

    /// Check if this is a string type.
    pub fn is_string(&self) -> bool {
        matches!(
            self,
            DataType::String | DataType::ExpandString | DataType::Link | DataType::MultiString
        )
    }

    /// Get the raw u32 value of this data type.
    pub fn raw_value(&self) -> u32 {
        match self {
            DataType::None => 0,
            DataType::String => 1,
            DataType::ExpandString => 2,
            DataType::Binary => 3,
            DataType::Dword => 4,
            DataType::DwordBigEndian => 5,
            DataType::Link => 6,
            DataType::MultiString => 7,
            DataType::ResourceList => 8,
            DataType::FullResourceDescriptor => 9,
            DataType::ResourceRequirementsList => 10,
            DataType::Qword => 11,
            DataType::Unknown(v) => *v,
        }
    }
}

impl From<u32> for DataType {
    fn from(value: u32) -> Self {
        match value {
            0 => DataType::None,
            1 => DataType::String,
            2 => DataType::ExpandString,
            3 => DataType::Binary,
            4 => DataType::Dword,
            5 => DataType::DwordBigEndian,
            6 => DataType::Link,
            7 => DataType::MultiString,
            8 => DataType::ResourceList,
            9 => DataType::FullResourceDescriptor,
            10 => DataType::ResourceRequirementsList,
            11 => DataType::Qword,
            _ => DataType::Unknown(value),
        }
    }
}

impl From<DataType> for u32 {
    fn from(dt: DataType) -> u32 {
        dt.raw_value()
    }
}

/// Registry value data.
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryValue {
    /// No value (REG_NONE).
    None,
    /// String value (REG_SZ, REG_EXPAND_SZ, REG_LINK).
    String(String),
    /// Multi-string value (REG_MULTI_SZ).
    MultiString(Vec<String>),
    /// Binary data (REG_BINARY and others).
    Binary(Vec<u8>),
    /// 32-bit integer (REG_DWORD).
    Dword(u32),
    /// 32-bit big-endian integer (REG_DWORD_BIG_ENDIAN).
    DwordBigEndian(u32),
    /// 64-bit integer (REG_QWORD).
    Qword(u64),
}

impl RegistryValue {
    /// Get the data type for this value.
    pub fn data_type(&self) -> DataType {
        match self {
            RegistryValue::None => DataType::None,
            RegistryValue::String(_) => DataType::String,
            RegistryValue::MultiString(_) => DataType::MultiString,
            RegistryValue::Binary(_) => DataType::Binary,
            RegistryValue::Dword(_) => DataType::Dword,
            RegistryValue::DwordBigEndian(_) => DataType::DwordBigEndian,
            RegistryValue::Qword(_) => DataType::Qword,
        }
    }

    /// Parse a value from raw bytes.
    pub fn from_bytes(data_type: DataType, data: &[u8]) -> Self {
        match data_type {
            DataType::None => RegistryValue::None,

            DataType::String | DataType::ExpandString | DataType::Link => {
                match decode_utf16le_string(data) {
                    Ok(s) => RegistryValue::String(s),
                    Err(_) => RegistryValue::Binary(data.to_vec()),
                }
            }

            DataType::MultiString => {
                match decode_multi_string(data) {
                    Ok(strings) => RegistryValue::MultiString(strings),
                    Err(_) => RegistryValue::Binary(data.to_vec()),
                }
            }

            DataType::Dword => {
                if data.len() < 4 {
                    return RegistryValue::Dword(0);
                }
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                RegistryValue::Dword(value)
            }

            DataType::DwordBigEndian => {
                if data.len() < 4 {
                    return RegistryValue::DwordBigEndian(0);
                }
                let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                RegistryValue::DwordBigEndian(value)
            }

            DataType::Qword => {
                if data.len() < 8 {
                    return RegistryValue::Qword(0);
                }
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                RegistryValue::Qword(value)
            }

            _ => RegistryValue::Binary(data.to_vec()),
        }
    }

    /// Encode the value to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RegistryValue::None => vec![],

            RegistryValue::String(s) => encode_utf16le_string(s),

            RegistryValue::MultiString(strings) => encode_multi_string(strings),

            RegistryValue::Binary(data) => data.clone(),

            RegistryValue::Dword(v) => v.to_le_bytes().to_vec(),

            RegistryValue::DwordBigEndian(v) => v.to_be_bytes().to_vec(),

            RegistryValue::Qword(v) => v.to_le_bytes().to_vec(),
        }
    }
}

/// Decode a UTF-16LE string from bytes.
pub fn decode_utf16le_string(data: &[u8]) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    // Convert bytes to u16 values
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

    String::from_utf16(&u16_values[..end]).map_err(|_| Error::InvalidUtf16String)
}

/// Encode a string to UTF-16LE bytes with null terminator.
pub fn encode_utf16le_string(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Add null terminator
    bytes.extend_from_slice(&[0, 0]);

    bytes
}

/// Decode a multi-string (REG_MULTI_SZ) from bytes.
pub fn decode_multi_string(data: &[u8]) -> Result<Vec<String>> {
    if data.is_empty() {
        return Ok(vec![]);
    }

    // Convert bytes to u16 values
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

    let mut strings = Vec::new();
    let mut start = 0;

    for (i, &c) in u16_values.iter().enumerate() {
        if c == 0 {
            if start < i {
                let s = String::from_utf16(&u16_values[start..i])
                    .map_err(|_| Error::InvalidUtf16String)?;
                strings.push(s);
            } else if start == i && !strings.is_empty() {
                // Double null terminator - end of multi-string
                break;
            }
            start = i + 1;
        }
    }

    Ok(strings)
}

/// Encode a multi-string to bytes.
pub fn encode_multi_string(strings: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for s in strings {
        bytes.extend(s.encode_utf16().flat_map(|c| c.to_le_bytes()));
        bytes.extend_from_slice(&[0, 0]); // Null terminator
    }

    // Final null terminator
    bytes.extend_from_slice(&[0, 0]);

    bytes
}

/// Decode an ASCII/extended ASCII string.
pub fn decode_ascii_string(data: &[u8]) -> String {
    // Find null terminator
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    
    // Extended ASCII - each byte maps to a character
    data[..end].iter().map(|&b| b as char).collect()
}

/// Encode a string as ASCII (for key/value names with COMP_NAME flag).
pub fn encode_ascii_string(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_conversion() {
        assert_eq!(DataType::from(0u32), DataType::None);
        assert_eq!(DataType::from(1u32), DataType::String);
        assert_eq!(DataType::from(4u32), DataType::Dword);
        assert_eq!(DataType::from(100u32), DataType::Unknown(100));
    }

    #[test]
    fn test_utf16_string() {
        let s = "Hello";
        let encoded = encode_utf16le_string(s);
        let decoded = decode_utf16le_string(&encoded).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn test_multi_string() {
        let strings = vec!["One".to_string(), "Two".to_string(), "Three".to_string()];
        let encoded = encode_multi_string(&strings);
        let decoded = decode_multi_string(&encoded).unwrap();
        assert_eq!(decoded, strings);
    }

    #[test]
    fn test_registry_value() {
        let value = RegistryValue::Dword(42);
        let bytes = value.to_bytes();
        let parsed = RegistryValue::from_bytes(DataType::Dword, &bytes);
        assert_eq!(parsed, value);
    }

    #[test]
    fn test_unknown_data_type() {
        let dt = DataType::from(999u32);
        assert_eq!(dt, DataType::Unknown(999));
        assert_eq!(dt.name(), "REG_UNKNOWN");
        assert_eq!(dt.raw_value(), 999);
        assert_eq!(u32::from(dt), 999);
    }
}

