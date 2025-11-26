//! Example: Converting a registry hive to .reg text format.
//!
//! This example demonstrates various ways to export registry hives to
//! the standard Windows .reg file format.

use regf::hive::RegistryHive;
use regf::writer::HiveBuilder;
use regf::structures::DataType;
use regf::reg_export::{RegExporter, RegExportOptions, RegVersion};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hive to .reg Text Conversion Examples ===\n");

    // First, create a sample hive with various data types
    let hive = create_sample_hive()?;

    // Example 1: Export entire hive with default options
    println!("--- Example 1: Full Export (Unicode) ---");
    let options = RegExportOptions::default();
    let exporter = RegExporter::new(&hive, options);
    
    let mut output = Vec::new();
    exporter.export(&mut output)?;
    print_reg_content(&output);

    // Example 2: Export with custom root path
    println!("\n--- Example 2: Custom Root Path ---");
    let options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: "HKEY_LOCAL_MACHINE\\SOFTWARE\\MyApp".to_string(),
        include_empty_keys: true,
        recursive: true,
    };
    let exporter = RegExporter::new(&hive, options);
    
    let mut output = Vec::new();
    exporter.export(&mut output)?;
    print_reg_content(&output);

    // Example 3: Export in legacy REGEDIT4 format (ANSI)
    println!("\n--- Example 3: Legacy Format (REGEDIT4) ---");
    let options = RegExportOptions {
        version: RegVersion::Version4,
        root_path: "HKEY_CURRENT_USER\\Software\\Test".to_string(),
        include_empty_keys: false,
        recursive: true,
    };
    let exporter = RegExporter::new(&hive, options);
    
    let mut output = Vec::new();
    exporter.export(&mut output)?;
    // REGEDIT4 format is ASCII, so we can print directly
    println!("{}", String::from_utf8_lossy(&output));

    // Example 4: Export to file
    println!("\n--- Example 4: Export to File ---");
    let reg_path = std::env::temp_dir().join("exported.reg");
    let options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: "HKEY_CURRENT_USER\\Software\\Example".to_string(),
        include_empty_keys: true,
        recursive: true,
    };
    let exporter = RegExporter::new(&hive, options);
    exporter.export_to_file(&reg_path)?;
    println!("Exported to: {:?}", reg_path);
    
    // Read and display the file
    let content = std::fs::read(&reg_path)?;
    print_reg_content(&content);
    
    // Cleanup
    std::fs::remove_file(&reg_path)?;

    // Example 5: Export specific subtree only
    println!("\n--- Example 5: Selective Export (Non-Recursive) ---");
    let options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: "HKEY_LOCAL_MACHINE\\SOFTWARE".to_string(),
        include_empty_keys: true,
        recursive: false, // Only export the root key, not subkeys
    };
    let exporter = RegExporter::new(&hive, options);
    
    let mut output = Vec::new();
    exporter.export(&mut output)?;
    print_reg_content(&output);

    println!("\nAll examples completed!");
    Ok(())
}

/// Create a sample hive with various data types for demonstration
fn create_sample_hive() -> Result<RegistryHive, Box<dyn std::error::Error>> {
    let mut builder = HiveBuilder::new();
    let root = builder.root_offset();

    // Create some keys and values
    let settings = builder.add_key(root, "Settings")?;
    
    // REG_SZ - String
    let str_data = encode_utf16("Hello, World!");
    builder.add_value(settings, "Greeting", DataType::String, &str_data)?;
    
    // REG_EXPAND_SZ - Expandable string with environment variables
    let expand_data = encode_utf16("%USERPROFILE%\\Documents");
    builder.add_value(settings, "DocsPath", DataType::ExpandString, &expand_data)?;
    
    // REG_DWORD - 32-bit integer
    builder.add_value(settings, "Count", DataType::Dword, &42u32.to_le_bytes())?;
    builder.add_value(settings, "Flags", DataType::Dword, &0xDEADBEEFu32.to_le_bytes())?;
    
    // REG_QWORD - 64-bit integer
    builder.add_value(settings, "BigNumber", DataType::Qword, &9876543210u64.to_le_bytes())?;
    
    // REG_BINARY - Binary data
    let binary_data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0xFF, 0xFE];
    builder.add_value(settings, "RawData", DataType::Binary, &binary_data)?;
    
    // REG_MULTI_SZ - Multiple strings
    let multi_data = encode_multi_string(&["First", "Second", "Third"]);
    builder.add_value(settings, "MultiValue", DataType::MultiString, &multi_data)?;
    
    // Default value
    let default_data = encode_utf16("Default Value");
    builder.add_value(settings, "", DataType::String, &default_data)?;

    // Nested keys
    let advanced = builder.add_key(settings, "Advanced")?;
    builder.add_value(advanced, "DebugMode", DataType::Dword, &1u32.to_le_bytes())?;
    builder.add_value(advanced, "LogLevel", DataType::Dword, &3u32.to_le_bytes())?;

    let network = builder.add_key(settings, "Network")?;
    let timeout_data = encode_utf16("30000");
    builder.add_value(network, "Timeout", DataType::String, &timeout_data)?;
    
    let servers = builder.add_key(network, "Servers")?;
    let server1 = encode_utf16("server1.example.com");
    let server2 = encode_utf16("server2.example.com");
    builder.add_value(servers, "Primary", DataType::String, &server1)?;
    builder.add_value(servers, "Secondary", DataType::String, &server2)?;

    // Build and return as RegistryHive
    let bytes = builder.to_bytes()?;
    Ok(RegistryHive::from_bytes(bytes)?)
}

/// Encode a string as UTF-16LE with null terminator
fn encode_utf16(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

/// Encode multiple strings as REG_MULTI_SZ
fn encode_multi_string(strings: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for s in strings {
        bytes.extend(s.encode_utf16().flat_map(|c| c.to_le_bytes()));
        bytes.extend_from_slice(&[0, 0]); // null terminator for each string
    }
    bytes.extend_from_slice(&[0, 0]); // final null terminator
    bytes
}

/// Print .reg file content (handles UTF-16LE BOM)
fn print_reg_content(data: &[u8]) {
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        // UTF-16LE with BOM
        let u16_values: Vec<u16> = data[2..]
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some(u16::from_le_bytes([c[0], c[1]]))
                } else {
                    None
                }
            })
            .collect();
        println!("{}", String::from_utf16_lossy(&u16_values));
    } else {
        // ASCII/UTF-8
        println!("{}", String::from_utf8_lossy(data));
    }
}

