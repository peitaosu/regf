//! Example: Converting .reg text files to registry hives.
//!
//! This example demonstrates how to parse .reg files and convert them
//! into binary registry hive files using both the high-level RegImporter
//! and the low-level manual approach.

use regf::reg_export::RegParser;
use regf::reg_import::RegImporter;
use regf::writer::HiveBuilder;
use regf::hive::RegistryHive;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== .reg Text to Hive Conversion Examples ===\n");

    // Example 0: Simple high-level import using RegImporter
    println!("--- Example 0: Simple Import using RegImporter ---");
    let simple_reg = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Example]
"Name"="Simple Example"
"Value"=dword:00000001
"#;
    
    // One-liner conversion using the new RegImporter
    let importer = RegImporter::from_string(simple_reg);
    let hive_bytes = importer.build_hive()?;
    let hive = RegistryHive::from_bytes(hive_bytes)?;
    println!("Created hive with root: {}", hive.root_key()?.name());
    println!("This is the recommended way for simple conversions!\n");

    // Example 1: Parse a simple .reg file (low-level)
    println!("--- Example 1: Low-level .reg Parsing ---");
    let reg_content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\MyCompany]
"CompanyName"="Acme Corporation"
"Founded"=dword:000007d0
@="Default Company Value"

[HKEY_LOCAL_MACHINE\SOFTWARE\MyCompany\Products]
"Product1"="Widget Pro"
"Product2"="Gadget Plus"
"Price"=dword:00000063

[HKEY_LOCAL_MACHINE\SOFTWARE\MyCompany\Settings]
"Enabled"=dword:00000001
"ConfigPath"=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,00,61,00,25,00,5c,00,4d,00,79,00,43,00,6f,00,6d,00,70,00,61,00,6e,00,79,00,00,00
"#;

    let parser = RegParser::new(reg_content.to_string());
    let entries = parser.parse();

    println!("Parsed {} key(s):", entries.len());
    for entry in &entries {
        println!("\n  Key: {}", entry.key_path);
        for value in &entry.values {
            let name = if value.name.is_empty() { "(Default)" } else { &value.name };
            println!("    {} ({:?}) = {} bytes", name, value.data_type, value.data.len());
        }
    }

    // Example 2: Convert .reg to hive
    println!("\n--- Example 2: Convert .reg to Binary Hive ---");
    let hive = reg_to_hive(reg_content)?;
    
    println!("\nCreated hive with keys:");
    for path in hive.enumerate_all_keys()? {
        println!("  {}", path);
    }

    // Example 3: Parse and convert a more complex .reg file
    println!("\n--- Example 3: Complex .reg File ---");
    let complex_reg = r#"Windows Registry Editor Version 5.00

; This is a comment - should be ignored
[HKEY_CURRENT_USER\Software\TestApp]
"Name"="Test Application"
"Version"="2.0.0"
"InstallDate"=hex(b):00,80,3e,d5,de,b1,9d,01
"Features"=hex(7):46,00,65,00,61,00,74,00,75,00,72,00,65,00,31,00,00,00,46,00,65,00,61,00,74,00,75,00,72,00,65,00,32,00,00,00,00,00

[HKEY_CURRENT_USER\Software\TestApp\Window]
"Width"=dword:00000320
"Height"=dword:00000258
"Maximized"=dword:00000000
"Position"=hex:64,00,00,00,64,00,00,00

[HKEY_CURRENT_USER\Software\TestApp\RecentFiles]
"File1"="C:\\Documents\\report.txt"
"File2"="C:\\Documents\\notes.txt"
"File3"="C:\\Documents\\data.csv"
"#;

    let hive = reg_to_hive(complex_reg)?;
    
    println!("Reading values from converted hive:");
    let app = hive.open_key("Software\\TestApp")?;
    for value in app.values()? {
        let name = if value.is_default() { "(Default)" } else { &value.name() };
        match value.data()? {
            regf::structures::RegistryValue::String(s) => println!("  {} = \"{}\"", name, s),
            regf::structures::RegistryValue::Dword(d) => println!("  {} = 0x{:08X}", name, d),
            regf::structures::RegistryValue::Qword(q) => println!("  {} = 0x{:016X}", name, q),
            regf::structures::RegistryValue::MultiString(ms) => println!("  {} = {:?}", name, ms),
            regf::structures::RegistryValue::Binary(b) => println!("  {} = {:02X?}", name, b),
            _ => println!("  {} = (other)", name),
        }
    }

    // Example 4: Save converted hive to disk
    println!("\n--- Example 4: Save to Disk ---");
    let output_path = std::env::temp_dir().join("converted.dat");
    
    let mut builder = build_hive_from_reg(complex_reg)?;
    builder.write_to_file(&output_path)?;
    println!("Saved hive to: {:?}", output_path);
    
    // Verify
    let loaded = RegistryHive::from_file(&output_path)?;
    println!("Loaded hive has {} keys", loaded.enumerate_all_keys()?.len());
    
    std::fs::remove_file(&output_path)?;

    // Example 5: Round-trip test (reg -> hive -> reg)
    println!("\n--- Example 5: Round-Trip Conversion ---");
    let original_reg = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\RoundTrip]
"StringValue"="Hello World"
"DwordValue"=dword:0000002a
"BinaryValue"=hex:01,02,03,04,05
"#;

    // Parse and convert to hive
    let hive = reg_to_hive(original_reg)?;
    
    // Export back to .reg format
    use regf::reg_export::{RegExporter, RegExportOptions, RegVersion};
    let options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: "HKEY_LOCAL_MACHINE".to_string(),
        include_empty_keys: false,
        recursive: true,
    };
    let exporter = RegExporter::new(&hive, options);
    let mut output = Vec::new();
    exporter.export(&mut output)?;
    
    println!("Original .reg:");
    println!("{}", original_reg);
    println!("After round-trip:");
    print_reg_content(&output);

    println!("\nAll examples completed!");
    Ok(())
}

/// Convert a .reg file content string to a RegistryHive
fn reg_to_hive(reg_content: &str) -> Result<RegistryHive, Box<dyn std::error::Error>> {
    let mut builder = build_hive_from_reg(reg_content)?;
    let bytes = builder.to_bytes()?;
    Ok(RegistryHive::from_bytes(bytes)?)
}

/// Build a HiveBuilder from .reg content
fn build_hive_from_reg(reg_content: &str) -> Result<HiveBuilder, Box<dyn std::error::Error>> {
    let parser = RegParser::new(reg_content.to_string());
    let entries = parser.parse();
    
    let mut builder = HiveBuilder::new();
    let root = builder.root_offset();
    
    // Track created keys: path -> offset
    let mut key_offsets: HashMap<String, u32> = HashMap::new();
    key_offsets.insert(String::new(), root);
    
    for entry in entries {
        // Strip the root hive prefix (e.g., HKEY_LOCAL_MACHINE\)
        let path = strip_hive_prefix(&entry.key_path);
        
        // Create the key path
        let key_offset = ensure_key_path(&mut builder, &mut key_offsets, &path)?;
        
        // Add values
        for value in entry.values {
            builder.add_value(
                key_offset,
                &value.name,
                value.data_type,
                &value.data,
            )?;
        }
    }
    
    Ok(builder)
}

/// Strip the hive prefix from a key path
fn strip_hive_prefix(path: &str) -> String {
    let prefixes = [
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_CURRENT_USER\\",
        "HKEY_CLASSES_ROOT\\",
        "HKEY_USERS\\",
        "HKEY_CURRENT_CONFIG\\",
        "HKLM\\",
        "HKCU\\",
        "HKCR\\",
        "HKU\\",
        "HKCC\\",
    ];
    
    for prefix in prefixes {
        if let Some(rest) = path.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    
    // Also handle case-insensitive
    let upper = path.to_uppercase();
    for prefix in prefixes {
        if let Some(idx) = upper.find(&prefix.to_uppercase()) {
            if idx == 0 {
                return path[prefix.len()..].to_string();
            }
        }
    }
    
    path.to_string()
}

/// Ensure a key path exists, creating parent keys as needed
fn ensure_key_path(
    builder: &mut HiveBuilder,
    offsets: &mut HashMap<String, u32>,
    path: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    if path.is_empty() {
        return Ok(*offsets.get("").unwrap());
    }
    
    if let Some(&offset) = offsets.get(path) {
        return Ok(offset);
    }
    
    // Find parent path
    let parts: Vec<&str> = path.split('\\').collect();
    let parent_path = if parts.len() > 1 {
        parts[..parts.len() - 1].join("\\")
    } else {
        String::new()
    };
    
    // Ensure parent exists
    let parent_offset = ensure_key_path(builder, offsets, &parent_path)?;
    
    // Create this key
    let key_name = parts.last().unwrap();
    let key_offset = builder.add_key(parent_offset, key_name)?;
    offsets.insert(path.to_string(), key_offset);
    
    Ok(key_offset)
}

/// Print .reg file content (handles UTF-16LE BOM)
fn print_reg_content(data: &[u8]) {
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
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
        println!("{}", String::from_utf8_lossy(data));
    }
}

