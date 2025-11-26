//! Basic example demonstrating how to use the regf library.
//!
//! This example creates a new registry hive, adds keys and values,
//! writes it to a file, and then reads it back.

use regf::hive::RegistryHive;
use regf::writer::HiveBuilder;
use regf::structures::DataType;
use regf::reg_export::{RegExporter, RegExportOptions, RegVersion};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new registry hive
    println!("Creating new registry hive...");
    let mut builder = HiveBuilder::new();
    let root = builder.root_offset();

    // Add some keys
    let software = builder.add_key(root, "Software")?;
    let microsoft = builder.add_key(software, "Microsoft")?;
    let windows = builder.add_key(microsoft, "Windows")?;
    let current_version = builder.add_key(windows, "CurrentVersion")?;

    // Add some values
    let version_str = "10.0.19041\0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>();
    builder.add_value(current_version, "CurrentVersion", DataType::String, &version_str)?;
    builder.add_value(current_version, "CurrentBuild", DataType::Dword, &19041u32.to_le_bytes())?;
    builder.add_value(current_version, "InstallDate", DataType::Qword, &1609459200u64.to_le_bytes())?;

    // Add a multi-string value
    let paths = "C:\\Windows\0C:\\Windows\\System32\0\0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>();
    builder.add_value(current_version, "ProgramFilesPath", DataType::MultiString, &paths)?;

    // Write to a temporary file
    let temp_path = std::env::temp_dir().join("test_hive.dat");
    println!("Writing hive to: {:?}", temp_path);
    builder.write_to_file(&temp_path)?;

    // Read it back
    println!("\nReading hive back...");
    let hive = RegistryHive::from_file(&temp_path)?;

    // Display hive info
    println!("Hive version: {:?}", hive.version());
    println!("Hive file name: {}", hive.file_name());
    println!("Is dirty: {}", hive.is_dirty());

    // Navigate to the key we created
    let key = hive.open_key("Software\\Microsoft\\Windows\\CurrentVersion")?;
    println!("\nKey: {}", key.name());
    println!("Last written: {:?}", key.last_written());
    println!("Subkey count: {}", key.subkey_count());
    println!("Value count: {}", key.value_count());

    // Read values
    println!("\nValues:");
    for value in key.values()? {
        let name = if value.is_default() { 
            "(Default)".to_string() 
        } else { 
            value.name() 
        };
        println!("  {} ({:?}): {:?}", name, value.data_type(), value.data()?);
    }

    // Export to .reg format
    let reg_path = std::env::temp_dir().join("test_export.reg");
    println!("\nExporting to: {:?}", reg_path);

    let options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: "HKEY_LOCAL_MACHINE".to_string(),
        include_empty_keys: true,
        recursive: true,
    };

    let exporter = RegExporter::new(&hive, options);
    exporter.export_to_file(&reg_path)?;

    // Print the .reg file content
    println!("\n.reg file content:");
    let reg_content = std::fs::read(&reg_path)?;
    
    // Skip BOM and convert from UTF-16LE
    if reg_content.len() >= 2 && reg_content[0] == 0xFF && reg_content[1] == 0xFE {
        let u16_values: Vec<u16> = reg_content[2..]
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some(u16::from_le_bytes([c[0], c[1]]))
                } else {
                    None
                }
            })
            .collect();
        let content = String::from_utf16_lossy(&u16_values);
        println!("{}", content);
    }

    // Enumerate all keys
    println!("\n--- All keys in hive ---");
    for path in hive.enumerate_all_keys()? {
        println!("  {}", path);
    }

    // Clean up
    std::fs::remove_file(&temp_path)?;
    std::fs::remove_file(&reg_path)?;

    println!("\nDone!");
    Ok(())
}

