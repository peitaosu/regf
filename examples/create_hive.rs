//! Example: Creating a complete registry hive from scratch.
//!
//! This example demonstrates how to create a registry hive with a complex
//! structure including nested keys, various value types, and multiple branches.

use regf::writer::HiveBuilder;
use regf::structures::DataType;
use regf::hive::RegistryHive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Creating a SOFTWARE-like Registry Hive ===\n");

    let mut builder = HiveBuilder::new();
    let root = builder.root_offset();

    // Create main branches like in a real SOFTWARE hive
    let classes = builder.add_key(root, "Classes")?;
    let microsoft = builder.add_key(root, "Microsoft")?;
    let policies = builder.add_key(root, "Policies")?;
    let wow6432node = builder.add_key(root, "Wow6432Node")?;

    // === Classes branch ===
    let txt_ext = builder.add_key(classes, ".txt")?;
    add_string_value(&mut builder, txt_ext, "", "txtfile")?;
    add_string_value(&mut builder, txt_ext, "Content Type", "text/plain")?;
    add_string_value(&mut builder, txt_ext, "PerceivedType", "text")?;

    let txtfile = builder.add_key(classes, "txtfile")?;
    add_string_value(&mut builder, txtfile, "", "Text Document")?;
    
    let shell = builder.add_key(txtfile, "shell")?;
    let open = builder.add_key(shell, "open")?;
    let command = builder.add_key(open, "command")?;
    add_string_value(&mut builder, command, "", "notepad.exe %1")?;

    // === Microsoft branch ===
    let windows = builder.add_key(microsoft, "Windows")?;
    let current_version = builder.add_key(windows, "CurrentVersion")?;

    // Add various value types
    add_string_value(&mut builder, current_version, "ProductName", "Windows 11 Pro")?;
    add_string_value(&mut builder, current_version, "EditionID", "Professional")?;
    add_string_value(&mut builder, current_version, "DisplayVersion", "23H2")?;
    
    builder.add_value(
        current_version,
        "CurrentMajorVersionNumber",
        DataType::Dword,
        &11u32.to_le_bytes(),
    )?;
    
    builder.add_value(
        current_version,
        "CurrentMinorVersionNumber",
        DataType::Dword,
        &0u32.to_le_bytes(),
    )?;

    // REG_EXPAND_SZ example (environment variable)
    let expand_str = encode_utf16("%SystemRoot%\\System32");
    builder.add_value(current_version, "CommonFilesDir", DataType::ExpandString, &expand_str)?;

    // Program Files paths
    let program_files = builder.add_key(current_version, "ProgramFilesDir")?;
    add_string_value(&mut builder, program_files, "", "C:\\Program Files")?;
    
    // App Paths
    let app_paths = builder.add_key(current_version, "App Paths")?;
    
    let notepad_path = builder.add_key(app_paths, "notepad.exe")?;
    add_string_value(&mut builder, notepad_path, "", "C:\\Windows\\System32\\notepad.exe")?;
    add_string_value(&mut builder, notepad_path, "Path", "C:\\Windows\\System32")?;

    let calc_path = builder.add_key(app_paths, "calc.exe")?;
    add_string_value(&mut builder, calc_path, "", "C:\\Windows\\System32\\calc.exe")?;

    // Uninstall information
    let uninstall = builder.add_key(current_version, "Uninstall")?;
    
    let app1 = builder.add_key(uninstall, "{12345678-1234-1234-1234-123456789ABC}")?;
    add_string_value(&mut builder, app1, "DisplayName", "Example Application")?;
    add_string_value(&mut builder, app1, "DisplayVersion", "1.0.0")?;
    add_string_value(&mut builder, app1, "Publisher", "Example Corp")?;
    add_string_value(&mut builder, app1, "UninstallString", "C:\\Program Files\\ExampleApp\\uninstall.exe")?;
    builder.add_value(app1, "EstimatedSize", DataType::Dword, &102400u32.to_le_bytes())?;
    builder.add_value(app1, "NoModify", DataType::Dword, &1u32.to_le_bytes())?;
    builder.add_value(app1, "NoRepair", DataType::Dword, &1u32.to_le_bytes())?;

    // === Policies branch ===
    let ms_policies = builder.add_key(policies, "Microsoft")?;
    let windows_pol = builder.add_key(ms_policies, "Windows")?;
    let explorer_pol = builder.add_key(windows_pol, "Explorer")?;
    builder.add_value(explorer_pol, "NoDesktop", DataType::Dword, &0u32.to_le_bytes())?;

    // === Wow6432Node branch (32-bit on 64-bit) ===
    let wow_microsoft = builder.add_key(wow6432node, "Microsoft")?;
    add_string_value(&mut builder, wow_microsoft, "Description", "32-bit application settings")?;

    // Write to file
    let output_path = std::env::temp_dir().join("software_example.dat");
    println!("Writing hive to: {:?}", output_path);
    builder.write_to_file(&output_path)?;

    // Verify by reading back
    println!("\n=== Verifying Created Hive ===\n");
    let hive = RegistryHive::from_file(&output_path)?;

    // Display all keys
    println!("All keys in hive:");
    for path in hive.enumerate_all_keys()? {
        println!("  {}", path);
    }

    // Show some specific values
    println!("\n--- CurrentVersion Values ---");
    let cv = hive.open_key("Microsoft\\Windows\\CurrentVersion")?;
    for value in cv.values()? {
        let name = if value.is_default() { "(Default)" } else { &value.name() };
        println!("  {} = {:?}", name, value.data()?);
    }

    println!("\n--- App Paths ---");
    let apps = hive.open_key("Microsoft\\Windows\\CurrentVersion\\App Paths")?;
    for subkey in apps.subkeys()? {
        println!("  {}", subkey.name());
        for value in subkey.values()? {
            let name = if value.is_default() { "(Default)" } else { &value.name() };
            println!("    {} = {:?}", name, value.data()?);
        }
    }

    // Cleanup
    std::fs::remove_file(&output_path)?;
    println!("\nDone!");

    Ok(())
}

/// Helper function to add a REG_SZ string value
fn add_string_value(
    builder: &mut HiveBuilder,
    key_offset: u32,
    name: &str,
    value: &str,
) -> Result<u32, Box<dyn std::error::Error>> {
    let data = encode_utf16(value);
    Ok(builder.add_value(key_offset, name, DataType::String, &data)?)
}

/// Encode a string as UTF-16LE with null terminator
fn encode_utf16(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    bytes.extend_from_slice(&[0, 0]); // null terminator
    bytes
}

