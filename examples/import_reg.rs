//! Example: Import .reg text file to binary hive
//!
//! This example demonstrates converting a Windows .reg file to a binary hive.

use regf::reg_import::{RegImportOptions, RegImporter};
use regf::RegistryHive;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        // Demo mode: create a sample .reg content and import it
        println!("=== Demo: Importing .reg content to binary hive ===\n");
        demo_import()?;
    } else {
        // File mode: import the specified .reg file
        let input_path = &args[1];
        let output_path = if args.len() > 2 {
            args[2].clone()
        } else {
            format!("{}.dat", input_path.trim_end_matches(".reg"))
        };
        
        import_file(input_path, &output_path)?;
    }

    Ok(())
}

fn demo_import() -> Result<(), Box<dyn std::error::Error>> {
    // Sample .reg content
    let reg_content = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\MyApp]
"AppName"="My Application"
"Version"=dword:00010203
"InstallDate"=hex(b):00,60,f0,5d,00,00,00,00
"Settings"=hex:01,02,03,04,05

[HKEY_LOCAL_MACHINE\SOFTWARE\MyApp\Config]
"DebugMode"=dword:00000000
"LogLevel"="Info"
"Features"=hex(7):46,00,65,00,61,00,74,00,75,00,72,00,65,00,31,00,00,00,46,00,65,00,61,00,74,00,75,00,72,00,65,00,32,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\MyApp\Users]
@="DefaultUser"
"LastUser"="Admin"

"#;

    println!("Input .reg content:");
    println!("---");
    println!("{}", reg_content);
    println!("---\n");

    // Parse and import
    let importer = RegImporter::from_string(reg_content);
    println!("Parsed {} registry entries from .reg content", importer.entry_count());
    
    // Build the hive
    let hive_bytes = importer.build_hive()?;
    println!("Built binary hive: {} bytes\n", hive_bytes.len());

    // Write to temp file
    let temp_path = std::env::temp_dir().join("demo_import.dat");
    fs::write(&temp_path, &hive_bytes)?;
    println!("Wrote hive to: {}\n", temp_path.display());

    // Verify by reading it back
    println!("=== Verifying imported hive ===\n");
    let hive = RegistryHive::from_bytes(hive_bytes)?;
    let root = hive.root_key()?;
    
    println!("Root key: {}", root.name());
    print_key_recursive(&root, 0)?;

    // Clean up
    fs::remove_file(&temp_path)?;

    Ok(())
}

fn import_file(input: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Importing: {} -> {}", input, output);
    
    // Create importer with options
    let options = RegImportOptions {
        root_name: "ImportedHive".to_string(),
        ..Default::default()
    };
    
    let importer = RegImporter::from_file_with_options(input, options)?;
    println!("Parsed {} registry entries", importer.entry_count());
    
    // Build and write
    importer.build_hive_to_file(output)?;
    println!("Successfully wrote hive to: {}", output);

    // Verify
    println!("\n=== Verifying imported hive ===\n");
    let hive = RegistryHive::from_file(output)?;
    let root = hive.root_key()?;
    
    println!("Root key: {}", root.name());
    print_key_recursive(&root, 0)?;

    Ok(())
}

fn print_key_recursive(
    key: &regf::hive::RegistryKey,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let indent = "  ".repeat(depth);
    
    // Print values
    for value in key.values()? {
        let name = if value.is_default() {
            "@".to_string()
        } else {
            value.name()
        };
        
        let data_str = match value.data() {
            Ok(data) => format!("{:?}", data),
            Err(_) => "<error reading data>".to_string(),
        };
        
        // Truncate long data
        let data_str = if data_str.len() > 60 {
            format!("{}...", &data_str[..57])
        } else {
            data_str
        };
        
        println!("{}  {} = {}", indent, name, data_str);
    }
    
    // Print subkeys
    for subkey in key.subkeys()? {
        println!("{}[{}]", indent, subkey.name());
        print_key_recursive(&subkey, depth + 1)?;
    }
    
    Ok(())
}

