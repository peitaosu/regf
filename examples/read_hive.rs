//! Example: Reading and exploring a real Windows registry hive.
//!
//! This example shows how to read a real Windows registry hive file
//! (like NTUSER.DAT, SOFTWARE, SYSTEM, etc.) and explore its contents.
//!
//! Usage: cargo run --example read_hive -- <path_to_hive>
//!
//! Note: On Windows, you may need administrator privileges to access
//! some hive files. You can also use hive files extracted from backups
//! or forensic images.

use regf::hive::RegistryHive;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Registry Hive Explorer");
        println!("======================\n");
        println!("Usage: {} <hive_file> [key_path]", args[0]);
        println!("\nExamples:");
        println!("  {} NTUSER.DAT", args[0]);
        println!("  {} SOFTWARE Microsoft\\\\Windows", args[0]);
        println!("  {} SYSTEM ControlSet001\\\\Services", args[0]);
        println!("\nCommon hive locations on Windows:");
        println!("  %USERPROFILE%\\NTUSER.DAT");
        println!("  %SystemRoot%\\System32\\config\\SOFTWARE");
        println!("  %SystemRoot%\\System32\\config\\SYSTEM");
        println!("  %SystemRoot%\\System32\\config\\SAM");
        println!("  %SystemRoot%\\System32\\config\\SECURITY");
        return Ok(());
    }

    let hive_path = &args[1];
    let key_path = args.get(2).map(|s| s.as_str()).unwrap_or("");

    println!("=== Registry Hive Explorer ===\n");
    println!("Loading: {}", hive_path);

    let hive = RegistryHive::from_file(hive_path)?;

    // Display hive information
    println!("\n--- Hive Information ---");
    let (major, minor) = hive.version();
    println!("Version: {}.{}", major, minor);
    println!("File Name: {}", hive.file_name());
    println!("Is Dirty: {}", hive.is_dirty());

    // Navigate to the specified key or root
    let key = if key_path.is_empty() {
        hive.root_key()?
    } else {
        println!("\nNavigating to: {}", key_path);
        hive.open_key(key_path)?
    };

    // Display key information
    let key_name = if key.name().is_empty() { "(Root)".to_string() } else { key.name() };
    println!("\n--- Key: {} ---", key_name);
    if let Some(ts) = key.last_written() {
        println!("Last Written: {}", ts);
    }
    println!("Subkeys: {}", key.subkey_count());
    println!("Values: {}", key.value_count());

    // List values
    let values = key.values()?;
    if !values.is_empty() {
        println!("\n--- Values ---");
        for value in &values {
            let name = if value.is_default() { 
                "(Default)".to_string() 
            } else { 
                value.name() 
            };
            
            let type_str = format!("{:?}", value.data_type());
            let data_str = match value.data() {
                Ok(data) => format_registry_value(&data),
                Err(e) => format!("(Error: {})", e),
            };
            
            println!("  {} [{}] = {}", name, type_str, data_str);
        }
    }

    // List subkeys
    let subkeys = key.subkeys()?;
    if !subkeys.is_empty() {
        println!("\n--- Subkeys ---");
        for subkey in &subkeys {
            let count_info = format!(
                "{} subkeys, {} values",
                subkey.subkey_count(),
                subkey.value_count()
            );
            println!("  {}  ({})", subkey.name(), count_info);
        }
    }

    // If showing root, also show a tree view (limited depth)
    if key_path.is_empty() && key.subkey_count() > 0 {
        println!("\n--- Tree View (depth 2) ---");
        print_tree(&key, "", 0, 2)?;
    }

    Ok(())
}

/// Format a registry value for display
fn format_registry_value(value: &regf::structures::RegistryValue) -> String {
    match value {
        regf::structures::RegistryValue::None => "(None)".to_string(),
        regf::structures::RegistryValue::String(s) => {
            let display = if s.len() > 60 {
                format!("\"{}...\"", &s[..60])
            } else {
                format!("\"{}\"", s)
            };
            display
        }
        regf::structures::RegistryValue::MultiString(strings) => {
            if strings.len() > 3 {
                format!("{:?}... ({} total)", &strings[..3], strings.len())
            } else {
                format!("{:?}", strings)
            }
        }
        regf::structures::RegistryValue::Binary(data) => {
            if data.len() > 16 {
                format!("{:02X?}... ({} bytes)", &data[..16], data.len())
            } else {
                format!("{:02X?}", data)
            }
        }
        regf::structures::RegistryValue::Dword(v) => format!("0x{:08X} ({})", v, v),
        regf::structures::RegistryValue::DwordBigEndian(v) => format!("0x{:08X} BE", v),
        regf::structures::RegistryValue::Qword(v) => format!("0x{:016X} ({})", v, v),
    }
}

/// Print a tree view of registry keys
fn print_tree(
    key: &regf::hive::RegistryKey,
    prefix: &str,
    depth: usize,
    max_depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if depth >= max_depth {
        return Ok(());
    }

    let subkeys = key.subkeys()?;
    let count = subkeys.len();

    for (i, subkey) in subkeys.iter().enumerate() {
        let is_last = i == count - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let extension = if is_last { "    " } else { "│   " };

        println!("{}{}{}", prefix, connector, subkey.name());

        // Show value count if any
        if subkey.value_count() > 0 {
            let val_prefix = format!("{}{}    ", prefix, extension);
            println!("{}({} values)", val_prefix, subkey.value_count());
        }

        // Recurse
        let new_prefix = format!("{}{}", prefix, extension);
        print_tree(&subkey, &new_prefix, depth + 1, max_depth)?;
    }

    Ok(())
}

