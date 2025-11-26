//! Example: Round-trip verification of registry hive export/import.
//!
//! This example reads a registry hive, exports it to .reg format,
//! imports the .reg back to a new hive, and verifies data integrity.
//!
//! Usage: cargo run --example roundtrip -- <hive_file>
//!
//! If no file is specified, uses Registry.dat from the project root.

use regf::hive::{RegistryHive, RegistryKey};
use regf::reg_export::{RegExportOptions, RegExporter, RegVersion};
use regf::reg_import::{RegImportOptions, RegImporter};
use regf::structures::{DataType, RegistryValue};
use std::collections::HashMap;
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    let input_path = if args.len() > 1 {
        args[1].clone()
    } else {
        "Registry.dat".to_string()
    };

    if !Path::new(&input_path).exists() {
        println!("Round-Trip Verification Test");
        println!("=============================\n");
        println!("Usage: {} <hive_file>", args[0]);
        println!("\nThis example performs a round-trip test:");
        println!("  1. Read original hive");
        println!("  2. Export to .reg format");
        println!("  3. Import .reg to new hive");
        println!("  4. Compare all keys and values");
        return Ok(());
    }

    println!("=== Round-Trip Verification Test ===\n");

    // Step 1: Read original hive
    println!("--- Step 1: Reading Original Hive ---");
    println!("File: {}", input_path);
    
    let original_hive = RegistryHive::from_file(&input_path)?;
    let original_root = original_hive.root_key()?;
    let root_name = original_root.name();
    
    println!("Root key: {}", root_name);
    println!("Version: {:?}", original_hive.version());
    
    let mut original_data = HashMap::new();
    collect_keys_and_values(&original_root, &root_name, &mut original_data);
    
    let orig_key_count = original_data.len();
    let orig_value_count: usize = original_data.values().map(|v| v.len()).sum();
    println!("Keys: {}, Values: {}", orig_key_count, orig_value_count);

    // Step 2: Export to .reg format
    println!("\n--- Step 2: Exporting to .reg ---");
    let reg_path = std::env::temp_dir().join("roundtrip_export.reg");
    
    let export_options = RegExportOptions {
        version: RegVersion::Version5,
        root_path: format!("HKEY_LOCAL_MACHINE\\{}", root_name),
        include_empty_keys: true,
        recursive: true,
    };
    
    let exporter = RegExporter::new(&original_hive, export_options);
    exporter.export_to_file(&reg_path)?;
    
    let reg_size = std::fs::metadata(&reg_path)?.len();
    println!("Exported to: {}", reg_path.display());
    println!("File size: {} bytes", reg_size);

    // Step 3: Import back to new hive
    println!("\n--- Step 3: Importing to New Hive ---");
    let new_hive_path = std::env::temp_dir().join("roundtrip_imported.dat");
    
    let import_options = RegImportOptions {
        root_name: root_name.clone(),
        strip_prefix: Some(format!("HKEY_LOCAL_MACHINE\\{}", root_name)),
        minor_version: 6,
    };
    
    let importer = RegImporter::from_file_with_options(&reg_path, import_options)?;
    println!("Parsed {} entries", importer.entry_count());
    
    importer.build_hive_to_file(&new_hive_path)?;
    
    let new_hive_size = std::fs::metadata(&new_hive_path)?.len();
    println!("Created: {}", new_hive_path.display());
    println!("File size: {} bytes", new_hive_size);

    // Step 4: Read and compare
    println!("\n--- Step 4: Reading Imported Hive ---");
    let new_hive = RegistryHive::from_file(&new_hive_path)?;
    let new_root = new_hive.root_key()?;
    
    println!("Root key: {}", new_root.name());
    
    let mut imported_data = HashMap::new();
    collect_keys_and_values(&new_root, &new_root.name(), &mut imported_data);
    
    let imp_key_count = imported_data.len();
    let imp_value_count: usize = imported_data.values().map(|v| v.len()).sum();
    println!("Keys: {}, Values: {}", imp_key_count, imp_value_count);

    // Step 5: Compare
    println!("\n--- Step 5: Comparison ---");
    let (missing, extra, value_diffs) = compare_hive_data(&original_data, &imported_data);
    
    println!("Keys:");
    println!("  Original: {}", orig_key_count);
    println!("  Imported: {}", imp_key_count);
    println!("  Missing:  {}", missing.len());
    println!("  Extra:    {}", extra.len());
    
    println!("\nValues:");
    println!("  Original: {}", orig_value_count);
    println!("  Imported: {}", imp_value_count);
    println!("  Differences: {}", value_diffs.len());

    // Print first few differences if any
    if !missing.is_empty() {
        println!("\nMissing keys (first 5):");
        for key in missing.iter().take(5) {
            println!("  - {}", key);
        }
    }
    
    if !extra.is_empty() {
        println!("\nExtra keys (first 5):");
        for key in extra.iter().take(5) {
            println!("  - {}", key);
        }
    }
    
    if !value_diffs.is_empty() {
        println!("\nValue differences (first 5):");
        for (path, diff) in value_diffs.iter().take(5) {
            println!("  [{}]: {}", path, diff);
        }
    }

    // Result
    println!("\n=== Result ===");
    let success = missing.is_empty() && extra.is_empty() && value_diffs.is_empty();
    
    if success {
        println!("PASS: Round-trip identical!");
        println!("  {} keys, {} values verified", orig_key_count, orig_value_count);
    } else {
        println!("FAIL: Differences found");
    }

    // Cleanup
    std::fs::remove_file(&reg_path)?;
    std::fs::remove_file(&new_hive_path)?;
    println!("\nTemporary files cleaned up.");

    if !success {
        std::process::exit(1);
    }
    
    Ok(())
}

/// Value information for comparison
#[derive(Clone)]
struct ValueInfo {
    name: String,
    data_type: DataType,
    data: RegistryValue,
}

/// Recursively collect all keys and their values
fn collect_keys_and_values(
    key: &RegistryKey,
    path: &str,
    result: &mut HashMap<String, Vec<ValueInfo>>,
) {
    let mut values = Vec::new();
    if let Ok(key_values) = key.values() {
        for v in key_values {
            values.push(ValueInfo {
                name: v.name(),
                data_type: v.data_type(),
                data: v.data().unwrap_or(RegistryValue::None),
            });
        }
    }
    values.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    result.insert(path.to_string(), values);

    if let Ok(subkeys) = key.subkeys() {
        for sk in subkeys {
            let new_path = if path.is_empty() {
                sk.name()
            } else {
                format!("{}\\{}", path, sk.name())
            };
            collect_keys_and_values(&sk, &new_path, result);
        }
    }
}

/// Compare two hive data sets, returns (missing_keys, extra_keys, value_diffs)
fn compare_hive_data(
    original: &HashMap<String, Vec<ValueInfo>>,
    imported: &HashMap<String, Vec<ValueInfo>>,
) -> (Vec<String>, Vec<String>, Vec<(String, String)>) {
    // Normalize to lowercase for case-insensitive comparison
    let orig_norm: HashMap<String, &Vec<ValueInfo>> = original
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    let imp_norm: HashMap<String, &Vec<ValueInfo>> = imported
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    
    let orig_keys: std::collections::HashSet<_> = orig_norm.keys().cloned().collect();
    let imp_keys: std::collections::HashSet<_> = imp_norm.keys().cloned().collect();
    
    let missing: Vec<String> = orig_keys.difference(&imp_keys).cloned().collect();
    let extra: Vec<String> = imp_keys.difference(&orig_keys).cloned().collect();
    
    let mut value_diffs = Vec::new();
    
    for key in orig_keys.intersection(&imp_keys) {
        let orig_vals = orig_norm.get(key).unwrap();
        let imp_vals = imp_norm.get(key).unwrap();
        
        let orig_map: HashMap<String, &ValueInfo> = orig_vals
            .iter()
            .map(|v| (v.name.to_lowercase(), v))
            .collect();
        let imp_map: HashMap<String, &ValueInfo> = imp_vals
            .iter()
            .map(|v| (v.name.to_lowercase(), v))
            .collect();
        
        for (name, orig_val) in &orig_map {
            match imp_map.get(name) {
                None => {
                    value_diffs.push((key.clone(), format!("missing: {}", orig_val.name)));
                }
                Some(imp_val) => {
                    if orig_val.data_type != imp_val.data_type {
                        value_diffs.push((
                            key.clone(),
                            format!("{}: type {:?} vs {:?}", orig_val.name, orig_val.data_type, imp_val.data_type),
                        ));
                    } else if !values_equal(&orig_val.data, &imp_val.data) {
                        value_diffs.push((
                            key.clone(),
                            format!("{}: data mismatch", orig_val.name),
                        ));
                    }
                }
            }
        }
        
        for (name, imp_val) in &imp_map {
            if !orig_map.contains_key(name) {
                value_diffs.push((key.clone(), format!("extra: {}", imp_val.name)));
            }
        }
    }
    
    (missing, extra, value_diffs)
}

/// Check if two RegistryValues are equal
fn values_equal(a: &RegistryValue, b: &RegistryValue) -> bool {
    match (a, b) {
        (RegistryValue::None, RegistryValue::None) => true,
        (RegistryValue::String(s1), RegistryValue::String(s2)) => s1 == s2,
        (RegistryValue::MultiString(v1), RegistryValue::MultiString(v2)) => v1 == v2,
        (RegistryValue::Binary(b1), RegistryValue::Binary(b2)) => b1 == b2,
        (RegistryValue::Dword(d1), RegistryValue::Dword(d2)) => d1 == d2,
        (RegistryValue::DwordBigEndian(d1), RegistryValue::DwordBigEndian(d2)) => d1 == d2,
        (RegistryValue::Qword(q1), RegistryValue::Qword(q2)) => q1 == q2,
        _ => false,
    }
}
