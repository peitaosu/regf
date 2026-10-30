use regf::hive::{RegistryHive, RegistryKey};
use std::collections::HashSet;
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let hive_path = env::args().nth(1).ok_or("usage: validate_hive <hive>")?;
    let hive = RegistryHive::from_file(&hive_path)?;
    let root = hive.root_key()?;
    let mut pending_keys = vec![root];
    let mut visited_offsets = HashSet::new();
    let mut key_count = 0usize;
    let mut value_count = 0usize;
    let mut data_byte_count = 0usize;
    let mut typed_error_count = 0usize;

    while let Some(key) = pending_keys.pop() {
        let subkeys = validate_key(
            &key,
            &mut visited_offsets,
            &mut key_count,
            &mut value_count,
            &mut data_byte_count,
            &mut typed_error_count,
        )?;
        pending_keys.extend(subkeys);
    }

    let (major_version, minor_version) = hive.version();
    println!(
        "{}: version={major_version}.{minor_version} dirty={} keys={key_count} values={value_count} data_bytes={data_byte_count} typed_errors={typed_error_count}",
        hive_path,
        hive.is_dirty()
    );
    Ok(())
}

fn validate_key<'a>(
    key: &RegistryKey<'a>,
    visited_offsets: &mut HashSet<u32>,
    key_count: &mut usize,
    value_count: &mut usize,
    data_byte_count: &mut usize,
    typed_error_count: &mut usize,
) -> Result<Vec<RegistryKey<'a>>, Box<dyn Error>> {
    if !visited_offsets.insert(key.offset()) {
        return Err(format!("duplicate key offset {:#010x}", key.offset()).into());
    }

    let key_path = key
        .path()
        .map_err(|error| format!("key at {:#010x}: {error}", key.offset()))?;
    key.class_name()
        .map_err(|error| format!("class name for {key_path}: {error}"))?;

    let values = key
        .values()
        .map_err(|error| format!("values for {key_path}: {error}"))?;
    if let Some(declared_value_count) = key.value_count() {
        if values.len() != declared_value_count as usize {
            return Err(format!(
                "key {} declares {declared_value_count} values but exposes {}",
                key_path,
                values.len()
            )
            .into());
        }
    }

    for value in values {
        let value_name = value.name();
        let raw_data = value
            .raw_data()
            .map_err(|error| format!("raw data for {key_path}\\{value_name}: {error}"))?;
        if raw_data.len() != value.data_size() as usize {
            return Err(format!(
                "value {} at {:#010x} declares {} bytes but exposes {}",
                value_name,
                value.offset(),
                value.data_size(),
                raw_data.len()
            )
            .into());
        }
        if let Err(error) = value.data() {
            eprintln!(
                "typed data for {key_path}\\{value_name}, type {}, size {}: {error}",
                value.raw_data_type(),
                raw_data.len()
            );
            *typed_error_count += 1;
        }
        *value_count += 1;
        *data_byte_count += raw_data.len();
    }

    let subkeys = key
        .subkeys()
        .map_err(|error| format!("subkeys for {key_path}: {error}"))?;
    if subkeys.len() != key.subkey_count() as usize {
        return Err(format!(
            "key {} declares {} subkeys but exposes {}",
            key_path,
            key.subkey_count(),
            subkeys.len()
        )
        .into());
    }

    *key_count += 1;
    Ok(subkeys)
}
