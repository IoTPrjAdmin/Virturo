// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//! 
//! application utils
//! 
//! contains various utility functions
//!
//! 
use chrono;
use std::fs;
use std::path::Path;
use anyhow::anyhow;

// get time function
pub fn get_time_fmt(time_fmt: &str) -> String {
    let now_ts = chrono::Local::now();
    return now_ts.format(time_fmt).to_string();
}

// Wrapper around checking existence of a file
pub fn file_check_exists(file_path: &str) -> anyhow::Result<bool> {
    match fs::exists(file_path) {
       Ok(true) => return Ok(true),
       Ok(false) => return Err(anyhow!("File was not found: {}", file_path)),
       Err(err) => return Err(anyhow!("Failed to verify existence of file: {}", err))
   };
}

#[allow(dead_code)]
// Return filename only or empty string if not found
pub fn file_get_name_only(file_path: &str) ->&str {
    match Path::new(file_path).file_stem() {
        Some(f) => {
            match f.to_str() {
                Some(v) => return v,
                None => return ""
            }
        },
        None => return ""
    };
}

#[allow(dead_code)]
/// convert str to byte, return converted value or default
pub fn str_to_byte(val_str : &str, def_val: u8) -> u8 {
    return  match u8::from_str_radix(val_str, 10) {
        Ok(v) => v,
        Err(_) => def_val
    };
}

#[allow(dead_code)]
pub fn str_hex_to_byte(val_str : &str) -> anyhow::Result<u8> {
    let res = match u8::from_str_radix(val_str, 16) {
        Ok(v) => v,
        Err(err) => {return Err(anyhow!("Failed to convert to hex {}", err)); }
    };
    Ok(res)
}

pub fn hexstr_to_vec(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

#[allow(dead_code)]
// Returns true if buf contains pattern from first place
pub fn buff_starts_with(buf: &[u8], pattern: &[u8]) -> bool {
    // compare length
    if buf.len() < pattern.len() {
        return false;
    }
    // compare bytes
    // TODO improvement, it is possible to compare 2 or 4 bytes at once depending on the pattern
    for i in 0..pattern.len() {
        if buf[i] != pattern[i] {
            return false;
        }
    }
    return true;
}
