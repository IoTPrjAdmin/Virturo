// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Handles application configurations as read from file.
//!
//!
use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;
use anyhow::{anyhow};

pub use crate::app_utils::*;

pub const TIME_FMT: &str = "%H:%M:%S.%3f";
pub const CNF_FORWARD_RULES_SECTION: &str = "forward_rules";
pub const CNF_GEN_SETTINGS_SECTION: &str = "settings";
pub const CNF_GEN_SETTING_TTL_DEFAULT: u16 = 30;

pub type CnfForwardRulesList = Vec<CnfForwardRules>;
pub type CnfSectionsDict = HashMap<String, serde_json::Value>;
pub type CnfNetInterfacesList = Vec<CnfNetInterface>;
pub type CnfForwardPatternsList =  Vec<CnfForwardPattern>;

// Patterns to detect and forward accordingly
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename(deserialize = "snake_case"))]
pub struct CnfForwardPattern {
    // Pattern to detect, expressed as hex
    // If empty, all traffic received on this port will be forwarded
    pub pattern_hex: String,
    // IP address to forward
    pub fwd_dst_ip: String,
    // Port to forward
    pub fwd_dst_port: u16
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename(deserialize = "snake_case"))]
pub struct CnfForwardRules {
    // Network interface to capture origin packet
    pub org_interface: String,
    // Destination port of original packet
    pub org_dst_port: u16,
    // Network interface to forward
    pub fwd_interface: String,
    // List of patterns to detect
    pub org_patterns: Vec<CnfForwardPattern>
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename(deserialize = "snake_case"))]
pub struct CnfNetInterface {
    intf_name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename(deserialize = "snake_case"))]
pub struct CnfGenSettings {
    pub fwd_entry_ttl_sec: u16,
}

impl Default for CnfGenSettings {
    fn default() -> Self {
        Self {
            fwd_entry_ttl_sec : CNF_GEN_SETTING_TTL_DEFAULT
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename(deserialize = "snake_case"))]
pub struct CnfSections {
    settings: Option<CnfGenSettings>,
    forward_rules: Option<CnfForwardRulesList>,
}

#[allow(dead_code)]
pub fn config_parse_net_intf_section(
    sections: &CnfSectionsDict,
    section_name: &str,
) -> anyhow::Result<CnfNetInterfacesList> {
    return match sections.get(section_name) {
        Some(v) => {
            let sections: CnfNetInterfacesList = match serde_json::from_value(v.to_owned()) {
                Ok(v) => v,
                Err(err) => return Err(anyhow!("Error parsing section: {}", err)),
            };
            Ok(sections)
        }
        None => Err(anyhow!("No {section_name} found in provided sections list")),
    };
}

pub fn config_parse_fwd_rules_section(
    sections: &CnfSectionsDict,
    section_name: &str,
) -> anyhow::Result<CnfForwardRulesList> {
    return match sections.get(section_name) {
        Some(v) => {
            let sections: CnfForwardRulesList = match serde_json::from_value(v.to_owned()) {
                Ok(v) => v,
                Err(err) => return Err(anyhow!("Error parsing section: {}", err)),
            };
            Ok(sections)
        }
        None => Err(anyhow!("No {section_name} found in provided sections list")),
    };
}

pub fn config_parse_cnf_settings_section(
    sections: &CnfSectionsDict,
    section_name: &str,
) -> anyhow::Result<CnfGenSettings> {
    return match sections.get(section_name) {
        Some(v) => {
            let section: CnfGenSettings = match serde_json::from_value(v.to_owned()) {
                Ok(v) => v,
                Err(err) => return Err(anyhow!("Error parsing section: {}", err)),
            };
            Ok(section)
        }
        None => Err(anyhow!("No {section_name} found in provided sections list")),
    };
}

pub fn conf_json_load(cnf_file_path: &str) -> anyhow::Result<CnfSectionsDict> {
    // TODO: capture error here and return error result, instead of panic
    let cnf_file = File::open(cnf_file_path).expect("Failed to load json file");
    // read into Stripped Comments JSON object
    let json_noc = BufReader::new(cnf_file);
    let sections: CnfSectionsDict = match serde_json::from_reader(json_noc) {
        Ok(prm_sections) => prm_sections,
        Err(err) => return Err(anyhow!("Error parsing configuration file: {}", err)),
    };
    Ok(sections)
}

// Load configuration from JSON file
pub fn config_load(cnf_file_path: &str) -> anyhow::Result<CnfSectionsDict> {
    file_check_exists(&cnf_file_path)?;
    let sections = conf_json_load(cnf_file_path)?;
    Ok(sections)
}
