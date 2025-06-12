// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Handle application command line parameters
//! 
//! 
//! 
use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(about = "Virturo - Virtual Router", long_about = None)]
pub struct CliParams {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.json")]
    pub config: String,

    /// List available network interfaces
    #[arg(short, long)]
    pub list: bool,
}
