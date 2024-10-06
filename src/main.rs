/*
Copyright (C) 2024 David Hamelin
This program is free software: you can redistribute it and/or modify it under the terms of the 
GNU General Public License as published by the Free Software Foundation, version 3.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details. 
You should have received a copy of the GNU General Public License along with this program. 
If not, see <https://www.gnu.org/licenses/>. 
*/

mod config;
mod server;
mod gateway;
mod common;
mod crypto;

use config::{CommonConfig, SpecificConfig};
use anyhow::Result;

fn main() -> Result<()> {
    let (config,specific) = CommonConfig::new()?; // Read and parse config
    match specific {
        SpecificConfig::Server(scfg) => server::main(config,scfg),
        SpecificConfig::Gateway(gcfg) => gateway::main(config,gcfg)
    }
}
