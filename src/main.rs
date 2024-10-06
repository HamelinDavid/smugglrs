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
