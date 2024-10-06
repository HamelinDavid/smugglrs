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

extern crate serde;

use crate::crypto::{Key, random_key};
use serde::{Serialize, Deserialize};
use toml::Value;
use anyhow::{anyhow, Result, Context};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub enum Protocol {
    UDP, TCP
}

#[derive(Serialize, Deserialize, Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct Port {
    pub port: u16,
    pub protocol: Protocol
}

impl Port {
    pub fn to_bytes(&self) -> [u8; 3] {
        let mut ret = [0u8; 3];
        let port_be_bytes = self.port.to_be_bytes();
        ret[0] = port_be_bytes[0];
        ret[1] = port_be_bytes[1];
        ret[2] = match self.protocol {
            Protocol::UDP => 0,
            Protocol::TCP => 1
        };
        ret
    }

    pub fn from_bytes(buf: &[u8; 3]) -> Port {
        Port {
            port: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            protocol: match buf[2] {
                0 => Protocol::UDP,
                1 => Protocol::TCP,
                _ => panic!("malformed port received")
            }
        }
    }

    pub fn new_tcp(port: u16) -> Port {
        Port {
            port,
            protocol: Protocol::TCP
        }
    }
}

pub struct ServerConfig {
    pub redirects: HashMap<Port, u16>,
    pub gateway_address: String,
    pub proxy: Option<String>,
}

pub struct GatewayConfig {
    pub port: u16
}

pub enum SpecificConfig {
    Gateway(GatewayConfig), 
    Server(ServerConfig)
}

pub struct CommonConfig {
    pub key : Key
}

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    pub mode: String,
    pub port: u16,
    pub gateway_address: Option<String>,
    pub http_proxy: Option<String>,
    pub redirects: Option<Vec<Vec<Value>>>,
}

impl CommonConfig {
    pub fn new() -> Result<(CommonConfig, SpecificConfig)> {
        let config = fs::read_to_string("config.toml").context("Failed to read config")?;
        let config: RawConfig = toml::from_str(&config).context("Failed to parse config")?;
        
        let specific_config = match config.mode.as_str() {
            "gateway" => SpecificConfig::Gateway(GatewayConfig {
                port: config.port
            }),
            "server" => {
                let raw_redirects = config.redirects.context("redirects should be defined when running as a server")?;
                let mut redirects = HashMap::with_capacity(raw_redirects.len());
                
                for portprot in raw_redirects {
                    if portprot.len() > 3 {
                        return Err(anyhow!("Each redirect should be an array of the form [<port>, <protocol>]"));
                    }

                    let server = match portprot[0] {
                        Value::Integer(x) => u16::try_from(x).context("Server port should be a 16-bits unsigned integer")?,
                        _ => {
                            return Err(anyhow!("Failed to parse port, we expected an integer"))
                        }
                    };

                    let (protindex, gateway) = if let Value::Integer(x) = portprot[1] {
                        (2, u16::try_from(x).context("Gateway port should be a 16-bits unsigned integer")?)
                    } else {
                        (1, server)
                    };

                    let protocol  = match &portprot[protindex] {
                        Value::String(x) => {
                            match x.as_str() {
                                "UDP" => Protocol::UDP,
                                "TCP" => Protocol::TCP,
                                x => return Err(anyhow!("{} is not a valid protocol", x))
                            }
                        },
                        _ => {
                            return Err(anyhow!("Protocol should be a string"));
                        }
                    };
                    
                    if redirects.insert(Port { port: server, protocol}, gateway).is_some() {
                        return Err(anyhow!("Duplicate port detected, {} is bound at least twice", gateway));
                    }
                }

                let gateway_address = format!("{}:{}", config.gateway_address.context("Server should indicate gateway address")?, config.port);
                

                SpecificConfig::Server(ServerConfig {
                    redirects,
                    gateway_address,
                    proxy: config.http_proxy
                })
            }
            x => {
                return Err(anyhow!("{} is not a valid server mode", x));
            }
        };

        let path = Path::new("aeskey.bin");

        let mut key = random_key();
        if !path.exists() {
            if let SpecificConfig::Gateway(_) = specific_config {
                fs::write(path, key)?;
            } else {
                return Err(anyhow!("No key file found, please copy the aeskey.bin file generated by the gateway to the server"));
            }
        } else {
            let mut file = File::open(path)?;
            file.read(&mut key)?;
        };
        
        Ok((CommonConfig { key }, specific_config))
    }
}

