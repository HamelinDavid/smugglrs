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

use crate::config::{CommonConfig, Port, ServerConfig};
use crate::common::{spawn_pipes, MAGIC1, TCP_CHALLENGE_LENGTH};
use crate::crypto::{self, AEAD_LENGTH};
use anyhow::{anyhow, Result, Context};
use std::net::{SocketAddr, TcpStream};
use std::io::{Read, Write};
use std::time::Duration;
use std::thread;

const RETRY_DELAY : u64 = 60;
const RESPONSE_BUFFER_SIZE : usize = 1024;
const RESPONSE_MAX_SIZE : usize = 1048576;

/* Establish a new TCP connection, taking into account http_proxy if required */
fn connect(scfg: &ServerConfig) -> Result<TcpStream> {
    match &scfg.proxy {
        None => {
            TcpStream::connect(&scfg.gateway_address).context("Failed to connect to gateway")
        }
        Some(proxy) => {
            println!("Connecting through http proxy");
            let mut stream = TcpStream::connect(&proxy).context("Failed to connect to http proxy")?;
            stream.write_all(format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", &scfg.gateway_address, &scfg.gateway_address).as_bytes())
                .context("Failed to write HTTP connect to proxy")?;
            stream.flush().context("Failed to flush HTTP connect to proxy")?;
            
            let mut response = Vec::new();
            let mut buf = [0u8; RESPONSE_BUFFER_SIZE];
            loop { // We first need to read an HTTP response, which ends with an empty line
                let size = stream.read(&mut buf).context("Failed to read HTTP CONNECT respone")?;
                if size == 0 {
                    let response = String::from_utf8(response).context("Malformed UTF8 HTTP CONNECT response")?;
                    println!("Stream ended early with response:\n{response}\n");
                    return Err(anyhow!("Unexpected end of stream"));
                } else if size+response.len() > RESPONSE_MAX_SIZE {
                    let response = String::from_utf8(response).context("Malformed UTF8 partial HTTP CONNECT response")?;
                    println!("HTTP connect partial response:\n{response}\n");
                    return Err(anyhow!("Response too big"));
                }
                response.extend_from_slice(&buf[0..size]);
                if response.len() >= 4 && (&response[response.len()-4..response.len()] == b"\r\n\r\n" || &response[response.len()-2..response.len()] == b"\n\n")  {
                    break;        
                }
            }
            let response = String::from_utf8(response).context("Received bad HTTP response")?;
            print!("http proxy response:\n{response}");
            Ok(stream)
        }
    }
}

fn server(ccfg: &CommonConfig, scfg: &ServerConfig) -> Result<()> {
    let mut control = connect(&scfg).context("Failed to connect to gateway")?;
    control.write(MAGIC1).context("Failed to write MAGIC1")?;
    control.flush().context("Failed to flush MAGIC1")?;
    let mut cipher = crypto::answer_challenge(&ccfg.key, &mut control).context("Failed to solve server's challenge")?;
    control.set_read_timeout(None).context("Failed to disable timeout on control socket")?; //We will be waiting for new connections, disable read timeout
    println!("Challenge solved, connection established. Sending ports to bind...");
    {
        let mut ports = Vec::new();
        for (port, _) in &scfg.redirects {
            ports.extend_from_slice(&port.to_bytes());
        }
        let length : u8 = (scfg.redirects.len()*3+AEAD_LENGTH).try_into().context("Too many forwarded port, should be less than 78")?; 
        let encrypted_length = cipher.encrypt(&[length]);
        control.write_all(&encrypted_length).context("Failed to write encrypted length")?;
        let encrypted_ports = cipher.encrypt(&ports);
        control.write_all(&encrypted_ports).context("Failed to write encrypted ports")?;
        control.flush().context("Failed to flush encrypted length+ports")?;
    }
    println!("Done. Waiting for new connections...");
    loop {
        let mut msg = [0u8; 2 + TCP_CHALLENGE_LENGTH + AEAD_LENGTH];
        control.read_exact(&mut msg).context("Failed to read control message")?;
        let msg = cipher.decrypt(&msg).context("Failed to decrypt control message")?;
        let port = u16::from_be_bytes(msg[0..2].try_into().unwrap());
        let mut gateway_socket = connect(&scfg).context("Failed to establish a new connection to the gateway")?;
        gateway_socket.write_all(&cipher.encrypt(&msg[2..])).context("Failed to write new connection challenge")?;
        gateway_socket.flush().context("Failed to flush new connection challenge")?;
        let local_port = match scfg.redirects.get(&Port::new_tcp(port)) {
            Some(port) => *port,
            None => {
                return Err(anyhow!("Server sent an invalid port"));
            }
        };
        let local_socket = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], local_port))).context("Failed to connect to the local server")?;
        spawn_pipes(gateway_socket, local_socket).context("Failed to spawn pipes")?;
    }    
}

pub fn main(ccfg: CommonConfig, scfg: ServerConfig) -> Result<()> {
    let retry = Duration::from_secs(RETRY_DELAY);
    println!("Server started.");
    loop {
        if let Err(err) = server(&ccfg, &scfg) {
            println!("Server error.\nReason:\n{err:?}\nWaiting {RETRY_DELAY}s before retrying...");
        }
        thread::sleep(retry);
    }
}
