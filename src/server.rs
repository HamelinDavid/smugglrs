use crate::config::{CommonConfig, Port, ServerConfig};
use crate::common::{spawn_pipes, MAGIC1};
use crate::crypto::{self, AEAD_LENGTH};
use anyhow::{anyhow, Result, Context};
use std::net::{SocketAddr, TcpStream};
use std::io::{Read, Write};
use std::time::Duration;
use std::thread;

const RETRY_DELAY : u64 = 60;

fn server(ccfg: &CommonConfig, scfg: &ServerConfig) -> Result<()> {
    let mut control = TcpStream::connect(&scfg.gateway_address).context("Failed to connect to gateway")?;
    control.write(MAGIC1)?;
    control.flush()?;
    let mut cipher = crypto::answer_challenge(&ccfg.key, &mut control).context("Failed to solve server's challenge")?;
    control.set_read_timeout(None)?; //We will be waiting for new connections, disable read timeout
    println!("Challenge solved, connection established. Sending ports to bind...");
    {
        let mut ports = Vec::new();
        for (port, _) in &scfg.redirects {
            ports.extend_from_slice(&port.to_bytes());
        }
        let length : u8 = (scfg.redirects.len()*3+AEAD_LENGTH).try_into().context("Too many forwarded port, should be less than 78")?; 
        let encrypted_length = cipher.encrypt(&[length]);
        control.write_all(&encrypted_length)?;
        let encrypted_ports = cipher.encrypt(&ports);
        control.write_all(&encrypted_ports)?;
        control.flush()?;
    }
    
    loop {
        let mut port_buf = [0u8; 2 + AEAD_LENGTH];
        
        control.read_exact(&mut port_buf)?;
        let port = cipher.decrypt(&port_buf)?;
        let port = u16::from_be_bytes(port.try_into().unwrap());
        let gateway_socket = TcpStream::connect(&scfg.gateway_address).context("Failed to establish a new connection to the gateway")?;
        let local_port = match scfg.redirects.get(&Port::new_tcp(port)) {
            Some(port) => *port,
            None => {
                return Err(anyhow!("Server sent an invalid port"));
            }
        };
        println!("Piping new stream; remote port {port}, local port {local_port}");
        let local_socket = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], local_port))).context("Failed to connect to the local server")?;
        spawn_pipes(gateway_socket, local_socket)?;
    }    
}

pub fn main(ccfg: CommonConfig, scfg: ServerConfig) -> Result<()> {
    let retry = Duration::from_secs(RETRY_DELAY);

    loop {
        if let Err(err) = server(&ccfg, &scfg) {
            println!("Server failed to start.\nReason:\n{err:?}\nWaiting {RETRY_DELAY}s before retrying...");
        }
        thread::sleep(retry);
    }
}
