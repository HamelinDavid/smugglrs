use crate::config::{CommonConfig, Port, Protocol, GatewayConfig};
use crate::common::{spawn_pipes, MAGIC1, MAGIC1_LENGTH};
use crate::crypto::{self, AEAD_LENGTH};
use anyhow::{anyhow, Result, Context};
use std::net::{Shutdown, UdpSocket, SocketAddr, TcpListener, TcpStream};
use std::io::{self, Read, Write};
use std::time::Duration;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::collections::HashMap;

const BUSY_LOOP_DELAY : u64 = 15;
const CONNECT_TIMEOUT : u64 = 2000;

enum EventType {
    ControlClosed,
    NewTCPConnection(u16, TcpStream),
}

/// Monitor the socket: if the connection is closed, we notify the main thread to transition 
/// back into "pairing" mode
fn socket_monitor(mut socket: TcpStream, tx: Sender<EventType>) -> Result<()> {
    socket.set_read_timeout(None)?;
    let mut buf = [0u8; 1];
    match socket.read_exact(&mut buf) {
        Err(err) => {
            eprintln!("Connection with server ended, reason :\n{err:?}\nNotifying main thread...");
        }
        Ok(_) => {
            eprintln!("Something weird is going on, the server should never send anything");
        }
    }
    tx.send(EventType::ControlClosed)?;
    Ok(())
}

fn tcp_listener(port: u16, tx: Sender<EventType>) -> Result<()> {
    println!("Binding port {port}");
    match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))) {
        Ok(listener) => loop {
            match listener.accept() {
                Err(err) => {
                    eprintln!("Client connection on TCP port {port} failed. Reason:\n{err:?}\n");
                    eprintln!("Ignoring...");
                }
                Ok((socket,_addr)) => {
                    tx.send(EventType::NewTCPConnection(port, socket))?;
                }
            }
        },
        Err(err) => {
            eprintln!("Failed to bind port {port}, reason:\n{err:?}\n");
            eprintln!("A service may be running on this port already.");
            eprintln!("The gateway will continue working without this port");
            Err(anyhow!("Failed to bind port {port}, reason:\n{err:?}\n"))
        }
    }
}

struct ThreadKiller {
    control_stream: TcpStream,
    //@TODO add udp socket
    ports: Vec<Port>
}

impl Drop for ThreadKiller {
    // Attempt a connection on every port, waking them up in the process
    // They should stop because the receiving part of the mpsc channel has been closed
    fn drop(&mut self) {
        if let Err(_) = self.control_stream.shutdown(Shutdown::Both) {
            eprintln!("Failed to shutdown tcp monitor thread");
        }
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap(); //@TODO, we should reuse the udp socket from the main thread
        for p in &self.ports {
            let addr = SocketAddr::from(([127, 0, 0, 1], p.port));
            match p.protocol {
                Protocol::TCP => {
                    if let Err(_) = TcpStream::connect(addr) {
                        eprintln!("Failed to connect to our own thread, it probably died on its own");
                    }
                }
                Protocol::UDP => {
                    if let Err(_) = udp.send_to(&[], addr) {
                        eprintln!("Failed to send a UDP message to our own thread, it probably died on its own");
                    }
                }
            }
        }
    }
}

fn gateway(ccfg: &CommonConfig, _gcfg: &GatewayConfig, listener: &TcpListener, mut socket: TcpStream, addr: SocketAddr) -> Result<()> {
    println!("Server candidate connected from {addr}");
    socket.set_read_timeout(Some(Duration::new(1,0)))?;
    let mut magic_test = [0 as u8; MAGIC1_LENGTH];
    socket.read_exact(&mut magic_test)?;

    if !crypto::constant_eq(&magic_test,MAGIC1) {
        return Err(anyhow!("{addr} did not send the correct magic; it's probably some kind of bot"));
    }
    
    let mut cipher = crypto::challenge(&ccfg.key, &mut socket).context("Candidate did not solve the challenge")?;

    socket.set_read_timeout(None)?; // Client completed the challenge, no need for timeouts
    
    println!("Receiving ports");
    let (ports, _mapping) = {
        let mut length = [0u8; 1+AEAD_LENGTH];
        socket.read_exact(&mut length)?;
        let length = cipher.decrypt(&length)?[0];

        let mut encrypted_ports = vec![0u8; length as usize];
        socket.read_exact(&mut encrypted_ports)?;
        let ports_raw = cipher.decrypt(&encrypted_ports)?;

        let ports_length = ports_raw.len()/3;
        let mut ports = Vec::with_capacity(ports_length);
        let mut mapping = HashMap::with_capacity(ports_length);
        for i in 0..ports_length {
            let port = Port::from_bytes(ports_raw[i*3..(i*3)+3].try_into().unwrap());
            ports.push(port);
            mapping.insert(port, i);
        }
        (ports,mapping)
    };
    
    let (tx, rx) = channel();
    
    for p in &ports {
        match p.protocol {
            Protocol::TCP => {
                let tx = tx.clone();
                let port = p.port;
                thread::spawn(move || tcp_listener(port, tx));
            },
            Protocol::UDP => {
                eprintln!("UDP is not implemented yet, ignoring bind {}", p.port);
            }
        }
    }

    {
        let socket = socket.try_clone()?;
        let tx = tx.clone();
        thread::spawn(move || socket_monitor(socket, tx));
    }

    // The only purpose of this object is to clean everything when it's dropped (for instance if we return an error)
    let _thread_killer = ThreadKiller {
        control_stream: socket.try_clone()?,
        ports: ports.clone()
    };

    listener.set_nonblocking(true)?; // Set the listener to non-blocking; this allows us to have timeouts later
    for msg in rx { 
        match msg {
            EventType::ControlClosed => {
                break;
            },
            EventType::NewTCPConnection(port, tcp) => {
                let encrypted_port = cipher.encrypt(&port.to_be_bytes());
                socket.write_all(&encrypted_port)?;
                socket.flush()?;
                let new_socket;
                let mut milis_elapsed = 0;
                let busy = Duration::from_millis(BUSY_LOOP_DELAY);
                loop {
                    match listener.accept() {
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // No connection yet, let's wait a bit
                            if milis_elapsed >= CONNECT_TIMEOUT {
                                return Err(anyhow!("Server took too long to connect"));
                            } else {
                                thread::sleep(busy);
                                milis_elapsed += BUSY_LOOP_DELAY;
                            }
                            continue;
                        } 
                        Err(e) => eprintln!("Client connection failed {e:?}, ignoring"),
                        Ok((candidate_socket,candidate_addr)) => {
                            if candidate_addr.ip() == addr.ip() {
                                new_socket = candidate_socket;
                                break;
                            } else {
                                println!("Connection from unexpected address {candidate_addr}, ignoring");
                            }
                        }
                    }
                }
                spawn_pipes(tcp, new_socket)?;
            }
        }
    }
    Err(anyhow!("Control socket closed"))
}

pub fn main(ccfg: CommonConfig, gcfg: GatewayConfig) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], gcfg.port))).context("Failed to bind gateway address. Is another process already running?")?;
    loop {
        listener.set_nonblocking(false)?; // Set to blocking (because the gateway function sets it to nonblocking which isn't what we want)
        match listener.accept() {
            Err(e) => eprintln!("Client connection failed {e:?}, ignoring"),
            Ok((socket,addr)) => if let Err(err) = gateway(&ccfg, &gcfg, &listener, socket, addr) {
                eprintln!("Gateway session finished. Details:\n{err:?}\ntransitioning into pairing mode...");
            }
        }
    }
}


