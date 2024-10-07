use std::net::TcpStream;
use std::thread;
use std::io::{Read, Write};
use anyhow::Result;

pub const MAGIC1_LENGTH : usize = 17;
pub const MAGIC1: &[u8; MAGIC1_LENGTH] = &[231, 3, 23, 145, 7, 2, 46, 41, 78, 222, 175, 4, 8, 15, 16, 23, 42];
 
const PIPE_BUFFER : usize = 65536;
fn pipe_streams(mut src: TcpStream, mut dst: TcpStream) -> Result<()> {
    let mut buf = [0u8; PIPE_BUFFER];
    loop {
        let len = src.read(&mut buf)?;
        if len == 0 {
            return Ok(()); // Connection ended successfully
        }
        dst.write_all(&buf[0..len])?;
    }
}
pub fn spawn_pipes(a: TcpStream, b: TcpStream) -> Result<()> {
    a.set_nonblocking(false)?;
    b.set_nonblocking(false)?;
    {
        let src = a.try_clone()?;
        let dst = b.try_clone()?;
        thread::spawn(move || pipe_streams(src, dst));
    }
    {
        let src = b;
        let dst = a;
        thread::spawn(move || pipe_streams(src, dst));
    }
    Ok(())
}
