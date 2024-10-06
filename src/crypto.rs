use anyhow::{anyhow, Result, Context};
use aes_gcm::{aead::Aead, KeyInit, Aes256Gcm};
use rand::{RngCore, rngs::OsRng};
use std::net::TcpStream;
use std::io::{Read, Write};


pub const AEAD_LENGTH : usize = 16;
pub const NONCE_LENGTH : usize = 12;

pub const KEY_LENGTH : usize = 32;
pub const ENCRYPTED_CHALLENGE_LENGTH : usize = KEY_LENGTH + NONCE_LENGTH + AEAD_LENGTH; 

pub type Key = [u8; KEY_LENGTH];
type Nonce = [u8; NONCE_LENGTH];

pub fn random_key() -> Key {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}


pub struct Cipher {
    cipher: Aes256Gcm,
    nonce: Nonce
}

impl Cipher {
    fn increase_nonce(&mut self) {
        for i in 0..NONCE_LENGTH {
            if self.nonce[i] < u8::MAX {
                self.nonce[i] += 1;
                break;
            } else {
                self.nonce[i] = 0;
            }
        }
    }

    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        self.increase_nonce();
        self.cipher.encrypt(&self.nonce.into(), buf).unwrap()
    }

    pub fn decrypt(&mut self, buf: &[u8]) -> Result<Vec<u8>> {
        self.increase_nonce();
        match self.cipher.decrypt(&self.nonce.into(), buf) {
            Ok(buf) => Ok(buf),
            Err(e) => Err(anyhow!("Undecryptable packet: {e:?}, might be some kind of attack"))
        }
    }
}
    

pub const MAGIC2_LENGTH : usize = 32;
pub const MAGIC2: &[u8; MAGIC2_LENGTH] = &[
    198, 158, 252, 226, 190, 135, 45, 91, 254, 58, 121, 222, 55, 121, 188,
    144, 42, 174, 18, 202, 227, 208, 46, 22, 31, 81, 62, 77, 45, 14, 42, 98
];

// Not critical; the attacker shouldn't be able
// To control MAGIC2, but it will make MAGIC1 way stronger 
// (it's a bit overkill, since it's only to filter scanning bots)
pub fn constant_eq(x: &[u8], y: &[u8]) -> bool {
    let x_len = x.len();
    let y_len = y.len();
    if x_len != y_len {
        return false;
    }
    let mut test_bit = 0u8;
    for i in 0..x_len {
        test_bit |= x[i] ^ y[i];
    }
    test_bit == 0u8
}

pub fn challenge(key: &Key, stream: &mut TcpStream) -> Result<Cipher> {
    let mut init_nonce = [0; NONCE_LENGTH];
    OsRng.fill_bytes(&mut init_nonce);

    let mut control_key_and_nonce = [0; KEY_LENGTH+NONCE_LENGTH];
    OsRng.fill_bytes(&mut control_key_and_nonce);
    let init_cipher = Aes256Gcm::new(key.try_into().context("Key format is invalid")?);
    stream.write_all(&init_nonce)?;
    
    let encrypted_key_and_nonce = init_cipher.encrypt(&init_nonce.into(), control_key_and_nonce.as_ref()).unwrap();
    stream.write_all(&encrypted_key_and_nonce)?;
    stream.flush()?;
    println!("Sent challenge, waiting for response...");

    let control_key : Key = control_key_and_nonce[..KEY_LENGTH].try_into().unwrap();
    let control_nonce : Nonce = control_key_and_nonce[KEY_LENGTH..].try_into().unwrap();
    let control_cipher = Aes256Gcm::new(&control_key.into());
    
    
    let mut magic2_test = [0u8; MAGIC2_LENGTH+AEAD_LENGTH];
    stream.read_exact(&mut magic2_test)?;
    
    if let Ok(magic2_test) = control_cipher.decrypt(&control_nonce.into(), magic2_test.as_ref()) {
        if constant_eq(&magic2_test, MAGIC2) {
            return Ok(Cipher { cipher: control_cipher, nonce: control_nonce });
        }
    }
    Err(anyhow!("Challenge failed, decryption didn't complete properly"))
}

pub fn answer_challenge(key: &Key, stream: &mut TcpStream) -> Result<Cipher> {
    let init_cipher = Aes256Gcm::new(key.try_into().context("Key format is invalid")?);
    
    let mut init_nonce = [0u8; NONCE_LENGTH];
    stream.read_exact(&mut init_nonce)?;
    let mut encrypted_key_and_nonce = [0u8; ENCRYPTED_CHALLENGE_LENGTH];
    stream.read_exact(&mut encrypted_key_and_nonce)?;

    
    println!("Received challenge; solving...");

    match init_cipher.decrypt(&init_nonce.into(), encrypted_key_and_nonce.as_ref()) {
        Ok(control_key_and_nonce) => {
            let control_key : Key = control_key_and_nonce[..KEY_LENGTH].try_into().unwrap();
            let control_nonce : Nonce = control_key_and_nonce[KEY_LENGTH..].try_into().unwrap();
            let control_cipher = Aes256Gcm::new(&control_key.into());
            let encrypted_magic2 = &control_cipher.encrypt(&control_nonce.into(), MAGIC2.as_ref()).unwrap();
            stream.write_all(encrypted_magic2)?;
            stream.flush()?;
            Ok(Cipher { cipher: control_cipher, nonce: control_nonce })
        },
        Err(err) => {
            Err(anyhow!("Could not decrypt the server challenge : {err:?}"))
        }
    }
}
