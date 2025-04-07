// 加密shellcode

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>; // AES-128 CBC mode

const KEY: &[u8; 16] = b"thisisakey123456"; // 16 bytes key
const IV: &[u8; 16] = b"thisisaniv123456"; // 16 bytes IV

fn encrypt_shellcode(data: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(KEY, IV)
        .expect("Invalid key/IV length");
    cipher.encrypt_vec(data)
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <shellcode> <en_shellcode>", args[0]);
        return Ok(());
    }
    let input_filename = &args[1];
    let output_filename = &args[2];

    if !Path::new(input_filename).exists() {
        println!("no {}", input_filename);
        return Ok(());
    }

    let mut file = File::open(input_filename)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let encrypted_data = encrypt_shellcode(&data);

    let mut out_file = File::create(output_filename)?;
    out_file.write_all(&encrypted_data)?;

    println!("Ok：{} -> {}", input_filename, output_filename);
    Ok(())
}