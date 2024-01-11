pub mod key;

use std::{time::Instant, io::{Read, Write}};
use key::hash;
use eyre::Ok;

use crate::key::nonce;
const CHUNK_SIZE:usize = 1000;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input:String,
        output:String,
        passwd:String,
    },
    Decrypt { 
        input:String,
        output:String,
        passwd:String,
    }
}

fn main() -> eyre::Result<()>{
    let cli = Cli::parse();
    let before = Instant::now();
    match &cli.command {
        Commands::Encrypt { input, output, passwd } => {
            encrypt(&input, &passwd, output)?;
        },
        Commands::Decrypt { input, output, passwd} => {
            decrypt(&input, &passwd, output)?;
        },
    }
    println!("complete dur:{}",before.elapsed().as_secs());
    Ok(())
}

fn encrypt(path:&str, passwd:&str, output:&str) -> eyre::Result<()> {
    const BUFFER_SIZE:usize = CHUNK_SIZE + 0;
    use aes_gcm_siv::{
        aead::{Aead, KeyInit},
        Aes256GcmSiv, Nonce
    };

    let cipher = Aes256GcmSiv::new_from_slice(&hash(passwd))?;
    let nonce = nonce(passwd);
    let nonce = Nonce::from_slice(&nonce);
    let mut input = std::fs::File::open(path)?;
    let mut output = std::fs::File::create(output)?;
    let mut buf = [0u8;BUFFER_SIZE];
    loop {
        let readed = input.read(&mut buf)?;
        if readed == BUFFER_SIZE {
            let cipherbytes = cipher.encrypt(nonce, buf.as_slice()).unwrap();
            output.write(&cipherbytes)?;
        } else {
            let cipherbytes = cipher.encrypt(nonce, buf.as_slice()).unwrap();
            output.write(&cipherbytes)?;
            break;
        }
    }
    return Ok(());
}
fn decrypt(path:&str, passwd:&str, output:&str) -> eyre::Result<()> {
    const BUFFER_SIZE:usize = CHUNK_SIZE +16;
    use aes_gcm_siv::{
        aead::{Aead, KeyInit},
        Aes256GcmSiv, Nonce
    };

    let cipher = Aes256GcmSiv::new_from_slice(&hash(passwd))?;
    let nonce = nonce(passwd);
    let nonce = Nonce::from_slice(&nonce);

    let mut input = std::fs::File::open(path)?;
    let mut output = std::fs::File::create(output)?;
    let mut buf = [0u8;BUFFER_SIZE];
    loop {
        let readed = input.read(&mut buf)?;
        if readed == BUFFER_SIZE {
            let plainbytes = cipher.decrypt(nonce, buf.as_slice()).unwrap();
            output.write(&plainbytes)?;
        } else {
            let plainbytes = cipher.decrypt(nonce, buf.as_slice()).unwrap();
            output.write(&plainbytes)?;
            break;
        }
    }

    return Ok(());
}