use clap::{Parser, Subcommand};
use hex;
use openssl::aes::{aes_ige, AesKey, KeyError};
use openssl::pkey::PKey;
use openssl::rand;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::Mode;
use protobuf::Message;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

include!("proto/mod.rs");

// if you want updata metedata
//protoc --rust_out src/proto/ src/proto/foo.proto

/// Heart shaped box CLI
#[derive(Debug, Parser)] // requires `derive` feature
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Put file in a secure box
    #[command(arg_required_else_help = true)]
    Put {
        /// Input file (what you want enrcypt)
        #[arg(required = true)]
        in_file: String,
        /// Output file (encrypted file name)
        #[arg(required = true)]
        out_file: String,
        /// Public key in PEM format
        #[arg(required = true)]
        pem_file: String,
    },
    /// Get file from a secure box
    #[command(arg_required_else_help = true)]
    Get {
        /// Input file (encrypted file name)
        #[arg(required = true)]
        in_file: String,
        /// Output directory
        #[arg(required = true)]
        out_dir: String,
        /// Private key in PEM format
        #[arg(required = true)]
        pem_file: String,
    },
    /// Get pair of public and private keys in PEM forman
    #[command()]
    Generate {
        /// Output directory
        #[arg(required = true)]
        out_dir: String,
    },
}

const META_BUFFER_LEN: usize = 256;
const BUFFER_LEN: usize = 512;

fn make_put(key_fname: String, fname: String, ofname: String) -> Result<(), KeyError> {
    println!("Encrypting...");

    // Make random key
    let mut random_aes_key = [0u8; 16];
    rand::rand_bytes(&mut random_aes_key).unwrap();
    // println!("Generated key {:?}", random_aes_key);

    let ser_file_name = fname.clone();
    let mut file = File::open(fname).unwrap();
    let mut ofile = File::create(ofname).unwrap();
    let metadata = file.metadata().unwrap();
    // println!("File len is {}", metadata.len().to_string());

    // Encode example request
    let mut out_msg = foo::MetaData::new();
    out_msg.fname = std::path::Path::new(&ser_file_name)
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap();
    out_msg.aes_key = hex::encode(random_aes_key);
    out_msg.file_len = metadata.len();

    let mut serialized = out_msg.write_to_bytes().unwrap();
    let real_len = (serialized.len() as u32).to_le_bytes().to_vec();
    let mut data_for_encr = real_len;

    data_for_encr.append(&mut serialized);

    // RSA encrypt
    let pub_key_pem = std::fs::read(key_fname).unwrap();
    let pub_key = Rsa::public_key_from_pem(&pub_key_pem).unwrap();
    let mut encrypted_buf = vec![0; pub_key.size() as usize];
    let encrypted_len = pub_key
        .public_encrypt(&data_for_encr, &mut encrypted_buf, Padding::PKCS1)
        .unwrap();
    if encrypted_len != META_BUFFER_LEN {
        panic!("Something wrong")
    }

    // write metadate
    ofile.write(&encrypted_buf).unwrap();
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = file.read(&mut buffer).unwrap();
        let out = ecrypt(&random_aes_key, &buffer).unwrap();
        if read_count != 0 {
            ofile.write(&out).unwrap();
        }
        if read_count != BUFFER_LEN {
            // println!("read_count != BUFFER_LEN usize={}", read_count);
            break;
        }
    }
    Ok(())
}

fn make_get(key_fname: String, fname: String, out_dir: String) -> Result<(), KeyError> {
    println!("Decrypting...");
    let mut buffer = [0u8; BUFFER_LEN];

    let mut file = File::open(fname).unwrap();
    let mut metabuf = [0u8; META_BUFFER_LEN];
    let meta_read_bytes = file.read(&mut metabuf).unwrap();
    if meta_read_bytes != META_BUFFER_LEN {
        panic!("File broken!!");
    }

    // RSA decrypt
    let buf_private = std::fs::read(key_fname).unwrap();
    let mut decrypted_data = vec![0; META_BUFFER_LEN];
    let private_key = Rsa::private_key_from_pem(&buf_private).unwrap();
    let _decrypted_len = private_key
        .private_decrypt(&metabuf, &mut decrypted_data, Padding::PKCS1)
        .unwrap();

    // deserialization
    let pb_len2 = decrypted_data[0..4].try_into().unwrap();
    let pb_len = i32::from_le_bytes(pb_len2) as usize;
    // println!("pb_len {}", pb_len);
    let buffer2 = decrypted_data[4..pb_len + 4].to_vec();

    let in_msg = foo::MetaData::parse_from_bytes(&buffer2).unwrap();
    // println!("{:?}", in_msg);
    let key = hex::decode(in_msg.aes_key).unwrap();
    // println!("{:?}", key);

    let output_file_path = Path::new(&out_dir);
    let ofile = output_file_path.join(in_msg.fname);
    let mut ofile = File::create(ofile).unwrap();
    let mut file_len = in_msg.file_len as usize;

    loop {
        let read_count = file.read(&mut buffer).unwrap();
        let out = decrypt(&key, &buffer).unwrap();
        if file_len >= read_count {
            file_len -= read_count;
        } else {
            // println!("file_len = {}", file_len);
            let buf2 = out[0..file_len].to_vec();
            ofile.write(&buf2).unwrap();
            break;
        }
        ofile.write(&out).unwrap();
        if read_count != BUFFER_LEN {
            // println!("read_count != BUFFER_LEN usize={}", read_count);
            break;
        }
    }
    Ok(())
}

fn make_generation(out_dir: String) -> Result<(), KeyError> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey_p = PKey::from_rsa(rsa).unwrap();

    let priv_key_pem: Vec<u8> = pkey_p.private_key_to_pem_pkcs8().unwrap();
    let pub_key_pem: Vec<u8> = pkey_p.public_key_to_pem().unwrap();

    let output_file_path = Path::new(&out_dir);
    let private_path = output_file_path.join("private.pem");
    let mut ofile = File::create(private_path).unwrap();
    ofile.write(&priv_key_pem).unwrap();

    let public_path = output_file_path.join("public.pem");
    let mut public_file = File::create(public_path).unwrap();
    public_file.write(&pub_key_pem).unwrap();
    Ok(())
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Put {
            in_file,
            out_file,
            pem_file,
        } => {
            make_put(pem_file, in_file, out_file).unwrap();
        }
        Commands::Get {
            in_file,
            out_dir,
            pem_file,
        } => {
            make_get(pem_file, in_file, out_dir).unwrap();
        }
        Commands::Generate { out_dir } => {
            make_generation(out_dir).unwrap();
        }
    }
}

#[test]
fn test_aes() {
    let mut random_aes_key = [0; 16];
    rand::rand_bytes(&mut random_aes_key).unwrap();
    let test_buff = [0; 512];
    let out = ecrypt(&random_aes_key, &test_buff).unwrap();
    let out2 = decrypt(&random_aes_key, &out).unwrap();
    assert_eq!(&test_buff[..], &out2[..]);
}

#[test]
fn test_rsa() {
    // Keygen
    let rsa = Rsa::generate(2048).unwrap();
    let pkey_p = PKey::from_rsa(rsa).unwrap();

    let priv_key_pem: Vec<u8> = pkey_p.private_key_to_pem_pkcs8().unwrap();
    let pub_key_pem: Vec<u8> = pkey_p.public_key_to_pem().unwrap();

    // encrypt
    let data = b"Hello password!!!!!";
    let pub_key = Rsa::public_key_from_pem(&pub_key_pem).unwrap();

    let mut buf = vec![0; pub_key.size() as usize];
    let _encrypted_len = pub_key
        .public_encrypt(data, &mut buf, Padding::PKCS1)
        .unwrap();

    // decrypt
    let private_key = Rsa::private_key_from_pem(&priv_key_pem).unwrap();
    let mut decrypted_buf = vec![0; pub_key.size() as usize];

    let _decrypted_len = private_key
        .private_decrypt(&buf, &mut decrypted_buf, Padding::PKCS1)
        .unwrap();

    let check_buf = decrypted_buf[0..data.len()].to_vec();

    assert_eq!(data[..], check_buf);
}

fn ecrypt(key_data: &[u8], data: &[u8]) -> Result<Vec<u8>, KeyError> {
    let mut iv_as_u8 = [0; 32];

    let key = AesKey::new_encrypt(&key_data)?;
    let mut output = vec![0u8; data.len()];

    aes_ige(&data, &mut output, &key, &mut iv_as_u8, Mode::Encrypt);
    Ok(output)
}

fn decrypt(key_data: &[u8], data: &[u8]) -> Result<Vec<u8>, KeyError> {
    let mut iv_as_u8 = [0; 32];

    let key = AesKey::new_decrypt(&key_data)?;
    let mut output = vec![0u8; data.len()];

    aes_ige(&data, &mut output, &key, &mut iv_as_u8, Mode::Decrypt);
    Ok(output)
}
