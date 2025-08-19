use std::env;
use std::fs;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path;

use crate::cipher::DecryptionContext;
use crate::cipher::EncryptionContext;

const MIN_PASSWORD_LENGTH: usize = 16;

mod cipher;
mod key;

fn handle_encryption(args: &[String]) {
    let path = path::Path::new(args[3].trim());

    if !is_encryptable_file(path) {
        println!("Can only encrypt files with an extension.");
        return;
    }

    if is_zug_file(path) {
        println!("Cannot encrypt an encrypted file.");
        return;
    }

    let file_contents =
        fs::read(path).unwrap_or_else(|_| panic!("Could not read file at {path:?}"));

    let hint = if args.len() > 4 {
        match args[4].trim() {
            "" => None,
            hint => Some(hint.to_owned()),
        }
    } else {
        None
    };

    match EncryptionContext::new(file_contents, hint) {
        None => {
            println!("Hint must be less than 255 characters.")
        }
        Some(context) => {
            let password = args[2].trim();
            if password.len() < MIN_PASSWORD_LENGTH {
                println!("Password length is short. Please consider using a longer password.")
            }

            let key = key::Key::from_str(password);
            let cipher_text = cipher::encrypt(&key, context);

            let encrypted_file_path = format!("{}.zug", path.to_str().unwrap());
            let encrypted_file_path = path::Path::new(&encrypted_file_path);
            fs::write(encrypted_file_path, cipher_text).expect("Failed to create encrypted file.");
        }
    }
}

fn handle_stream_encryption(args: &[String]) {
    let path = path::Path::new(args[3].trim());

    if !is_encryptable_file(path) {
        println!("Can only encrypt files with an extension.");
        return;
    }

    if is_zug_file(path) {
        println!("Cannot encrypt an encrypted file.");
        return;
    }

    let hint = if args.len() > 4 {
        match args[4].trim() {
            "" => None,
            hint => Some(hint.to_owned()),
        }
    } else {
        None
    };

    let password = args[2].trim();
    let key = key::Key::from_str(password);

    let input_file = std::fs::File::open(path).expect("Could not read file at {path:?}");

    let encrypted_file_path = format!("{}.zug", path.to_str().unwrap());
    let encrypted_file_path = path::Path::new(&encrypted_file_path);

    let output_file =
        std::fs::File::create_new(encrypted_file_path).expect("Could not create output file.");

    let mut reader = BufReader::with_capacity(1024 * 64, input_file);
    let mut writer = BufWriter::with_capacity(1024 * 64, output_file);

    cipher::encrypt_from_stream(&key, hint, &mut reader, &mut writer);

    writer.flush().expect("Could not flush writer.");
}

fn handle_decryption(args: &[String]) {
    let path = path::Path::new(args[3].trim());

    if !is_zug_file(path) {
        println!("Not a file encrypted using zug");
        return;
    }

    let file_contents =
        fs::read(path).unwrap_or_else(|_| panic!("Could not read file at {path:?}"));

    match DecryptionContext::from_file(file_contents) {
        Err(err) => panic!("{err:?}"),
        Ok(context) => {
            let password = args[2].trim();
            let key = key::Key::from_str(password);

            let maybe_plain_bytes = cipher::decrypt(&key, context);

            match maybe_plain_bytes {
                None => println!("Wrong password."),
                Some(plain_bytes) => {
                    let decrypted_file_path = path.file_stem().unwrap().to_str().unwrap();
                    let decrypted_file_path = path::Path::new(&decrypted_file_path);
                    fs::write(decrypted_file_path, plain_bytes)
                        .expect("Failed to create encrypted file.");
                }
            }
        }
    }
}

fn handle_stream_decryption(args: &[String]) {
    let path = path::Path::new(args[3].trim());

    if !is_zug_file(path) {
        println!("Not a file encrypted using zug");
        return;
    }

    let password = args[2].trim();
    let key = key::Key::from_str(password);

    let input_file = std::fs::File::open(path).expect("Could not read file at {path:?}");
    let decrypted_file_path = path.file_stem().unwrap().to_str().unwrap();
    let output_file =
        std::fs::File::create_new(decrypted_file_path).expect("Could not create output file.");

    let mut reader = BufReader::with_capacity(1024 * 64 + 4 + 12, input_file);
    let mut writer = BufWriter::with_capacity(1024 * 64 + 4 + 12, output_file);

    cipher::decrypt_from_stream(&key, &mut reader, &mut writer);

    writer.flush().expect("Could not flush writer.");
}

fn handle_hint(args: &[String]) {
    let path = path::Path::new(args[2].trim());

    if !is_zug_file(path) {
        println!("Not a file encrypted using zug");
        return;
    }

    match cipher::hint(path) {
        None => println!("File does not have a hint."),
        Some(hint) => println!("{hint}"),
    }
}

fn is_encryptable_file(path: &path::Path) -> bool {
    path.extension().is_some()
}

fn is_zug_file(path: &path::Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("zug")
}

fn print_usage() {
    println!("zug v0.2.0");
    println!("Usage:");
    println!("-e    <password> <path> [hint] Encrypts the file using the provided password.");
    println!(
        "-sd   <password> <path> [hint] Stream encrypts the file using the provided password."
    );
    println!("-d    <password> <path>        Decrypts the file file using the provided password.");
    println!(
        "-sd   <password> <path>        Stream decrypts the file file using the provided password."
    );
    println!("-h    <path>                   Displays the hint of an encrypted file.");
}

pub fn execute() {
    let args = env::args();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let args: Vec<String> = args.collect();
    let mode = args[1].trim();

    match mode {
        "-e" => handle_encryption(&args),
        "-d" => handle_decryption(&args),
        "-h" => handle_hint(&args),
        "-se" => handle_stream_encryption(&args),
        "-sd" => handle_stream_decryption(&args),
        _ => print_usage(),
    }
}
