use std::env;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path;

const MIN_PASSWORD_LENGTH: usize = 16;

mod cipher;
mod key;

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
    if password.len() < MIN_PASSWORD_LENGTH {
        println!("Password length is short. Please consider using a longer password.")
    }

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
    println!("-e <password> <path> [hint] Encrypts the file using the provided password.");
    println!("-d <password> <path>        Decrypts the file file using the provided password.");
    println!("-h <path>                   Displays the hint of an encrypted file.");
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
        "-e" => handle_stream_encryption(&args),
        "-d" => handle_stream_decryption(&args),
        "-h" => handle_hint(&args),
        _ => print_usage(),
    }
}
