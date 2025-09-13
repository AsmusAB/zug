use std::env;
use std::path;

const MIN_PASSWORD_LENGTH: usize = 16;

mod cipher;
mod key;

fn handle_encryption(args: &[String]) {
    let hint = match args[3].trim() {
        "-h" => {
            if args.len() < 4 {
                panic!("Expected a hint")
            }
            Some(args[4].to_owned())
        }
        _ => None,
    };

    let password = args[2].trim();
    if password.len() < MIN_PASSWORD_LENGTH {
        println!("Password length is short. Please consider using a longer password.")
    }

    let key = key::Key::from_str(password);

    let path_index_start = match hint {
        Some(_) => 5,
        None => 3,
    };

    let paths: Vec<&path::Path> = args[path_index_start..args.len()]
        .iter()
        .map(|x| path::Path::new(x))
        .collect();

    for path in paths {
        if !is_encryptable_file(path) {
            println!("Can only encrypt files with an extension.");
            return;
        }

        if is_zug_file(path) {
            println!("Cannot encrypt an encrypted file.");
            return;
        }

        let input_file = std::fs::File::open(path).expect("Could not read file at {path:?}");

        let encrypted_file_path = format!("{}.zug", path.to_str().unwrap());
        let encrypted_file_path = path::Path::new(&encrypted_file_path);

        let output_file =
            std::fs::File::create_new(encrypted_file_path).expect("Could not create output file.");

        let mut reader = cipher::EncryptionReader::from_reader(input_file);
        let mut writer = cipher::EncryptionWriter::from_writer(output_file);

        let encryption_result =
            cipher::encrypt_from_stream(&key, hint.clone(), &mut reader, &mut writer);
        writer.flush().expect("Could not flush writer");

        match encryption_result {
            Ok(_) => (),
            Err(err) => {
                std::fs::remove_file(encrypted_file_path).expect("Could not delete file.");
                println!("Error during encryption: {:?}", err)
            }
        }
    }
}

fn handle_decryption(args: &[String]) {
    let password = args[2].trim();
    let key = key::Key::from_str(password);

    let paths: Vec<&path::Path> = args[3..args.len()]
        .iter()
        .map(|x| path::Path::new(x))
        .collect();

    for path in paths {
        if !is_zug_file(path) {
            println!("Not a file encrypted using zug");
            return;
        }

        let input_file = std::fs::File::open(path).expect("Could not read file at {path:?}");
        let decrypted_file_path = path.file_stem().unwrap().to_str().unwrap();
        let output_file =
            std::fs::File::create_new(decrypted_file_path).expect("Could not create output file.");

        let mut reader = cipher::EncryptionReader::from_reader(input_file);
        let mut writer = cipher::EncryptionWriter::from_writer(output_file);

        let decryption_result = cipher::decrypt_from_stream(&key, &mut reader, &mut writer);
        writer.flush().expect("Could not flush writer");

        match decryption_result {
            Ok(_) => (),
            Err(err) => {
                std::fs::remove_file(decrypted_file_path).expect("Could not delete file.");
                println!("Error during decryption: {:?}", err)
            }
        }
    }
}

fn handle_hint(args: &[String]) {
    let path = path::Path::new(args[2].trim());

    if !is_zug_file(path) {
        println!("Not a file encrypted using zug");
        return;
    }

    let mut reader =
        std::io::BufReader::new(std::fs::File::open(path).expect("Could not open file."));
    match cipher::hint(&mut reader) {
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
    println!("-e <password> -h [hint] <path> Encrypts the file(s) using the provided password.");
    println!("-d <password> <path>           Decrypts the file(s) using the provided password.");
    println!("-h <path>                      Displays the hint of an encrypted file.");
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
        _ => print_usage(),
    }
}
