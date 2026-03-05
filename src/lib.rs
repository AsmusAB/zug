use std::path;

const MIN_PASSWORD_LENGTH: usize = 16;

mod args;
mod cipher;
mod key;

fn handle_encryption(password: &str, hint: Option<String>, paths: Vec<path::PathBuf>) {
    if password.len() < MIN_PASSWORD_LENGTH {
        println!("Password length is short. Please consider using a longer password.")
    }

    let key = key::Key::from_str(password);

    for path in &paths {
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

fn handle_decryption(password: &str, paths: Vec<path::PathBuf>) {
    let key = key::Key::from_str(password);

    for path in &paths {
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

fn handle_hint(path: &path::Path) {
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

pub fn execute() {
    match args::parse() {
        args::Command::Encrypt {
            password,
            hint,
            paths,
        } => handle_encryption(&password, hint, paths),
        args::Command::Decrypt { password, paths } => handle_decryption(&password, paths),
        args::Command::Hint { path } => handle_hint(&path),
    }
}
