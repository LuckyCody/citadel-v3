// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Citadel CLI — operational tooling for encryption/decryption
//!
//! Usage:
//!   citadel keygen --output <dir>
//!   citadel seal --key <pk_file> --aad <aad> --context <ctx> --input <file> --output <file>
//!   citadel open --key <sk_file> --aad <aad> --context <ctx> --input <file> --output <file>
//!   citadel inspect <file>

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use citadel_envelope::{Aad, Citadel, Context, PublicKey, SecretKey};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }

    let result = match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "seal" => cmd_seal(&args[2..]),
        "open" => cmd_open(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "--version" | "-V" => {
            println!("citadel {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        cmd => {
            eprintln!("error: unknown command '{}'", cmd);
            print_usage();
            Err("unknown command".into())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        r#"Citadel CLI — hybrid post-quantum encryption

USAGE:
    citadel <COMMAND> [OPTIONS]

COMMANDS:
    keygen      Generate a new keypair
    seal        Encrypt a file
    open        Decrypt a file
    inspect     Show ciphertext metadata (no decryption)

EXAMPLES:
    # Generate keypair
    citadel keygen --output ./keys

    # Encrypt
    citadel seal \
        --key ./keys/public.key \
        --aad "backup|db|2026" \
        --context "myapp|prod" \
        --input secret.txt \
        --output secret.enc

    # Decrypt
    citadel open \
        --key ./keys/secret.key \
        --aad "backup|db|2026" \
        --context "myapp|prod" \
        --input secret.enc \
        --output secret.txt

    # Inspect
    citadel inspect secret.enc

OPTIONS:
    -h, --help       Print help
    -V, --version    Print version
"#
    );
}

fn cmd_keygen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut output_dir = PathBuf::from(".");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                output_dir = PathBuf::from(args.get(i).ok_or("missing output path")?);
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    fs::create_dir_all(&output_dir)?;

    let citadel = Citadel::new();
    let (pk, sk) = citadel.generate_keypair();

    let pk_path = output_dir.join("public.key");
    let sk_path = output_dir.join("secret.key");

    fs::write(&pk_path, pk.to_bytes())?;
    fs::write(&sk_path, sk.to_bytes())?;

    // Restrict secret key permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&sk_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&sk_path, perms)?;
    }

    eprintln!("Generated keypair:");
    eprintln!("  Public key:  {}", pk_path.display());
    eprintln!("  Secret key:  {} (mode 600)", sk_path.display());
    eprintln!();
    eprintln!("Public key size:  {} bytes", pk.to_bytes().len());
    eprintln!("Secret key size:  {} bytes", sk.to_bytes().len());

    Ok(())
}

fn cmd_seal(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut key_path: Option<PathBuf> = None;
    let mut aad_str = String::new();
    let mut ctx_str = String::new();
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" => {
                i += 1;
                key_path = Some(PathBuf::from(args.get(i).ok_or("missing key path")?));
            }
            "--aad" | "-a" => {
                i += 1;
                aad_str = args.get(i).ok_or("missing aad")?.clone();
            }
            "--context" | "-c" => {
                i += 1;
                ctx_str = args.get(i).ok_or("missing context")?.clone();
            }
            "--input" | "-i" => {
                i += 1;
                input_path = Some(PathBuf::from(args.get(i).ok_or("missing input path")?));
            }
            "--output" | "-o" => {
                i += 1;
                output_path = Some(PathBuf::from(args.get(i).ok_or("missing output path")?));
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    let key_path = key_path.ok_or("missing --key")?;
    let output_path = output_path.ok_or("missing --output")?;

    // Load public key
    let pk_bytes = fs::read(&key_path)?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| "invalid public key")?;

    // Read plaintext
    let plaintext = if let Some(ref path) = input_path {
        fs::read(path)?
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Encrypt
    let citadel = Citadel::new();
    let aad = Aad::raw(aad_str.as_bytes());
    let ctx = Context::raw(ctx_str.as_bytes());
    let ciphertext = citadel
        .seal(&pk, &plaintext, &aad, &ctx)
        .map_err(|_| "encryption failed")?;

    // Write ciphertext
    fs::write(&output_path, &ciphertext)?;

    eprintln!(
        "Encrypted {} bytes -> {} bytes",
        plaintext.len(),
        ciphertext.len()
    );
    eprintln!("Output: {}", output_path.display());

    Ok(())
}

fn cmd_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut key_path: Option<PathBuf> = None;
    let mut aad_str = String::new();
    let mut ctx_str = String::new();
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" | "-k" => {
                i += 1;
                key_path = Some(PathBuf::from(args.get(i).ok_or("missing key path")?));
            }
            "--aad" | "-a" => {
                i += 1;
                aad_str = args.get(i).ok_or("missing aad")?.clone();
            }
            "--context" | "-c" => {
                i += 1;
                ctx_str = args.get(i).ok_or("missing context")?.clone();
            }
            "--input" | "-i" => {
                i += 1;
                input_path = Some(PathBuf::from(args.get(i).ok_or("missing input path")?));
            }
            "--output" | "-o" => {
                i += 1;
                output_path = Some(PathBuf::from(args.get(i).ok_or("missing output path")?));
            }
            _ => return Err(format!("unknown option: {}", args[i]).into()),
        }
        i += 1;
    }

    let key_path = key_path.ok_or("missing --key")?;

    // Load secret key
    let sk_bytes = fs::read(&key_path)?;
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "invalid secret key")?;

    // Read ciphertext
    let ciphertext = if let Some(ref path) = input_path {
        fs::read(path)?
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Decrypt
    let citadel = Citadel::new();
    let aad = Aad::raw(aad_str.as_bytes());
    let ctx = Context::raw(ctx_str.as_bytes());
    let plaintext = citadel
        .open(&sk, &ciphertext, &aad, &ctx)
        .map_err(|_| "decryption failed")?;

    // Write plaintext
    if let Some(ref path) = output_path {
        fs::write(path, &plaintext)?;
        eprintln!(
            "Decrypted {} bytes -> {} bytes",
            ciphertext.len(),
            plaintext.len()
        );
        eprintln!("Output: {}", path.display());
    } else {
        io::stdout().write_all(&plaintext)?;
    }

    Ok(())
}

fn cmd_inspect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = args.first().ok_or("missing file path")?;

    let ciphertext = fs::read(input_path)?;

    let info = citadel_envelope::inspect(&ciphertext).map_err(|_| "invalid ciphertext format")?;

    println!("Citadel Ciphertext");
    println!("==================");
    println!("Version:         {}", info.version);
    println!("Mode:            {}", if info.streaming { "streaming (v2)" } else { "envelope (v1)" });
    println!("KEM Suite:       {}", info.kem_suite);
    println!("AEAD Suite:      {}", info.aead_suite);
    println!();
    println!("Total Size:      {} bytes", info.total_bytes);
    if info.streaming {
        println!("Plaintext Size:  (stream — unknown from header)");
    } else {
        println!("Plaintext Size:  ~{} bytes", info.plaintext_bytes);
    }

    Ok(())
}
