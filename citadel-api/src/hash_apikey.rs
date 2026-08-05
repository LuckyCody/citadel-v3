// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Hash an API key for use with CITADEL_API_KEY_HASH.
//!
//! Uses HMAC-SHA256 with the configured root custody key as the server-side
//! secret, matching the algorithm used by the API server at runtime.
//!
//! Usage:
//!   CITADEL_MASTER_KEY=<64-char-hex> cargo run --bin hash-apikey -- "your-secret-api-key"
//!
//! Or generate a random key and hash it:
//!   CITADEL_MASTER_KEY=<64-char-hex> cargo run --bin hash-apikey -- --generate
//!
//! IMPORTANT: CITADEL_MASTER_KEY must be set here AND on the server.
//! Both must use the same key or authentication will fail.

use citadel_keystore::{LinuxFileRootKeyProvider, LocalPilotConfig, RootKeyProvider};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: CITADEL_MASTER_KEY=<64-char-hex> hash-apikey <api-key>");
        eprintln!("       CITADEL_MASTER_KEY=<64-char-hex> hash-apikey --generate");
        std::process::exit(1);
    }

    let key = if args[1] == "--generate" {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
        let key = hex::encode(buf);
        buf.zeroize();
        eprintln!("Generated API key (save this - it cannot be recovered):");
        eprintln!("  {}", key);
        println!("KEY:{}", key);
        eprintln!();
        key
    } else {
        args[1].clone()
    };

    let mut hmac_key = if std::env::var("CITADEL_PROFILE").as_deref() == Ok("local-pilot") {
        let config = LocalPilotConfig::from_env().unwrap_or_else(|e| {
            eprintln!("[FATAL] Invalid local-pilot configuration: {e}");
            std::process::exit(1);
        });
        let provider = LinuxFileRootKeyProvider::open(config.root_key_file).unwrap_or_else(|e| {
            eprintln!("[FATAL] Linux root-key provider failed: {e}");
            std::process::exit(1);
        });
        provider
            .load_root_key()
            .unwrap_or_else(|e| {
                eprintln!("[FATAL] Linux root-key provider failed: {e}");
                std::process::exit(1);
            })
            .to_vec()
    } else {
        let master_key = std::env::var("CITADEL_MASTER_KEY").unwrap_or_else(|_| {
            eprintln!("ERROR: CITADEL_MASTER_KEY is not set.");
            eprintln!("  For a Linux pilot, configure CITADEL_PROFILE and CITADEL_ROOT_KEY_FILE.");
            std::process::exit(1);
        });
        match hex::decode(master_key.trim()) {
            Err(e) => {
                eprintln!("[FATAL] CITADEL_MASTER_KEY is not valid hex: {}", e);
                std::process::exit(1);
            }
            Ok(bytes) if bytes.len() != 32 => {
                eprintln!(
                    "[FATAL] CITADEL_MASTER_KEY must decode to 32 bytes, got {}.",
                    bytes.len()
                );
                std::process::exit(1);
            }
            Ok(bytes) => bytes,
        }
    };

    let mut mac =
        HmacSha256::new_from_slice(&hmac_key).expect("HMAC-SHA256 accepts any key length");
    hmac_key.zeroize();
    mac.update(key.as_bytes());
    let hash = mac.finalize().into_bytes();
    let hex_hash = hex::encode(hash);

    eprintln!("HMAC-SHA256 hash (set as CITADEL_API_KEY_HASH):");
    // P179: print hash with label to stdout for script parsing
    println!("HASH:{}", hex_hash);
}
