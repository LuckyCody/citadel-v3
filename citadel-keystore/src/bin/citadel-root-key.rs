// SPDX-License-Identifier: AGPL-3.0-or-later
//! Initialize or validate the Linux local-pilot root custody file.

use citadel_keystore::{LinuxFileRootKeyProvider, RootKeyProvider};
use std::path::Path;

fn usage() -> ! {
    eprintln!("Usage: citadel-root-key init <path>");
    eprintln!("       citadel-root-key check <path>");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| usage());
    let path = args.next().unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let provider = match command.as_str() {
        "init" => LinuxFileRootKeyProvider::create(Path::new(&path)),
        "check" => LinuxFileRootKeyProvider::open(Path::new(&path)),
        _ => usage(),
    }
    .unwrap_or_else(|error| {
        eprintln!("root custody {command} failed: {error}");
        std::process::exit(1);
    });

    let capabilities = provider.capabilities();
    println!("provider={}", capabilities.provider);
    println!("path={}", provider.path().display());
    println!("hardware_backed={}", capabilities.hardware_backed);
    println!("non_exportable={}", capabilities.non_exportable);
    println!(
        "owner_only_permissions_enforced={}",
        capabilities.owner_only_permissions_enforced
    );
    println!("symlink_rejected={}", capabilities.symlink_rejected);
    println!("status=pass");
}
