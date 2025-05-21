/*
 * SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
 * SPDX-FileCopyrightText: 2025 NightProg <tonio.barbier@gmail.com>
 * SPDX-License-Identifier: MPL-2.0
 */

use std::env::args;

use std::process::ExitCode;

use dsh::target::*;

fn main() -> ExitCode {
    let args: Vec<String> = args().collect();

    let program_name = args[0].clone();

    let ip = args.get(1);
    let password = args.get(2);

    let info = if let (Some(target), Some(password)) = (ip, password) {
        ConnectionLoginInfo {
            target: Target::try_from(target.clone()).unwrap(),
            password: password.clone(),
        }
    } else {
        eprintln!("Usage: {} <ip:port@user> <password>", program_name);
        return ExitCode::FAILURE;
    };

    println!("{:?}", info);
    ExitCode::SUCCESS
}
