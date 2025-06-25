// SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
// SPDX-License-Identifier: MPL-2.0

use gumdrop::Options;

#[derive(Debug, Options)]
pub struct PrOptions {
    #[options(help = "Port to listen on", default = "1736")]
    pub port: String,

    #[options(help = "Prints this message")]
    help: bool,
}

pub fn main() -> PrOptions{
    let opts = PrOptions::parse_args_default_or_exit();
    
    if opts.help {
        println!("{}", PrOptions::usage());
        std::process::exit(1);
    }
    
    opts
}