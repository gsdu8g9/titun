// Copyright 2017 Sopium

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

extern crate clap;
extern crate env_logger;
extern crate sodiumoxide;
extern crate titun;

use clap::{App, AppSettings, SubCommand};
use std::fs::File;
use std::io::{Read, Result};
use titun::config::{Config, genkey_base64};
use titun::map_err_io::MapErrIo;
use titun::titun::run;

fn read_file(path: &str) -> Result<String> {
    let mut f = File::open(path)?;
    let mut out = String::new();
    f.read_to_string(&mut out)?;
    Ok(out)
}

fn inner() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init().map_err_io()?;
    sodiumoxide::init();

    let sub_tun = SubCommand::with_name("tun")
        .display_order(1)
        .args_from_usage("-c, --config=<FILE> 'Specify config file'");
    let sub_genkey = SubCommand::with_name("genkey").display_order(2);

    let app = App::new("titun")
        .version("0.0.2")
        .about("A simple secure ip tunnel for linux.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(sub_tun)
        .subcommand(sub_genkey);

    let matches = app.get_matches();

    match matches.subcommand() {
        ("genkey", _) => {
            println!("key: \"{}\"", genkey_base64());
        }
        ("tun", Some(m)) => {
            let config_file = m.value_of("config").unwrap();
            let config = read_file(config_file)?;
            let config = Config::parse(config.as_str())?;
            run(&config)?;
        }
        _ => {
            unreachable!();
        }
    }

    Ok(())
}

fn main() {
    inner().unwrap_or_else(|e| {
        println!("Error: {}", e);
        std::process::exit(1);
    })
}
