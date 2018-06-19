#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![feature(rustc_private)]
extern crate zipdefrag;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::env;
use std::fs::File;
use std::iter::Iterator;
use std::process::exit;
use zipdefrag::*;

fn usage(filename: &str) {
    println!("Usage: {} [filedump.bin]", filename);
}

fn main() {
    env_logger::init().unwrap();

    let mut args = env::args();

    let _executable = match args.next() {
        Some(exec) => exec,
        None => "".to_owned(),
    };
    match args.next() {
        Some(dump) => {
            if let Ok(mut df) = File::open(dump) {
                rip_a_zip(&mut df, Some(0x400));
            } else {
                println!("Couldn't open file");
            }
            exit(0);
        }
        None => {
            println!("Not enough args");
            exit(1);
        }
    };
}
