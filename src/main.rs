extern crate rustyline;
extern crate nix;
extern crate object;
extern crate gimli;
extern crate addr2line;


mod debugger;
mod debugger_command;
mod inferior;
mod dwarf_data;
mod gimli_wrapper;

use debugger::Debugger;
use std::env;

fn main() {
    unsafe {env::set_var("RUST_BACKTRACE", "full");}
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <program>", args[0]);
        std::process::exit(1);
    }

    let program = &args[1];
    let mut debugger = Debugger::new(program.to_string());
    debugger.run();
}
