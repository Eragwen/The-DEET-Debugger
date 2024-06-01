use rustyline::Editor;
use crate::inferior::Inferior;
use std::collections::HashMap;

pub struct Debugger {
    program: String,
    breakpoints: HashMap<usize, bool>,
}


impl Debugger {
    pub fn new(program: String) -> Debugger {
        Debugger {
            program,
            breakpoints: HashMap::new(),
        }
    }

    pub fn run(&mut self) {
        let mut rl = Editor::<()>::new().expect("Error creating line editor");
        let mut inferior = None;

        loop {
            let readline = rl.readline("(deet) ");
            match readline {
                Ok(line) => {
                    let args: Vec<&str> = line.split_whitespace().collect();
                    match args.get(0).map(|s| *s) {
                        Some("run" | "r") => {
                            if inferior.is_some() {
                                println!("Program already running.");
                            } else {
                                match Inferior::new(&self.program) {
                                    Ok(mut child) => {
                                        if !self.breakpoints.is_empty() {
                                            for &addr in self.breakpoints.keys() {
                                                child.set_breakpoint(addr).expect("Failed to set breakpoint");
                                            }
                                        }
                                        inferior = Some(child);
                                        if let Some(child) = &mut inferior {
                                            if let Err(e) = child.cont() {
                                                println!("Error continuing inferior: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => println!("Error starting inferior: {}", e),
                                }
                            }
                        }
                        Some("continue" | "c") => {
                            if let Some(child) = &mut inferior {
                                if let Err(e) = child.cont() {
                                    println!("Error continuing inferior: {}", e);
                                }
                            } else {
                                println!("No program running.");
                            }
                        }
                        Some("break" | "b") => {
                            if args.len() < 2 {
                                println!("Usage: break <address>");
                            } else {
                                let addr = usize::from_str_radix(args[1], 16).expect("Invalid address");
                                if self.breakpoints.insert(addr, true).is_none() {
                                    println!("Breakpoint set at address {:#x}", addr);
                                    if let Some(child) = &mut inferior {
                                        if let Err(e) = child.set_breakpoint(addr) {
                                            println!("Error setting breakpoint: {}", e);
                                        }
                                    }
                                } else {
                                    println!("Breakpoint already set at address {:#x}", addr);
                                }
                            }   
                        }
                        Some("delete" | "del") => {
                            if args.len() < 2 {
                                println!("Usage: delete <address>");
                            } else {
                                let addr = usize::from_str_radix(args[1], 16).expect("Invalid address");
                                if self.breakpoints.remove(&addr).is_some() {
                                    println!("Breakpoint removed at address {:#x}", addr);
                                } else {
                                    println!("No breakpoint found at address {:#x}", addr);
                                }
                            }
                        }
                        Some("list" | "l") => {
                            if self.breakpoints.is_empty() {
                                println!("No breakpoints set.");
                            } else {
                                for &addr in self.breakpoints.keys() {
                                    println!("Breakpoint at address {:#x}", addr);
                                }
                            }
                        }
                        Some("quit" | "q") => {
                            if let Some(child) = &mut inferior {
                                if let Err(e) = child.kill() {
                                    println!("Error killing inferior: {}", e);
                                }
                            }
                            break;
                        }
                        Some("backtrace" | "bt") => {
                            if let Some(child) = &mut inferior {
                                child.backtrace();
                            } else {
                                println!("No program running.");
                            }
                        }
                        Some("help") => {
                            println!("Available commands:");
                            println!("run | r               - Start the program");
                            println!("continue | c              - Continue execution");
                            println!("break <address> | b       - Set a breakpoint at address");
                            println!("delete <address> | del    - Delete breakpoint at address");
                            println!("list | l                  - List all breakpoints");
                            println!("quit | q                  - Quit the debugger");
                            println!("help                 - Show this help message");
                        }
                        _ => println!("Unrecognized command. Type 'help' for a list of commands."),
                    }
                }
                Err(_) => break,
            }
        }
    }
}
