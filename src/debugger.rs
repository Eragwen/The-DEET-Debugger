use crate::debugger_command::DebuggerCommand;
use crate::inferior::Inferior;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use crate::dwarf_data::{DwarfData, Error as DwarfError};


pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    dwarf_data: DwarfData
    breakpoints: Vec<usize>,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // (milestone 3): initialize the DwarfData
        let dwarf_data = match DwarfData::from_file(target) {
            Ok(dwarf_data) => dwarf_data,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Error opening the file: {} ", target)
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Error parsing the file: {}", err);
                std::process::exit(1);
            }
        };

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            dwarf_data,
            breakpoints: Vec::new(),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    // If we're already debugging a process, kill it before starting a new one
                    if let Some(mut inferior) = self.inferior.take() {
                        inferior.kill().unwrap();
                    }

                    // Start a new inferior process
                    match Inferior::new(&self.target, &args, &self.breakpoints) {
                        Some(inferior) => {
                            self.inferior = Some(inferior);
                            println!("Started inferior with pid {}", self.inferior.as_ref().unwrap().pid());
                        }
                        None => {
                            println!("Failed to start inferior process");
                        }
                    }
                }

                    
                }
                DebuggerCommand::Quit => {
                    if let Some(mut inferior) = self.inferior.take() {
                        if let Err(err) = inferior.kill() {
                            println!("Error killing inferior process: {}", err);
                        }
                    }
                    break;
                }

                DebuggerCommand::Continue => {
                    if let Some(ref mut inferior) = self.inferior {
                        match inferior.continue_execution() {
                            Ok(status) => {
                                match status {
                                    Status::Exited(code) => {
                                        println!("Inferior exited with code {}", code);
                                        self.inferior = None;
                                    }
                                    Status::Signaled(signal) => {
                                        println!("Inferior received signal {}", signal);
                                    }
                                    Status::Stopped(signal, rip) => {
                                        println!("Inferior stopped with signal {} at address {:#x}", signal, rip);
                                    }
                                }
                            }
                            Err(err) => {
                                println!("Error continuing inferior process: {}", err);
                            }
                        }
                    } else {
                        println!("No inferior process to continue");
                    }
                }

                DebuggerCommand::Backtrace => {
                    if let Some(ref inferior) = self.inferior {
                        self.backtrace();
                    } else {
                        println!("No inferior process to get backtrace from");
                    }
                }

                DebuggerCommand::Breakpoint(addr) => {
                    self.set_breakpoint(addr);
                }
            }
        }
    }

    pub fn backtrace(&self) {
        // Read registers from the inferior process
        let pid = self.inferior.as_ref().unwrap().pid();
        let regs = ptrace::getregs(pid).unwrap();

        // Print the backtrace
        let mut ip: usize = regs.rip.try_into().unwrap();
        let mut bp: usize = regs.rbp.try_into().unwrap();
        let mut stack_idx = 0;
        loop {
            // Read the return address from the stack
            let ret_addr = self.inferior.as_ref().unwrap().read_memory((bp + 8) as *const libc::c_void, 8).unwrap();
            let ret_addr = LittleEndian::read_u64(&ret_addr);
            let func_name = self.dwarf_data.get_function_name(ip).unwrap_or("???".to_string());
            println!("{}: {:#x} - {}", stack_idx, ip, func_name);

            // Check if we've reached the end of the backtrace
            if ret_addr == 0 {
                break;
            }

            // Update the stack index, instruction pointer, and base pointer
            stack_idx += 1;
            ip = ret_addr as usize;
            bp = self.inferior.as_ref().unwrap().read_memory((bp) as *const libc::c_void, 8).unwrap();
            bp = LittleEndian::read_u64(&bp);
        }

    }

    pub fn set_breakpoint(&mut self, input: &str) {
        let bp: usize
        if inp.starts_with("*") {
            breakpoint = match Debugger::parse_address(&input[1..]) {
                Some(addr) => addr,
                None => {
                    println!("ERROR: {} is not a well-formed address.", &inp[1..]);
                    return;
                },
            };
        } else {
            bp = match input.parse::<usize>().ok() {
                Some(line) => {
                    match self.dwarf_data.get_addr_for_line(None, line) {
                        Some(addr) => addr,
                        None => {
                            println!("ERROR: No address found for line {}.", line);
                            return;
                        }
                    }
                },
                None => {
                    match self.dwarf_data.get_addr_for_function(None, input) {
                        Some(addr) => addr,
                        None => {
                            println!("ERROR: No address found for function {}.", input);
                            return;
                        }
                    }
                }
            }
        }

        // Check if the breakpoint already exists
        if self.breakpoints.contains(&bp) {
            println!("Breakpoint already exists at address: {:#x}", bp);
            return;
        }

        // if not, add the breakpoint
        println!("Set breakpoint at address: {:#x}", self.breakpoints.len(), bp);

        // If child has not started, add the breakpoint to the list, child will set it when it starts
        // If child has started, set the breakpoint in the child by calling set_breakpoint  and add it to the list
        if let Some(inferior) = self.inferior.as_mut() {
            let bpt = vec![bp];
            if let Err(err) = inferior.set_breakpoints(bpt) {
                println!("Error setting breakpoint: {}", err);
                return;
            }

            self.breakpoints.push(bp);}
     }


    pub fn parse_address(addr: &str) -> Option<usize> {
        if addr.starts_with("0x") {
            usize::from_str_radix(&addr[2..], 16).ok()
        } else {
            &addr.parse::<usize>().ok()
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}