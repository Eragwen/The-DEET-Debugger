use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::process::{Child, Command};
use std::os::unix::process::CommandExt;
use std::convert::TryInto;

pub struct Breakpoint {
    addr: usize,
    orig_byte: u8,
}

pub struct Inferior {
    child: Child,
    pid: Pid,
    breakpoints: HashMap<usize, Breakpoint>,
}

impl Inferior {
    pub fn new(program: &str) -> Result<Inferior, Box<dyn std::error::Error>> {
        let mut command = Command::new(program);
        unsafe {
            command.pre_exec(|| {
                ptrace::traceme().expect("Failed to enable ptrace");
                Ok(())
            });
        }

        let child = command.spawn().expect("Failed to start inferior process");
        let pid = Pid::from_raw(child.id() as i32);

        waitpid(pid, None)?;

        Ok(Inferior {
            child,
            pid,
            breakpoints: HashMap::new(),
        })
    }

    pub fn cont(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        ptrace::cont(self.pid, None)?;
        match waitpid(self.pid, None)? {
            WaitStatus::Exited(pid, status) => println!("Process {} exited with status {}", pid, status),
            WaitStatus::Signaled(pid, signal, _) => println!("Process {} signaled with {:?}", pid, signal),
            WaitStatus::Stopped(pid, signal) => {
                if signal == nix::sys::signal::SIGTRAP {
                    self.handle_breakpoints()?;
                } else {
                    println!("Process {} stopped with {:?}", pid, signal);
                }
            }
            _ => println!("Unexpected status"),
        }
        Ok(())
    }

    pub fn set_breakpoint(&mut self, addr: usize) -> Result<(), Box<dyn std::error::Error>> {
        let orig_byte = ptrace::read(self.pid, addr as *mut _)? as u8;
        let breakpoint = Breakpoint { addr, orig_byte };
        self.breakpoints.insert(addr, breakpoint);
        let int3 = (orig_byte & !0xFF) | 0xCC;
        ptrace::write(self.pid, addr as *mut _, int3 as *mut _)?;
        Ok(())
    }

    pub fn handle_breakpoints(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let regs = ptrace::getregs(self.pid)?;
        let rip = regs.rip as usize - 1;

        if let Some(bp) = self.breakpoints.get(&rip) {
            ptrace::write(self.pid, bp.addr as *mut _, bp.orig_byte as *mut _)?;
            let mut regs = ptrace::getregs(self.pid)?;
            regs.rip -= 1;
            ptrace::setregs(self.pid, regs)?;
            ptrace::step(self.pid, None)?;
            waitpid(self.pid, None)?;
            let int3 = (bp.orig_byte & !0xFF) | 0xCC;
            ptrace::write(self.pid, bp.addr as *mut _, int3 as *mut _)?;
        }
        Ok(())
    }

    // pub fn remove_breakpoint(&mut self, addr: usize) -> Result<(), Box<dyn std::error::Error>> {
    //     if let Some(bp) = self.breakpoints.remove(&addr) {
    //         ptrace::write(self.pid, bp.addr as *mut _, bp.orig_byte as *mut _)?;
    //         Ok(())
    //     } else {
    //         Err(Box::new(std::io::Error::new(
    //             std::io::ErrorKind::NotFound,
    //             "Breakpoint not found",
    //         )))
    //     }
    // }

    pub fn kill(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.child.kill()?;
        Ok(())
    }
    pub fn backtrace(&mut self) {
        let pid = self.pid;

        fn get_func_and_line(address: usize) -> (String, usize) {
            // The path to the compiled binary
            let binary_path = std::env::current_exe().unwrap();
            // Convert address to hex string
            let address_str = format!("{:x}", address);
        
            // Call addr2line
            let output = Command::new("addr2line")
                .args(&["-e", binary_path.to_str().unwrap(), &address_str])
                .output()
                .expect("failed to execute addr2line");
        
            // Parse the output
            let output_str = std::str::from_utf8(&output.stdout).unwrap().trim();
            let parts: Vec<&str> = output_str.split(':').collect();
            if parts.len() == 2 {
                let func_name = parts[0].to_string();
                let line_number: usize = parts[1].parse().unwrap_or(0);
                (func_name, line_number)
            } else {
                ("Unknown".to_string(), 0)
            }
        }
        

        // Lire les registres du tracee
        if let Ok(regs) = ptrace::getregs(pid) {
            // Imprimer la backtrace
            let mut ip: usize = regs.rip.try_into().unwrap();
            let mut bp: usize = regs.rbp.try_into().unwrap();
            let mut stack_idx = 0;
            println!("prout : {} et         daezdaed {}", ip, bp);
            loop {
                // Obtenir les informations de la fonction et de la ligne
                let (function, line) = get_func_and_line(ip);
                println!("#{}  {:#010x} in {} at {}", stack_idx, ip, function, line);
                if function == "main" {
                    break;
                }

                // Obtenir l'adresse de retour de la fonction actuelle
                if let Ok(ip_val) = ptrace::read(pid, (bp + 8) as ptrace::AddressType) {
                    ip = ip_val.try_into().unwrap();
                    println!("ip : {}", ip);
                } else {
                    println!("[...]\nERROR: Unable to complete backtrace.");
                    break;
                }

                // Obtenir l'adresse de base de la pile de la fonction appelante
                if let Ok(bp_val) = ptrace::read(pid, bp as ptrace::AddressType) {
                    bp = bp_val.try_into().unwrap();
                } else {
                    println!("[...]\nERROR: Unable to complete backtrace.");
                    break;
                }
                stack_idx += 1;
            }
        } else {
            println!("Error: Failed to get registers of the inferior process");
        }
    }
}

