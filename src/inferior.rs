use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::process::Child;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

pub struct Inferior {
    child: Child,
    pub breakpoints: HashMap<usize, u8>,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, breakpoints: &Vec<usize>) -> Option<Inferior> {
        let mut cmd = std::process::Command::new(target);
        unsafe {
            cmd.pre_exec(child_traceme);
        }
        if let Ok(child) = cmd.args(args).spawn() {
            // Create unferior object with child process and empty breakpoints hashmap
            let mut inferior = Inferior {
                child,
                breakpoints: HashMap::new(),
            };

            // Add breakpoints to inferior object
            for bp in breakpoints {
                inferior.breakpoints.insert(*bp, 0);
            }

            Some(inferior)
        } else {
            None
        }
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    // Kill the inferior process aand reaps the child process.
    pub fn kill(&mut self) -> Result<(), nix::Error> {
        self.child.kill().unwrap();
        self.wait(Some(WaitPidFlag::empty())).unwrap();
    }
    
     // Writes breakpoint(s) to memory and saves the original addresses in
    // the hashmap bp_map.
    pub fn set_breakpoints(&mut serlf, breakpoints: Vec<usize>) -> Result<(), nix::Error> {
        for bp in breakpoints {
            if self.breakpoints.contains_key(&bp) {
                println!("Breakpoint already exists at address: {:#x}", bp);
            }
            else 
            let data = self.child.read_memory(bp as *const libc::c_void, 1).unwrap();
            self.breakpoints.insert(bp, data[0]);
            self.child.write_memory(bp as *const libc::c_void, &[0xcc]).unwrap();
        }
    }
}