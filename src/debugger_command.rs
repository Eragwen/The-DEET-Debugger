pub enum DebuggerCommand {
    Quit,
    Run(Vec<String>),
    Continue,
    Backtrace,
    Breakpoint(usize),
}

impl DebuggerCommand {
    pub fn from_tokens(tokens: &Vec<&str>) -> Option<DebuggerCommand> {
        match tokens[0] {
            "q" | "quit" => Some(DebuggerCommand::Quit),
            "r" | "run" => {
                let args = tokens[1..].to_vec();
                Some(DebuggerCommand::Run(
                    args.iter().map(|s| s.to_string()).collect(),
                ))
            },
            "c" | "continue" => Some(DebuggerCommand::Continue),
            "bt" | "backtrace" => Some(DebuggerCommand::Backtrace),
            "b" | "break" => {
                if tokens.len() != 2 {
                    println!("Usage: b <address>");
                    return None;
                }
                let addr = usize::from_str_radix(tokens[1], 16).unwrap();
                Some(DebuggerCommand::Breakpoint(addr))
            },
            // Default case:
            _ => None,
        }
    }
}