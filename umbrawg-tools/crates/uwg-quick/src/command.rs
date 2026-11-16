use crate::error::{QuickError, QuickResult};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// How the child's standard error stream is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StderrMode {
    Inherit,
    Null,
}

/// A command invocation, mirroring `cmd()` from the shell implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub stderr: StderrMode,
    pub echo: bool,
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            stderr: StderrMode::Inherit,
            echo: false,
            env: Vec::new(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn stderr_null(mut self) -> Self {
        self.stderr = StderrMode::Null;
        self
    }

    pub fn echo(mut self) -> Self {
        self.echo = true;
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Text printed by `cmd()` before execution (`[#] $*`).
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            return self.program.clone();
        }
        let mut text = self.program.clone();
        for arg in &self.args {
            text.push(' ');
            text.push_str(arg);
        }
        text
    }
}

/// Result of a captured command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub status: i32,
    pub stdout: Vec<u8>,
}

impl Captured {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Abstraction over external processes, so orchestration is testable.
pub trait CommandRunner {
    fn run(&self, spec: &CommandSpec) -> QuickResult<i32>;
    fn capture(&self, spec: &CommandSpec) -> QuickResult<Captured>;
    fn command_exists(&self, program: &str) -> bool {
        find_in_path(program).is_some()
    }

    fn run_checked(&self, spec: &CommandSpec) -> QuickResult<()> {
        let status = self.run(spec)?;
        if status == 0 {
            Ok(())
        } else {
            Err(QuickError::command(&spec.program, status))
        }
    }
}

/// Real process runner.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl SystemRunner {
    fn build(&self, spec: &CommandSpec) -> Command {
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        for (key, value) in &spec.env {
            command.env(key, value);
        }
        match &spec.stdin {
            Some(_) => {
                command.stdin(Stdio::piped());
            }
            None => {
                command.stdin(Stdio::inherit());
            }
        }
        command.stderr(match spec.stderr {
            StderrMode::Inherit => Stdio::inherit(),
            StderrMode::Null => Stdio::null(),
        });
        command
    }

    fn announce(spec: &CommandSpec) {
        if spec.echo {
            eprintln!("[#] {}", spec.display());
        }
    }

    fn spawn_error(spec: &CommandSpec, error: std::io::Error) -> QuickError {
        if spec.stderr == StderrMode::Inherit {
            eprintln!("{}: {error}", spec.program);
        }
        QuickError::command(&spec.program, 127)
    }
}

impl CommandRunner for SystemRunner {
    fn run(&self, spec: &CommandSpec) -> QuickResult<i32> {
        Self::announce(spec);
        let mut command = self.build(spec);
        command.stdout(Stdio::inherit());
        let mut child = command
            .spawn()
            .map_err(|error| Self::spawn_error(spec, error))?;
        if let Some(data) = &spec.stdin {
            let write_result = match child.stdin.take() {
                Some(mut stdin) => stdin.write_all(data),
                None => Ok(()),
            };
            if let Err(error) = write_result {
                let _ = child.wait();
                return Err(error.into());
            }
        }
        let status = child.wait()?;
        Ok(exit_status_code(status))
    }

    fn capture(&self, spec: &CommandSpec) -> QuickResult<Captured> {
        Self::announce(spec);
        let mut command = self.build(spec);
        command.stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| Self::spawn_error(spec, error))?;
        if let Some(data) = &spec.stdin {
            let write_result = match child.stdin.take() {
                Some(mut stdin) => stdin.write_all(data),
                None => Ok(()),
            };
            if let Err(error) = write_result {
                let _ = child.wait();
                return Err(error.into());
            }
        }
        let output = child.wait_with_output()?;
        Ok(Captured {
            status: exit_status_code(output.status),
            stdout: output.stdout,
        })
    }
}

fn exit_status_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Search `program` in `PATH` (or use it directly when it contains a slash).
pub fn find_in_path(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = Path::new(program);
        return is_executable(path).then(|| path.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
pub mod testing {
    use super::{Captured, CommandRunner, CommandSpec};
    use crate::error::QuickResult;
    use std::cell::RefCell;
    use std::collections::HashSet;

    type MockHandler = Box<dyn Fn(&CommandSpec) -> QuickResult<Captured>>;

    pub struct MockRunner {
        handler: MockHandler,
        available: RefCell<HashSet<String>>,
        calls: RefCell<Vec<CommandSpec>>,
    }

    impl MockRunner {
        pub fn new<F>(handler: F) -> Self
        where
            F: Fn(&CommandSpec) -> QuickResult<Captured> + 'static,
        {
            Self {
                handler: Box::new(handler),
                available: RefCell::new(HashSet::new()),
                calls: RefCell::new(Vec::new()),
            }
        }

        pub fn empty() -> Self {
            Self::new(|_| Ok(Captured::default()))
        }

        pub fn with_available<I, S>(self, names: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            for name in names {
                self.available.borrow_mut().insert(name.into());
            }
            self
        }

        pub fn add_available(&self, name: impl Into<String>) {
            self.available.borrow_mut().insert(name.into());
        }

        pub fn calls(&self) -> Vec<CommandSpec> {
            self.calls.borrow().clone()
        }

        pub fn call_strings(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(CommandSpec::display)
                .collect()
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, spec: &CommandSpec) -> QuickResult<i32> {
            self.calls.borrow_mut().push(spec.clone());
            Ok((self.handler)(spec)?.status)
        }

        fn capture(&self, spec: &CommandSpec) -> QuickResult<Captured> {
            self.calls.borrow_mut().push(spec.clone());
            (self.handler)(spec)
        }

        fn command_exists(&self, program: &str) -> bool {
            self.available.borrow().contains(program)
        }
    }
}
