pub struct CliLogger {
    module: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Level {
    Error,
    Info,
    Warn,
    Debug,
}

#[allow(dead_code)]
impl CliLogger {
    pub fn new(module: &str) -> Self {
        Self {
            module: format!("{:>5}", module),
        }
    }

    pub fn log(&self, level: Level, msg: &str) {
        let level = format!("{:?}", level).to_uppercase();
        eprintln!("[{}][{:>5}] {}", self.module, level, msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::Info, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::Error, msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::Warn, msg);
    }

    #[allow(unused_variables)]
    pub fn debug(&self, msg: &str) {
        #[cfg(debug_assertions)]
        self.log(Level::Debug, msg);
    }
}
