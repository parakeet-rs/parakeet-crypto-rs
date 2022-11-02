pub struct CliLogger {
    module: String,
}

#[derive(Debug)]
pub enum Level {
    ERROR,
    INFO,
    WARN,
    DEBUG,
}

impl CliLogger {
    pub fn new(module: &str) -> Self {
        Self {
            module: String::from(module),
        }
    }

    pub fn log(&self, level: Level, msg: &str) {
        let level = format!("{:?}", level);
        eprintln!("[{}][{:>5}] {}", self.module, level, msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::INFO, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::ERROR, msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::WARN, msg);
    }

    pub fn debug(&self, msg: &str) {
        #[cfg(debug_assertions)]
        self.log(Level::DEBUG, msg);
    }
}
