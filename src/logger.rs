use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;

/// Thread-safe block logger that writes to block.log.
pub struct BlockLogger {
    writer: Mutex<BufWriter<File>>,
}

impl BlockLogger {
    /// Create a new logger, opening/appending to the given file.
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(BlockLogger {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Log a blocked request.
    /// Format: "{datetime},{src_ip}:{sport},{dst_ip}:80,http://{full_uri}\n"
    pub fn log(
        &self,
        datetime: &str,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        full_uri: &str,
    ) {
        let msg = format!(
            "{},{},{}:{},{}:80,http://{}",
            datetime, src_ip, src_port, dst_ip, dst_ip, full_uri
        );
        // Original FileLogger only writes strings > 20 chars
        if msg.len() <= 20 {
            return;
        }
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{}", msg);
            let _ = w.flush();
        }
    }
}

/// Write an error message to logs/error.log.
pub fn error_log(msg: &str) {
    let datetime = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    eprintln!("{} {}", datetime, msg);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/error.log")
    {
        let _ = writeln!(file, "{} {}", datetime, msg);
    }
}
