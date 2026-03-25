use anyhow::{Context, Result};
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Output destination for JSONL event data.
pub enum OutputSink {
    /// Write to a file (append mode).
    File(tokio::fs::File),
    /// Write to stdout.
    Stdout(tokio::io::Stdout),
    /// Write to a Unix domain socket.
    #[cfg(unix)]
    UnixSocket(tokio::net::UnixStream),
}

impl OutputSink {
    /// Create a file sink (creates or appends).
    pub async fn file(path: impl AsRef<Path>) -> Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .await
            .with_context(|| {
                format!("opening output file: {}", path.as_ref().display())
            })?;
        Ok(Self::File(file))
    }

    /// Create a stdout sink.
    pub fn stdout() -> Self {
        Self::Stdout(tokio::io::stdout())
    }

    /// Connect to a Unix domain socket.
    #[cfg(unix)]
    pub async fn unix_socket(path: impl AsRef<Path>) -> Result<Self> {
        let stream = tokio::net::UnixStream::connect(path.as_ref())
            .await
            .with_context(|| {
                format!(
                    "connecting to Unix socket: {}",
                    path.as_ref().display()
                )
            })?;
        Ok(Self::UnixSocket(stream))
    }

    /// Parse an output target string into a sink.
    ///
    /// Formats:
    /// - `-` or empty → stdout
    /// - `unix:///path/to/socket` → Unix socket
    /// - anything else → file path
    pub async fn from_target(target: &str) -> Result<Self> {
        match target {
            "" | "-" => Ok(Self::stdout()),
            s if s.starts_with("unix://") => {
                #[cfg(unix)]
                {
                    let path = &s["unix://".len()..];
                    Self::unix_socket(path).await
                }
                #[cfg(not(unix))]
                {
                    anyhow::bail!("Unix sockets are not supported on this platform")
                }
            }
            path => Self::file(path).await,
        }
    }

    /// Write a single JSONL line (appends newline).
    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        let buf = format!("{line}\n");
        match self {
            Self::File(f) => f
                .write_all(buf.as_bytes())
                .await
                .context("writing to file sink"),
            Self::Stdout(out) => out
                .write_all(buf.as_bytes())
                .await
                .context("writing to stdout"),
            #[cfg(unix)]
            Self::UnixSocket(s) => s
                .write_all(buf.as_bytes())
                .await
                .context("writing to unix socket"),
        }
    }

    /// Flush the underlying writer.
    pub async fn flush(&mut self) -> Result<()> {
        match self {
            Self::File(f) => f.flush().await.context("flushing file sink"),
            Self::Stdout(out) => out.flush().await.context("flushing stdout"),
            #[cfg(unix)]
            Self::UnixSocket(s) => s.flush().await.context("flushing unix socket"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_sink_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut sink = OutputSink::file(&path).await.unwrap();
        sink.write_line(r#"{"event":"test"}"#).await.unwrap();
        sink.write_line(r#"{"event":"test2"}"#).await.unwrap();
        sink.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], r#"{"event":"test"}"#);
    }

    #[tokio::test]
    async fn test_from_target_stdout() {
        let sink = OutputSink::from_target("-").await.unwrap();
        assert!(matches!(sink, OutputSink::Stdout(_)));

        let sink = OutputSink::from_target("").await.unwrap();
        assert!(matches!(sink, OutputSink::Stdout(_)));
    }

    #[tokio::test]
    async fn test_from_target_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.jsonl");

        let sink = OutputSink::from_target(path.to_str().unwrap())
            .await
            .unwrap();
        assert!(matches!(sink, OutputSink::File(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_socket_connect_error() {
        let result = OutputSink::from_target("unix:///tmp/nonexistent.sock").await;
        assert!(result.is_err());
    }
}
