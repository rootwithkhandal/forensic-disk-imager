use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForgelensError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("VSS error: {0}")]
    VssError(String),

    #[error("Acquisition cancelled")]
    Cancelled,

    #[error("Plugin error: {0}")]
    Plugin(String),
}

pub type Result<T> = std::result::Result<T, ForgelensError>;
