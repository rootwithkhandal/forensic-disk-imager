use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ForgelensError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Backend error: {0}")]
    Backend(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid device path: {0}")]
    InvalidDevice(String),

    #[error("Acquisition cancelled")]
    Cancelled,

    #[error("Checkpoint error: {0}")]
    Checkpoint(String),
    
    #[error("Generic error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ForgelensError>;
