use rusqlite;
use thiserror::Error;
use keyring;

#[derive(Error, Debug)]
pub enum GetCookieError {
    #[error("cannot find cookie database")]
    DatabaseNotFound,
    #[error(transparent)]
    SQLiteError {
        #[from]
        source: rusqlite::Error
    },
    #[error(transparent)]
    KeyringError {
        #[from]
        source: keyring::KeyringError
    },
    #[error("invalid cookie format")]
    InvalidCookieFormat,
    #[error("cookie decryption error")]
    DecryptionError,
}

