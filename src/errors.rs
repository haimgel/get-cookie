use keyring;
use rusqlite;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GetCookieError {
    #[error("cannot find cookie database")]
    DatabaseNotFound,
    #[error(transparent)]
    SQLiteError {
        #[from]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    KeyringError {
        #[from]
        source: keyring::Error,
    },
    #[error("invalid cookie format")]
    InvalidCookieFormat,
    #[error("cookie decryption error")]
    DecryptionError,
    #[error("cookie not found")]
    CookieNotFound,
}
