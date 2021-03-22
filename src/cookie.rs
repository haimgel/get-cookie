use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub enum CookieValue {
    Encrypted(Vec<u8>),
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Cookie {
    /// The cookie's name.
    pub name: String,
    /// The cookie's value.
    pub value: CookieValue,
    /// Last access time, if known
    pub last_access: Option<DateTime<Utc>>,
    /// The cookie's expiration, if any.
    pub expires: Option<DateTime<Utc>>,
    /// The cookie's domain, if any.
    pub domain: String,
}
