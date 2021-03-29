use dirs::home_dir;
use std::path::PathBuf;
use rusqlite::{Connection, Result, OpenFlags, OptionalExtension};
use chrono;
use chrono::{DateTime, Utc, NaiveDateTime};

use crate::errors::GetCookieError;
use crate::cookie::{Cookie, CookieValue};

#[cfg(target_os = "macos")]
mod decrypt_osx;
#[cfg(target_os = "macos")]
use decrypt_osx::decrypt_encrypted_cookie;

#[cfg(target_os = "windows")]
mod decrypt_win;
#[cfg(target_os = "windows")]
use decrypt_win::decrypt_encrypted_cookie;

#[cfg(target_os = "macos")]
fn chrome_profile_dir() -> Result<PathBuf, GetCookieError> {
    let mut result = home_dir().ok_or(GetCookieError::DatabaseNotFound)?;
    result.push("Library/Application Support/Google/Chrome/Default");
    return Ok(result)
}

fn cookie_jar() -> Result<PathBuf, GetCookieError> {
    let mut result = chrome_profile_dir()?;
    result.push("Cookies");
    return if result.is_file() {
        Ok(result)
    } else {
        Err(GetCookieError::DatabaseNotFound)
    }
}

/// Chrome stores time in Microsoft Gregorian calendar epoch, even on Mac. It is the same across all platforms.
/// See: https://github.com/adobe/chromium/blob/master/base/time_mac.cc#L29
static NANOSECONDS_IN_SECONDS: i64 = 1000 * 1000;
static WINDOWS_EPOCH_DELTA_NANOSECONDS: i64 = 11644473600i64 * NANOSECONDS_IN_SECONDS;

/// Convert Chrome timestamp to time
fn chrome_timestamp_to_time(chrome_timestamp: i64) -> Option<DateTime<Utc>> {
    return if chrome_timestamp == 0 {
        None
    } else {
        let timestamp = chrome_timestamp - WINDOWS_EPOCH_DELTA_NANOSECONDS;
        let seconds = timestamp / NANOSECONDS_IN_SECONDS;
        let nanoseconds = (timestamp % NANOSECONDS_IN_SECONDS) as u32;
        NaiveDateTime::from_timestamp_opt(seconds, nanoseconds)
            .map(|d| DateTime::<Utc>::from_utc(d, Utc))
    }
}

/// Get encrypted cookie from Chrome's cookie database.
/// Tested on Chrome V89, should work on Chrome V80+
fn get_encrypted_cookie(domain: &str, cookie_name: &str) -> Result<Cookie, GetCookieError> {
    let connection = Connection::open_with_flags(cookie_jar()?, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result = connection.query_row(
        "SELECT host_key, expires_utc, last_access_utc, encrypted_value
                    FROM cookies
                    WHERE host_key LIKE ? and name=?",
        &[domain, cookie_name], |row|
            Ok(Cookie {
                name: cookie_name.to_string(),
                value: CookieValue::Encrypted(row.get(3)?),
                last_access: chrome_timestamp_to_time(row.get(2)?),
                expires: chrome_timestamp_to_time(row.get(1)?),
                domain: row.get(0)?,
            })
    ).optional()?.ok_or(GetCookieError::CookieNotFound);
    return result;
}

/// Get a cookie with a given name for a given domain
pub fn get_cookie(domain: &str, cookie: &str) -> Result<Cookie, GetCookieError> {
    let mut cookie = get_encrypted_cookie(domain, cookie)?;
    if let CookieValue::Encrypted(encrypted) = cookie.value {
        cookie.value = CookieValue::Text(decrypt_encrypted_cookie(&encrypted)?)
    }
    Ok(cookie)
}
