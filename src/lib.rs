//! Fetch a cookie from a locally-installed browser store
//!
//! # Example
//!
//! ```rust,no_run
//! extern crate get_cookie;
//!
//! # fn main() {
//!   let cookie = get_cookie(".mydomain.com", "my-cookie-name");
//! # }
//! ```

mod chrome;
mod cookie;
mod errors;

pub fn get_cookie(domain: &str, cookie: &str) -> Result<Option<cookie::Cookie>, GetCookieError> {
    // TODO: Add support for other browsers, check which browser has the latest cookie and return it.
    chrome::get_cookie(domain, cookie)
    //
    // Safari support:
    //   * Could be based on https://github.com/alexwlchan/azure-aws-credentials/blob/development/src/safari_browsercookie.rs
    //   * Safari cookies file could not be read by default, the app needs "full disk access" permission, which
    //     requires an App (not a stand-alone binary), signing, etc.
}
