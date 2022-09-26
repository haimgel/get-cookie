use crate::errors::GetCookieError;
use ring::aead;
use ring::aead::{BoundKey, Nonce};

/// WARNING: Windows support is not implemented yet, not even 25%
/// For reference, see:
///   * https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc
///   * https://stackoverflow.com/a/60423699/331862
///   * https://github.com/n8henrie/pycookiecheat/blob/dev/src/pycookiecheat/pycookiecheat.py
///   * https://github.com/Fa1c0n35/Cheat-Sheet/blob/master/Z%20-%20Tool%20Box/LaZagne/Linux/lazagne/softwares/browsers/chromium_based.py

struct OneNonceSequence {
    inner: Option<ring::aead::Nonce>,
}
impl OneNonceSequence {
    fn new(inner: ring::aead::Nonce) -> Self {
        Self { inner: Some(inner) }
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.inner.take().ok_or(ring::error::Unspecified)
    }
}

fn get_chrome_key() -> Result<Vec<u8>, GetCookieError> {
    // Not implemented
    Err(GetCookieError::NotImplemented)
}

/// Not working, not fully implemented!
pub fn decrypt_encrypted_cookie(cookie: &Vec<u8>) -> Result<String, GetCookieError> {
    if cookie.len() < 15 {
        // Should be at least 15 bytes: 3 bytes prefix + 12 bytes IV
        return Err(GetCookieError::InvalidCookieFormat);
    }
    let (signature, data) = cookie.split_at(3);
    let (iv, encrypted) = data.split_at(12);

    if std::str::from_utf8(signature) != Ok("v10") {
        return Err(GetCookieError::InvalidCookieFormatVersion);
    }
    let key = get_chrome_key()?;

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
    let nonce = Nonce::try_assume_unique_for_key(&iv).unwrap();
    let x = OneNonceSequence::new(nonce);
    let mut key = aead::OpeningKey::new(key, x);
    let mut buffer = Vec::from(encrypted);
    let out = key
        .open_in_place(ring::aead::Aad::empty(), &mut buffer)
        .unwrap();
    return Ok(String::from_utf8(Vec::from(out)).unwrap());
}
