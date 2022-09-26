use crate::errors::GetCookieError;
use aes;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use cbc;
use keyring;
use ring::pbkdf2;
use std::num::NonZeroU32;

// Must be equal to AES-128 key size
const CREDENTIALS_LEN: usize = 16;
type Credential = [u8; CREDENTIALS_LEN];
type Aes128Cbc = cbc::Decryptor<aes::Aes128Dec>;

/// Get a Chrome decryption key: it is stored in the Keyring for security
fn get_chrome_key() -> Result<Credential, GetCookieError>{
    // Follows the same algorithm as `GetEncryptionKey` in:
    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_mac.mm;l=66

    let keyring = keyring::Entry::new("Chrome Safe Storage", "Chrome");
    let key = keyring.get_password()?;

    let mut derived_key = [0u8; CREDENTIALS_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        NonZeroU32::new(1003u32).unwrap(),
        "saltysalt".as_bytes(),
        key.as_bytes(),
        &mut derived_key
    );
    return Ok(derived_key);
}

/// Decrypts an encrypted cookie to a plain-text form
pub fn decrypt_encrypted_cookie(mut cookie: Vec<u8>) -> Result<String, GetCookieError> {
    // Should do the same as Chrome in `OSCrypt::DecryptString` in:
    // https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_mac.mm;l=170
    let (signature, data) = cookie.split_at_mut(3);
    if std::str::from_utf8(signature) != Ok("v10") {
        return Err(GetCookieError::InvalidCookieFormat)
    }
    let key = get_chrome_key()?;
    let iv = [0x20u8; CREDENTIALS_LEN];

    let cypher = Aes128Cbc::new(&key.into(), &iv.into());
    let output = cypher
        .decrypt_padded_mut::<Pkcs7>(data)
        .map_err(|_| GetCookieError::DecryptionError)?;
    return String::from_utf8(output.into()).map_err(|_| GetCookieError::DecryptionError);
}
