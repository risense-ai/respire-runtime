//! memory::crypto — end-to-end encryption key hierarchy
//!
//!   Auth domain (separate from crypto): password → PBKDF2 hash → server verify; token is auth only
//!   Crypto domain (**v4 live**, frozen 2026-09-16):
//!     Secret Key      A3- code (144-bit entropy), **the only root credential**, in the OS keyring
//!     KEK             HKDF(Secret Key entropy, kdf_salt, info="onememory:kek:v4") — wraps URK only, never on disk
//!     URK             random 256-bit at first register; uploaded wrapped only (vault table)
//!     data_key        HKDF(URK, "onememory:data:v1") — **one per library**, encrypts every entry
//!     embedding_key   HKDF(URK, "onememory:embedding:v1") — encrypts vectors
//!     data            AES-256-GCM, **independent random nonce per item** (nonce stored beside ciphertext)
//!
//!   Rotation:
//!     change password/Secret → rewrap URK (data stays); change token → crypto unaffected
//!
//!   Server never sees: password, Secret, URK plaintext, data keys, plaintext content
//!
//!   **History (do not implement the old draft)**: this file once copied a four-layer roadmap with two
//!   mismatches vs the real code, corrected 2026-09-20 — (1) "Item Key: independent random key per memory"
//!   **was never implemented** (no item_key anywhere; one data_key for the whole library, so you cannot
//!   "re-encrypt just this item"); (2) early KEK drafts used Argon2id; from v4 KEK is pure HKDF
//!   (`derive_kek_v4`; Argon2id remains only in v1 `derive_kek`).

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result as AnyResult;
use argon2::Argon2;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
/// Account Secret length in hex characters.
pub const SECRET_HEX_CHARS: usize = 64;

type AeadError = aes_gcm::Error;

// ── random generation ──
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_hex(n_bytes: usize) -> String {
    hex::encode(random_bytes(n_bytes))
}

/// Generate an Account Secret (64 hex chars, created at register, kept offline by the user).
pub fn generate_account_secret() -> String {
    random_hex(32)
}

/// Generate a random key (shared by URK / Item Key).
pub fn generate_key() -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    OsRng.fill_bytes(&mut key);
    key
}

// ── KDF: password + Secret → KEK ──
/// Argon2id(password, kdf_salt) → intermediate; HKDF mixes in Account Secret → KEK.
/// KEK only wraps/unwraps URK; stays in memory after unlock, never on disk.
pub fn derive_kek(password: &str, account_secret: &str, kdf_salt_hex: &str) -> AnyResult<[u8; KEY_BYTES]> {
    let salt_bytes = hex::decode(kdf_salt_hex).map_err(|e| anyhow::anyhow!("KDF salt hex decode failed: {e}"))?;
    let argon2 = Argon2::default();
    let mut intermediate = [0u8; KEY_BYTES];
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut intermediate)
        .map_err(|e| anyhow::anyhow!("Argon2id derive failed: {e}"))?;
    let hk = Hkdf::<Sha256>::new(Some(account_secret.as_bytes()), &intermediate);
    let mut kek = [0u8; KEY_BYTES];
    hk.expand(b"onememory:kek:v1", &mut kek)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(kek)
}

/// Derive a domain-separated subkey from URK. Data keys and related keys come from this.
pub fn derive_subkey(urk: &[u8; KEY_BYTES], info: &[u8]) -> AnyResult<[u8; KEY_BYTES]> {
    let hk = Hkdf::<Sha256>::new(None, urk);
    let mut key = [0u8; KEY_BYTES];
    hk.expand(info, &mut key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(key)
}

// ── wrap / unwrap (AES-256-GCM) ──
/// wrapping_key wraps plaintext_key. Returns (nonce_hex, wrapped_hex).
pub fn wrap_key(plaintext_key: &[u8; KEY_BYTES], wrapping_key: &[u8; KEY_BYTES]) -> AnyResult<(String, String)> {
    let (nonce, ct) = encrypt_raw(plaintext_key, wrapping_key)?;
    Ok((nonce, ct))
}

/// unwrapping_key unwraps. Returns the plaintext key.
pub fn unwrap_key(wrapped_hex: &str, nonce_hex: &str, unwrapping_key: &[u8; KEY_BYTES]) -> AnyResult<[u8; KEY_BYTES]> {
    let plain = decrypt_raw(wrapped_hex, nonce_hex, unwrapping_key)?;
    if plain.len() != KEY_BYTES {
        anyhow::bail!("unwrapped key has unexpected length: {}", plain.len());
    }
    let mut key = [0u8; KEY_BYTES];
    key.copy_from_slice(&plain);
    Ok(key)
}

// ── auth domain: password hash (server verify; separate from crypto) ──
/// Super password → KEK (separate from login password). PBKDF2-SHA256 210k, random salt stored in cloud vault.
pub const SUPER_KDF_ITERS: u32 = 210_000;

pub fn derive_super_kek(super_pass: &str, salt_hex: &str) -> AnyResult<[u8; KEY_BYTES]> {
    let salt = hex::decode(salt_hex).map_err(|e| anyhow::anyhow!("super salt hex decode failed: {e}"))?;
    let mut out = [0u8; KEY_BYTES];
    pbkdf2::pbkdf2_hmac::<Sha256>(super_pass.as_bytes(), &salt, SUPER_KDF_ITERS, &mut out);
    Ok(out)
}

/// v4 single factor: KEK = HKDF(ikm=Secret Key entropy, salt=kdf_salt, info="onememory:kek:v4").
/// Super password left the crypto domain — Secret Key (144-bit random) alone protects URK, held in the OS keyring.
pub fn derive_kek_v4(secret_key: &str, kdf_salt_hex: &str) -> AnyResult<[u8; KEY_BYTES]> {
    let ikm = secret_key_bytes(secret_key)?;
    let salt = hex::decode(kdf_salt_hex).map_err(|e| anyhow::anyhow!("kdf_salt hex decode failed: {e}"))?;
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut kek = [0u8; KEY_BYTES];
    hk.expand(b"onememory:kek:v4", &mut kek)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(kek)
}

/// Secret Key string (A3-xxxx-… hyphenated) → 18 bytes of raw entropy.
pub fn secret_key_bytes(secret_key: &str) -> AnyResult<[u8; 18]> {
    // Strip the A3- prefix before filtering hex — "A3" itself is valid hex and would add a byte
    let body = secret_key.trim().trim_start_matches("A3-");
    let raw: String = body.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes = hex::decode(&raw).map_err(|e| anyhow::anyhow!("Secret Key format error: {e}"))?;
    if bytes.len() != 18 {
        anyhow::bail!("Secret Key length is {} bytes (expected 18)", bytes.len());
    }
    let mut out = [0u8; 18];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 1Password-style: master password (user-chosen) + Secret Key (generated) → KEK. Secret Key never goes to the server.
pub fn generate_secret_key() -> String {
    let raw = random_hex(18);
    format!(
        "A3-{}-{}-{}-{}-{}-{}",
        &raw[0..6],
        &raw[6..12],
        &raw[12..18],
        &raw[18..24],
        &raw[24..30],
        &raw[30..36]
    )
}

pub fn derive_vault_kek(super_pass: &str, secret_key: &str, salt_hex: &str) -> AnyResult<[u8; KEY_BYTES]> {
    let intermediate = derive_super_kek(super_pass, salt_hex)?;
    let hk = Hkdf::<Sha256>::new(Some(secret_key.as_bytes()), &intermediate);
    let mut kek = [0u8; KEY_BYTES];
    hk.expand(b"onememory:kek:v1", &mut kek)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(kek)
}

/// PBKDF2-SHA256 password hash. Server stores only this hash, never the plaintext password.
/// 100k iterations (OWASP-recommended class).
pub fn derive_pass_hash(password: &str, salt_hex: &str) -> AnyResult<String> {
    let salt = hex::decode(salt_hex).map_err(|e| anyhow::anyhow!("salt hex decode failed: {e}"))?;
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut out);
    Ok(hex::encode(out))
}

/// Auth salt: deterministic, domain-separated derivation from user. Any device can recompute it.
/// Server stores only pass_hash; every client device hashes with the same salt for login.
pub fn derive_auth_salt(user: &str) -> AnyResult<String> {
    let hk = Hkdf::<Sha256>::new(None, user.trim().to_lowercase().as_bytes());
    let mut salt = [0u8; 16];
    hk.expand(b"onememory:auth-salt:v1", &mut salt)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(hex::encode(salt))
}

// ── data encryption (data_key AES-256-GCM) ──
/// data_key encrypts content → (nonce_hex, ciphertext_hex).
pub fn encrypt_item(data_key: &[u8; KEY_BYTES], plaintext: &str) -> AnyResult<(String, String)> {
    encrypt_raw(plaintext.as_bytes(), data_key)
}

/// data_key decrypts content.
pub fn decrypt_item(data_key: &[u8; KEY_BYTES], ciphertext_hex: &str, nonce_hex: &str) -> AnyResult<String> {
    let plain = decrypt_raw(ciphertext_hex, nonce_hex, data_key)?;
    String::from_utf8(plain).map_err(|e| anyhow::anyhow!("decrypt result is not UTF-8: {e}"))
}

// ── binary encryption (embeddings and other non-UTF-8 payloads) ──
/// key encrypts arbitrary bytes → (nonce_hex, ciphertext_hex).
pub fn encrypt_bytes(key: &[u8; KEY_BYTES], plaintext: &[u8]) -> AnyResult<(String, String)> {
    encrypt_raw(plaintext, key)
}

/// key decrypts arbitrary bytes.
pub fn decrypt_bytes(key: &[u8; KEY_BYTES], ciphertext_hex: &str, nonce_hex: &str) -> AnyResult<Vec<u8>> {
    decrypt_raw(ciphertext_hex, nonce_hex, key)
}

// ── internal: raw AEAD ──
fn encrypt_raw(plaintext: &[u8], key: &[u8; KEY_BYTES]) -> AnyResult<(String, String)> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e: AeadError| anyhow::anyhow!("encrypt failed: {e}"))?;
    Ok((hex::encode(nonce_bytes), hex::encode(ct)))
}

fn decrypt_raw(ciphertext_hex: &str, nonce_hex: &str, key: &[u8; KEY_BYTES]) -> AnyResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| anyhow::anyhow!("nonce hex decode failed: {e}"))?;
    if nonce_bytes.len() != NONCE_BYTES {
        anyhow::bail!("nonce length must be {NONCE_BYTES} bytes");
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct_bytes = hex::decode(ciphertext_hex).map_err(|e| anyhow::anyhow!("ciphertext hex decode failed: {e}"))?;
    cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|e: AeadError| anyhow::anyhow!("decrypt failed (wrong key or corrupted data): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_hierarchy_roundtrip() -> AnyResult<()> {
        let password = "user-password-123";
        let secret = generate_account_secret();
        assert_eq!(secret.len(), SECRET_HEX_CHARS);
        let kdf_salt = random_hex(16);
        let kek = derive_kek(password, &secret, &kdf_salt)?;
        let urk = generate_key();
        let (urk_nonce, wrapped_urk) = wrap_key(&urk, &kek)?;
        // New-device unlock chain
        let kek2 = derive_kek(password, &secret, &kdf_salt)?;
        let urk2 = unwrap_key(&wrapped_urk, &urk_nonce, &kek2)?;
        assert_eq!(urk, urk2);
        // Data encryption
        let data_key = derive_subkey(&urk, b"onememory:data:v1")?;
        let original = "跨设备共享的记忆！";
        let (d_nonce, ct) = encrypt_item(&data_key, original)?;
        assert_eq!(decrypt_item(&data_key, &ct, &d_nonce)?, original);
        Ok(())
    }

    #[test]
    fn super_password_wraps_without_login_pass() -> AnyResult<()> {
        let salt = random_hex(16);
        let kek = derive_super_kek("super-pass", &salt)?;
        let urk = generate_key();
        let (nonce, wrapped) = wrap_key(&urk, &kek)?;
        let kek2 = derive_super_kek("super-pass", &salt)?;
        assert_eq!(unwrap_key(&wrapped, &nonce, &kek2)?, urk);
        let login_kek = derive_super_kek("login-pass", &salt)?;
        assert!(unwrap_key(&wrapped, &nonce, &login_kek).is_err());
        Ok(())
    }

    #[test]
    fn wrong_password_cannot_unwrap() -> AnyResult<()> {
        let secret = generate_account_secret();
        let salt = random_hex(16);
        let kek = derive_kek("right", &secret, &salt)?;
        let urk = generate_key();
        let (nonce, wrapped) = wrap_key(&urk, &kek)?;
        let wrong = derive_kek("wrong", &secret, &salt)?;
        assert!(unwrap_key(&wrapped, &nonce, &wrong).is_err());
        Ok(())
    }

    #[test]
    fn subkey_domain_separation() -> AnyResult<()> {
        let urk = [9u8; 32];
        assert_ne!(
            derive_subkey(&urk, b"onememory:data:v1")?,
            derive_subkey(&urk, b"onememory:blind-index:v1")?
        );
        Ok(())
    }

    #[test]
    fn vault_v3_needs_master_and_secret_key() -> AnyResult<()> {
        let salt = random_hex(16);
        let secret = generate_secret_key();
        assert!(secret.starts_with("A3-"));
        assert_eq!(secret.split('-').count(), 7);
        let kek = derive_vault_kek("master-pass", &secret, &salt)?;
        let urk = generate_key();
        let (nonce, wrapped) = wrap_key(&urk, &kek)?;
        assert_eq!(
            unwrap_key(
                &wrapped,
                &nonce,
                &derive_vault_kek("master-pass", &secret, &salt)?
            )?,
            urk
        );
        assert!(unwrap_key(
            &wrapped,
            &nonce,
            &derive_vault_kek("wrong-pass", &secret, &salt)?
        )
        .is_err());
        assert!(unwrap_key(
            &wrapped,
            &nonce,
            &derive_vault_kek("master-pass", "A3-000000-000000-000000-000000-000000-000000", &salt)?
        )
        .is_err());
        assert!(unwrap_key(
            &wrapped,
            &nonce,
            &derive_super_kek("master-pass", &salt)?
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn vault_v4_super_wraps_urk() -> AnyResult<()> {
        let salt = random_hex(16);
        let super_pass = generate_secret_key();
        let kek = derive_kek_v4(&super_pass, &salt)?;
        let urk = generate_key();
        let (nonce, wrapped) = wrap_key(&urk, &kek)?;
        assert_eq!(unwrap_key(&wrapped, &nonce, &derive_kek_v4(&super_pass, &salt)?)?, urk);
        assert!(unwrap_key(&wrapped, &nonce, &derive_kek_v4("A3-000000-000000-000000-000000-000000-000000", &salt)?).is_err());
        assert!(unwrap_key(&wrapped, &nonce, &derive_super_kek(&super_pass, &salt)?).is_err());
        Ok(())
    }
}
