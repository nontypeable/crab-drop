use crate::domain::errors::CryptoError;

pub trait AeadCipher {
    fn encrypt(&self, key: &[u8], nonce: &[u8],plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, key: &[u8], nonce: &[u8],ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
