use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::domain::{crypto::AeadCipher, errors::CryptoError};

pub struct ChaCha20Poly1305Cipher;

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::AeadCipher;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = ChaCha20Poly1305Cipher;

        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"some plaintext";
        let aad = b"some aad";

        let ciphertext = cipher
            .encrypt(&key, &nonce, plaintext, aad)
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt(&key, &nonce, &ciphertext, aad)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_fails_with_invalid_key_length() {
        let cipher = ChaCha20Poly1305Cipher;

        let key = [0u8; 16]; // invalid key length
        let nonce = [1u8; 12];
        let plaintext = b"some plaintext";
        let aad = b"some aad";

        let err = cipher
            .encrypt(&key, &nonce, plaintext, aad)
            .expect_err("encryption should fail");

        assert!(matches!(err, CryptoError::InvalidKeyLength));
    }

    #[test]
    fn encrypt_fails_with_invalid_nonce_length() {
        let cipher = ChaCha20Poly1305Cipher;

        let key = [0u8; 32];
        let nonce = [0u8; 8]; // invalid nonce length
        let plaintext = b"some plaintext";
        let aad = b"some aad";

        let err = cipher
            .encrypt(&key, &nonce, plaintext, aad)
            .expect_err("encryption should fail");

        assert!(matches!(err, CryptoError::InvalidNonce));
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let cipher = ChaCha20Poly1305Cipher;

        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = cipher
            .encrypt(&key, &nonce, plaintext, aad)
            .expect("encryption should succeed");

        let err = cipher
            .decrypt(&key, &nonce, &ciphertext, wrong_aad)
            .expect_err("decryption should fail");

        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn decrypt_fails_when_ciphertext_is_modified() {
        let cipher = ChaCha20Poly1305Cipher;

        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"";
        let aad = b"chunk-1";

        let mut ciphertext = cipher
            .encrypt(&key, &nonce, plaintext, aad)
            .expect("encryption should succeed");

        ciphertext[0] ^= 0xff; // corrupt ciphertext

        let err = cipher
            .decrypt(&key, &nonce, &ciphertext, aad)
            .expect_err("decryption should fail");

        assert!(matches!(err, CryptoError::DecryptionFailed));
    }
}
