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
