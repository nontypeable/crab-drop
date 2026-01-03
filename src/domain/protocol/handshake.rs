use crate::domain::protocol::message::{HandshakeInit, HandshakeResponse};
use crate::domain::{
    crypto::{AeadCipher, KeyDerivation, Nonce},
    errors::CryptoError,
};

pub struct Handshake<'a, A: AeadCipher, K: KeyDerivation> {
    pub aead: &'a A,
    pub kdf: &'a K,
}

impl<'a, A: AeadCipher, K: KeyDerivation> Handshake<'a, A, K> {
    pub fn initiate(&self, secret_phrase: &[u8]) -> Result<HandshakeInit, CryptoError> {
        let psk = self.kdf.derive(secret_phrase, b"psk-discovery", 32);
        let client_token = [0u8; 32];
        let nonce = Nonce([0u8; 12]);

        Ok(HandshakeInit {
            client_token,
            nonce,
        })
    }

    pub fn respond(&self, client_token: &[u8]) -> Result<HandshakeResponse, CryptoError> {
        let server_token = [0u8; 32];
        let nonce = Nonce([0u8; 12]);
        Ok(HandshakeResponse {
            server_token,
            nonce,
        })
    }

    pub fn derive_session_key(&self, client_token: &[u8], server_token: &[u8]) -> Vec<u8> {
        self.kdf
            .derive(&[client_token, server_token].concat(), b"session", 32)
    }
}
