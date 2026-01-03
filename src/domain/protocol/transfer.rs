use crate::domain::crypto::{AeadCipher, Nonce};
use crate::domain::errors::CryptoError;
use crate::domain::protocol::message::{FileAck, FileChunk};

pub struct FileTransfer<'a, A: AeadCipher> {
    pub aead: &'a A,
}

impl<'a, A: AeadCipher> FileTransfer<'a, A> {
    pub fn encrypt_chunk(
        &self,
        session_key: &[u8],
        index: u64,
        data: &[u8],
        nonce: Nonce,
    ) -> Result<FileChunk, CryptoError> {
        let aad = index.to_le_bytes();
        let ciphertext = self
            .aead
            .encrypt(session_key, nonce.as_bytes(), data, &aad)?;
        Ok(FileChunk {
            index,
            data: ciphertext,
            nonce,
        })
    }

    pub fn verify_chunk(&self, chunk: &FileChunk, expected_hash: &[u8]) -> bool {
        expected_hash == chunk.data.as_slice()
    }

    pub fn ack_chunk(&self, chunk: &FileChunk) -> FileAck {
        FileAck {
            index: chunk.index,
            hash: chunk.data.clone(),
            nonce: chunk.nonce.clone(),
        }
    }
}
