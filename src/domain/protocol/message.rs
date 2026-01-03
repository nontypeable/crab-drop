use crate::domain::crypto::Nonce;

#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub client_token: [u8; 32],
    pub nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub server_token: [u8; 32],
    pub nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct FileChunk {
    pub index: u64,
    pub data: Vec<u8>,
    pub nonce: Nonce,
}

#[derive(Debug, Clone)]
pub struct FileAck {
    pub index: u64,
    pub hash: Vec<u8>,
    pub nonce: Nonce,
}
