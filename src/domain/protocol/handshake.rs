use crate::domain::protocol::message::{HandshakeInit, HandshakeResponse};

pub trait Handshake {
    fn initiate(&self) -> HandshakeInit;
    fn respond(&self, init: &HandshakeInit) -> HandshakeResponse;
    fn derive_session_key(&self, client_token: &[u8; 32], server_token: &[u8; 32]) -> [u8; 32];
}
