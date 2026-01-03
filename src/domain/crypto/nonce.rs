#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
