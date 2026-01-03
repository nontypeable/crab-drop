pub trait KeyDerivation {
    fn derive(&self, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8>;
}
