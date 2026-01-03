use crate::domain::crypto::KeyDerivation;
use hkdf::Hkdf;
use sha2::Sha256;

pub struct HkdfSha256;

impl KeyDerivation for HkdfSha256 {
    fn derive(&self, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, ikm);

        let mut okm: Vec<u8> = Vec::with_capacity(len);
        hk.expand(&info, &mut okm)
            .expect("42 is a valid length for Sha256 to output");

        okm
    }
}
