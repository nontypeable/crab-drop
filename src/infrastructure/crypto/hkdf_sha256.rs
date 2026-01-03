use crate::domain::crypto::KeyDerivation;
use hkdf::Hkdf;
use sha2::Sha256;

pub struct HkdfSha256;

impl KeyDerivation for HkdfSha256 {
    fn derive(&self, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, ikm);

        let mut okm: Vec<u8> = vec![0u8; len];
        hk.expand(&info, &mut okm)
            .expect("42 is a valid length for Sha256 to output");

        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::crypto::KeyDerivation;

    #[test]
    fn hkdf_sha256_derives_correct_length() {
        let kdf = HkdfSha256;
        let ikm = b"input key material";
        let info = b"context info";

        let out_len = 32;
        let okm = kdf.derive(ikm, info, out_len);

        assert_eq!(okm.len(), out_len);
    }

    #[test]
    fn hkdf_sha256_is_deterministic() {
        let kdf = HkdfSha256;
        let ikm = b"same input key material";
        let info = b"same info";

        let okm1 = kdf.derive(ikm, info, 32);
        let okm2 = kdf.derive(ikm, info, 32);

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn hkdf_sha256_produces_different_output_for_different_info() {
        let kdf = HkdfSha256;
        let ikm = b"some ikm";

        let okm1 = kdf.derive(ikm, b"info1", 32);
        let okm2 = kdf.derive(ikm, b"info2", 32);

        assert_ne!(okm1, okm2);
    }

    #[test]
    fn hkdf_sha256_produces_different_output_for_different_ikm() {
        let kdf = HkdfSha256;
        let info = b"context info";

        let okm1 = kdf.derive(b"ikm1", info, 32);
        let okm2 = kdf.derive(b"ikm2", info, 32);

        assert_ne!(okm1, okm2);
    }
}
