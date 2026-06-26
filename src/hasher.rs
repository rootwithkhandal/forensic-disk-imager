use sha2::{Digest, Sha256, Sha512};
use md5::Md5;
use sha1::Sha1;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

pub struct MultiHasher {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
}

impl MultiHasher {
    pub fn new(algorithms: &[HashAlgorithm]) -> Self {
        let mut md5 = None;
        let mut sha1 = None;
        let mut sha256 = None;
        let mut sha512 = None;

        for algo in algorithms {
            match algo {
                HashAlgorithm::MD5 => md5 = Some(Md5::new()),
                HashAlgorithm::SHA1 => sha1 = Some(Sha1::new()),
                HashAlgorithm::SHA256 => sha256 = Some(Sha256::new()),
                HashAlgorithm::SHA512 => sha512 = Some(Sha512::new()),
            }
        }

        Self {
            md5,
            sha1,
            sha256,
            sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if let Some(ref mut h) = self.md5 {
            h.update(data);
        }
        if let Some(ref mut h) = self.sha1 {
            h.update(data);
        }
        if let Some(ref mut h) = self.sha256 {
            h.update(data);
        }
        if let Some(ref mut h) = self.sha512 {
            h.update(data);
        }
    }

    pub fn finalize(self) -> HashMap<HashAlgorithm, String> {
        let mut results = HashMap::new();

        if let Some(h) = self.md5 {
            results.insert(HashAlgorithm::MD5, hex::encode(h.finalize()));
        }
        if let Some(h) = self.sha1 {
            results.insert(HashAlgorithm::SHA1, hex::encode(h.finalize()));
        }
        if let Some(h) = self.sha256 {
            results.insert(HashAlgorithm::SHA256, hex::encode(h.finalize()));
        }
        if let Some(h) = self.sha512 {
            results.insert(HashAlgorithm::SHA512, hex::encode(h.finalize()));
        }

        results
    }
}
