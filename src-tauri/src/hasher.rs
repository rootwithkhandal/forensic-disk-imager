use sha2::{Digest, Sha256, Sha512};
use md5::Md5;
use sha1::Sha1;
use std::collections::HashMap;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

struct Worker {
    tx: UnboundedSender<Vec<u8>>,
    handle: JoinHandle<String>,
}

pub struct MultiHasher {
    workers: HashMap<HashAlgorithm, Worker>,
}

impl MultiHasher {
    pub fn new(algorithms: &[HashAlgorithm]) -> Self {
        let mut workers = HashMap::new();

        for algo in algorithms {
            let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
            let algo_clone = *algo;
            let handle = tokio::task::spawn_blocking(move || {
                match algo_clone {
                    HashAlgorithm::MD5 => {
                        let mut h = Md5::new();
                        while let Some(data) = rx.blocking_recv() {
                            h.update(&data);
                        }
                        hex::encode(h.finalize())
                    }
                    HashAlgorithm::SHA1 => {
                        let mut h = Sha1::new();
                        while let Some(data) = rx.blocking_recv() {
                            h.update(&data);
                        }
                        hex::encode(h.finalize())
                    }
                    HashAlgorithm::SHA256 => {
                        let mut h = Sha256::new();
                        while let Some(data) = rx.blocking_recv() {
                            h.update(&data);
                        }
                        hex::encode(h.finalize())
                    }
                    HashAlgorithm::SHA512 => {
                        let mut h = Sha512::new();
                        while let Some(data) = rx.blocking_recv() {
                            h.update(&data);
                        }
                        hex::encode(h.finalize())
                    }
                }
            });

            workers.insert(*algo, Worker { tx, handle });
        }

        Self { workers }
    }

    pub fn update(&mut self, data: &[u8]) {
        let vec = data.to_vec();
        for worker in self.workers.values() {
            let _ = worker.tx.send(vec.clone());
        }
    }

    pub async fn finalize(mut self) -> HashMap<HashAlgorithm, String> {
        let mut results = HashMap::new();
        let workers = std::mem::take(&mut self.workers);
        for (algo, worker) in workers {
            drop(worker.tx);
            if let Ok(hash_str) = worker.handle.await {
                results.insert(algo, hash_str);
            }
        }
        results
    }
}

pub fn generate_digital_signature(report_content: &str, case_number: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(report_content.as_bytes());
    hasher.update(case_number.as_bytes());
    hasher.update(b"FORGELENS-SECURE-FORENSIC-SIGNING-SALT-2026");
    hex::encode(hasher.finalize())
}


