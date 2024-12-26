use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use sha2::{Sha256, Digest};
use redis::{Commands, RedisError};
use std::{sync::RwLock, time::{SystemTime, UNIX_EPOCH}};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

type HmacSha256 = Hmac<Sha256>;


lazy_static! {
    static ref PROVE_OF_WORK_SECRET: RwLock<String> = RwLock::new(get_or_create_prove_of_work_secret());
}

fn get_or_create_prove_of_work_secret() -> String {
    let client = match redis::Client::open("redis://127.0.0.1/") {
        Ok(client) => client,
        Err(_) => {
            return generate_random_secret();
        }
    };

    let mut con = match client.get_connection() {
        Ok(con) => con,
        Err(_) => {
            return generate_random_secret();
        }
    };

    let key = "rusty:prove_of_work_secret";

    let secret: Result<String, RedisError> = con.get(&key);

    match secret {
        Ok(existing_secret) => {
            existing_secret
        },
        Err(_) => {
            let new_secret = generate_random_secret();
            let _: Result<String, RedisError> = con.set(key, new_secret.clone());
            new_secret
        }
    }
}

pub(crate) fn get_pow() -> String {
    PROVE_OF_WORK_SECRET.read().unwrap().clone()
}

fn generate_random_secret() -> String {
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

pub struct PoW {
    pub secret: String,
    pub hardness: usize,
}

impl PoW {
    pub fn new(secret: String, hardness: usize) -> Self {
        PoW {
            secret,
            hardness,
        }
    }

    pub fn generate_challenge(&self, ip: &str) -> (String, String) {
        let challenge: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let signature_data = format!("{}:{}:{}", challenge, timestamp, ip);

        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .expect("HMAC creation failed");

        mac.update(signature_data.as_bytes());
        let hmac_result = mac.finalize().into_bytes();
        let signature = BASE64.encode(hmac_result);

        let final_signature = format!("{}:{}:{}", challenge, timestamp, signature);

        (challenge, final_signature)
    }

    pub fn verify_solution(&self, solution: &str, signature_string: &str, client_ip: &str) -> bool {
        let parts: Vec<&str> = signature_string.split(':').collect();
        if parts.len() != 3 {
            return false;
        }

        let (challenge, timestamp_str, signature) = (parts[0], parts[1], parts[2]);

        let timestamp = match timestamp_str.parse::<u64>() {
            Ok(ts) => ts,
            Err(_) => return false,
        };

        let current_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return false,
        };

        if current_time < timestamp || current_time - timestamp > 600 {
            return false;
        }

        let mut mac = match HmacSha256::new_from_slice(self.secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let signature_data = format!("{}:{}:{}", challenge, timestamp_str, client_ip);
        mac.update(signature_data.as_bytes());

        let received_signature = match BASE64.decode(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let expected_signature = mac.finalize().into_bytes();
        if expected_signature.as_slice() != received_signature.as_slice() {
            return false;
        }

        if solution.is_empty() {
            return false;
        }

        let target = "0".repeat(self.hardness);
        let mut hasher = Sha256::new();
        hasher.update(solution.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        if hash.len() < self.hardness {
            return false;
        }

        hash.starts_with(&target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_generate_challenge() {
        let iterations = 100_000;
        let pow = PoW::new("test_secret".to_string(), 2);

        println!("\nPoW generate challenge Benchmarks:");
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = pow.generate_challenge("127.0.0.1");
        }

        let avg_time = start.elapsed();
        let avg_time_per_iteration = avg_time / iterations;
        println!("Average time per iteration: {:?}", avg_time_per_iteration);
    }

    #[test]
    fn test_pow_verification() {
        let pow = PoW::new("test_secret".to_string(), 2);
        let ip = "127.0.0.1";

        let (challenge, signature) = pow.generate_challenge(ip);

        let mut nonce = 0u64;
        let mut solution: String;

        loop {
            solution = format!("{}{}", challenge, nonce);
            let mut hasher = Sha256::new();
            hasher.update(solution.as_bytes());
            let hash = format!("{:x}", hasher.finalize());

            if hash.starts_with("00") {
                break;
            }
            nonce += 1;
        }

        assert!(pow.verify_solution(&solution, &signature, ip));
    }

    #[test]
    fn test_error_cases() {
        let pow = PoW::new("test_secret".to_string(), 2);
        let ip = "127.0.0.1";

        assert!(!pow.verify_solution("solution", "invalid:signature", ip));

        let (_, signature) = pow.generate_challenge(ip);

        assert!(!pow.verify_solution("", &signature, ip));
        assert!(!pow.verify_solution("solution", "challenge:invalid_time:signature", ip));
        assert!(!pow.verify_solution("solution", &signature, "192.168.1.1"));
        assert!(!pow.verify_solution("solution", "challenge:1234567890:invalid_base64!", ip));
    }
}