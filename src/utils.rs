use url::Url;
use redis::{Client, Commands, RedisError};
use sha2::{Sha256, Digest};
use std::error::Error;

pub(crate) fn get_domain_host(request_url: String) -> String {
    let host = match Url::parse(&*request_url) {
        Ok(url) => {
            let mut host = url.host_str().unwrap_or("");
            if let Some(pos) = host.find(':') {
                host = &host[..pos];
            }
            host.to_string()
        }
        Err(_) => "".to_string(),
    };

    let mut host = if host.is_empty() || host == "localhost" {
        "localhost".to_string()
    } else {
        host
    };

    let parts: Vec<&str> = host.split('.').collect();

    if host.len() > 20 || parts.iter().any(|&part| part.len() > 10) {
        host = parts.iter()
            .rev()
            .take(2)
            .map(|&part| part)
            .collect::<Vec<_>>()
            .join(".");
    }

    host
}

pub(crate) fn append_query_prefix(request_url: &str) -> String {
    let mut updated_url = String::from(request_url);

    if updated_url.contains('?') {
        updated_url.push('&');
    } else {
        updated_url.push('?');
    }

    updated_url
}

pub struct CacheHandler {
    client: Client,
    prefix: String,
}

impl CacheHandler {
    pub fn new(redis_url: &str, prefix: &str) -> Result<Self, RedisError> {
        let client = Client::open(redis_url)?;
        Ok(CacheHandler {
            client,
            prefix: prefix.to_string(),
        })
    }

    fn hash_field_value(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn build_cache_key(&self, cache_key: &str, field_value: &str) -> String {
        format!("{}:{}:{}", self.prefix, cache_key, self.hash_field_value(field_value))
    }

    pub fn get_cached_bool(&self, cache_key: &str, field_value: &str) -> Result<Option<bool>, Box<dyn Error>> {
        let mut con = self.client.get_connection()?;
        let full_key = self.build_cache_key(cache_key, field_value);

        let result: Option<String> = con.get(&full_key)?;
        Ok(result.map(|v| v == "1"))
    }

    pub fn set_cached_bool(&self, cache_key: &str, field_value: &str, value: bool, ttl: usize) -> Result<(), Box<dyn Error>> {
        let mut con = self.client.get_connection()?;
        let full_key = self.build_cache_key(cache_key, field_value);
        let value_str = if value { "1" } else { "0" };

        con.set_ex::<String, &str, u64>(full_key, value_str, ttl as u64)?;
        Ok(())
    }
}
