use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use reqwest;
use std::error::Error;
use chrono::{Utc, Duration};
use serde_json::Value;
use url::Url;
use dns_lookup::lookup_host;
use crate::utils::CacheHandler;

const TTL: usize = 28800;

pub fn is_valid_public_ip(ip_address: &str) -> bool {
    let ip = match ip_address.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(ipv4) => is_valid_public_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_valid_public_ipv6(ipv6),
    }
}

fn is_valid_public_ipv4(ip: Ipv4Addr) -> bool {
    !(
        ip.is_private()           || // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        ip.is_loopback()          || // 127.0.0.0/8
        ip.is_link_local()        || // 169.254.0.0/16
        ip.is_broadcast()         || // 255.255.255.255
        ip.is_documentation()     || // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        ip.is_unspecified()       || // 0.0.0.0
        ip.is_multicast()         || // 224.0.0.0/4
        ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0 || // 192.0.0.0/24
        ip.octets()[0] == 198 && ip.octets()[1] == 18 && ip.octets()[2] == 0    // 198.18.0.0/15
    )
}

fn is_valid_public_ipv6(ip: Ipv6Addr) -> bool {
    !(
        ip.is_loopback()          || // ::1
        ip.is_unspecified()       || // ::
        ip.is_multicast()         || // ff00::/8
        is_documentation_ipv6(ip) || // 2001:db8::/32
        is_unique_local(ip)       || // fc00::/7
        is_link_local(ip)            // fe80::/10
    )
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    let first_byte = ip.octets()[0];
    first_byte & 0xfe == 0xfc
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    let first_byte = ip.octets()[0];
    let second_byte = ip.octets()[1];
    first_byte == 0xfe && (second_byte & 0xc0) == 0x80
}

fn is_documentation_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0xdb8
}

fn is_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok()
}

pub struct IpChecker {
    cache: CacheHandler,
    http_client: reqwest::Client,
}

impl IpChecker {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn Error>> {
        let cache = CacheHandler::new(redis_url, "rusty")?;
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()?;

        Ok(IpChecker {
            cache,
            http_client,
        })
    }

    pub async fn is_ip_malicious_ipapi(&self, ip_address: &str) -> Option<bool> {
        if let Ok(Some(cached)) = self.cache.get_cached_bool("ipapi", ip_address) {
            return Some(cached);
        }

        let url = format!(
            "http://ip-api.com/json/{}?fields=proxy,hosting",
            ip_address
        );

        let response = match self.http_client.get(&url).send().await {
            Ok(resp) => resp,
            Err(_) => return None,
        };

        let data: Value = match response.json().await {
            Ok(data) => data,
            Err(_) => return None,
        };

        for key in ["proxy", "hosting"].iter() {
            if let Some(value) = data.get(key) {
                if value.as_bool() == Some(true) {
                    let _ = self.cache.set_cached_bool("ipapi", ip_address, true, TTL);
                    return Some(true);
                }
            }
        }

        if !data.get("proxy").is_some() && !data.get("hosting").is_some() {
            return None;
        }

        let _ = self.cache.set_cached_bool("ipapi", ip_address, false, TTL);
        Some(false)
    }

    pub async fn is_ip_tor_exonerator(&self, ip_address: &str) -> Option<bool> {
        if let Ok(Some(cached)) = self.cache.get_cached_bool("tor_exonerator", ip_address) {
            return Some(cached);
        }

        let today = (Utc::now() - Duration::days(2)).format("%Y-%m-%d").to_string();

        let url = Url::parse_with_params(
            "https://metrics.torproject.org/exonerator.html",
            &[
                ("ip", ip_address),
                ("timestamp", &today),
                ("lang", "en"),
            ],
        ).ok()?;

        let response = match self.http_client
            .get(url.as_str())
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
            .header("Range", "bytes=0-")
            .send()
            .await {
            Ok(resp) => resp,
            Err(_) => {
                let _ = self.cache.set_cached_bool("tor_exonerator", ip_address, true, TTL);
                return Some(true);
            }
        };

        let text = match response.text().await {
            Ok(text) => text,
            Err(_) => {
                let _ = self.cache.set_cached_bool("tor_exonerator", ip_address, true, TTL);
                return Some(true);
            }
        };

        let result_is_positive = text.contains("Result is positive");
        let _ = self.cache.set_cached_bool("tor_exonerator", ip_address, result_is_positive, TTL);

        Some(result_is_positive)
    }

    pub async fn is_ipv4_tor(&self, ip_address: &str) -> Option<bool> {
        if let Ok(Some(cached)) = self.cache.get_cached_bool("tor_hostname", ip_address) {
            return Some(cached);
        }

        if ip_address.is_empty() {
            return None;
        }

        let reversed_ip: String = ip_address.split('.')
            .rev()
            .collect::<Vec<&str>>()
            .join(".");
        let query = format!("{}.dnsel.torproject.org", reversed_ip);

        match lookup_host(&query) {
            Ok(ips) => {
                for ip in ips {
                    if ip.to_string() == "127.0.0.2" {
                        let _ = self.cache.set_cached_bool("tor_hostname", ip_address, true, TTL);
                        return Some(true);
                    }
                }
            }
            Err(_) => {
                let _ = self.cache.set_cached_bool("tor_hostname", ip_address, false, TTL);
                return Some(false);
            }
        }

        let _ = self.cache.set_cached_bool("tor_hostname", ip_address, false, TTL);
        Some(false)
    }

    pub async fn is_ip_malicious(&self, ip_address: &str) -> Option<String> {
        if !is_valid_public_ip(ip_address) {
            return Some("Invalid".to_string());
        }

        let is_malicious = self.is_ip_malicious_ipapi(ip_address).await;
        let is_tor_exonerator = self.is_ip_tor_exonerator(ip_address).await;

        let mut is_tor_v4 = None;
        if is_ipv4(ip_address) {
            is_tor_v4 = self.is_ipv4_tor(ip_address).await;
        }

        let checks = vec![
            ("Malicious", is_malicious),
            ("TOR", is_tor_exonerator),
            ("TORv4", is_tor_v4),
        ];

        for (name, result) in checks {
            if result == Some(true) {
                return Some(name.to_string());
            }
        }

        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn run_benchmark(ip: &str, iterations: u32) -> Duration {
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = is_valid_public_ip(ip);
        }
        start.elapsed() / iterations
    }

    #[test]
    fn benchmark_ipv4_valid() {
        let iterations = 100_000;
        let ips = [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.1",
        ];

        println!("\nIPv4 Valid Address Benchmarks:");
        for ip in ips {
            let avg_time = run_benchmark(ip, iterations);
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[test]
    fn benchmark_ipv4_invalid() {
        let iterations = 100_000;
        let ips = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
        ];

        println!("\nIPv4 Invalid Address Benchmarks:");
        for ip in ips {
            let avg_time = run_benchmark(ip, iterations);
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[test]
    fn benchmark_ipv6_valid() {
        let iterations = 100_000;
        let ips = [
            "2606:4700:4700::1111",
            "2404:6800:4003:c00::64",
            "2001:0db7:85a3::8a2e:0370:7334",
        ];

        println!("\nIPv6 Valid Address Benchmarks:");
        for ip in ips {
            let avg_time = run_benchmark(ip, iterations);
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[test]
    fn benchmark_ipv6_invalid() {
        let iterations = 100_000;
        let ips = [
            "2001:db8::1",
            "fe80::1234:5678",
            "fc00::1",
        ];

        println!("\nIPv6 Invalid Address Benchmarks:");
        for ip in ips {
            let avg_time = run_benchmark(ip, iterations);
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[test]
    fn benchmark_invalid_format() {
        let iterations = 100_000;
        let ips = [
            "invalid",
            "256.256.256.256",
            "2001:xyz::1",
        ];

        println!("\nInvalid Format Benchmarks:");
        for ip in ips {
            let avg_time = run_benchmark(ip, iterations);
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[actix_rt::test]
    async fn benchmark_ipv4_tor() {
        let ip_checker = IpChecker::new("redis://127.0.0.1/").unwrap();

        // Before testing, gather new IP addresses, as some of these
        // may be inactive and no longer considered valid TOR exit nodes.
        let ips = [
            "92.246.84.133",
            "178.20.55.182",
            "195.47.238.91",
            "185.220.101.52"
        ];

        println!("\nIPv4 TOR Hostname Benchmarks:");
        for ip in ips {
            let start = Instant::now();
            for _ in 0..100_000 {
                let _ = ip_checker.is_ipv4_tor(ip).await;
            }
            let avg_time = start.elapsed() / 100_000;
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[actix_rt::test]
    async fn benchmark_ip_tor_exonerator() {
        let ip_checker = IpChecker::new("redis://127.0.0.1/").unwrap();

        // Before testing, gather new IP addresses, as some of these
        // may be inactive and no longer considered valid TOR exit nodes.
        let ips = [
            "92.246.84.133",
            "178.20.55.182",
            "2a0d:c2c0:1:4::2",
            "2a00:1b88:4::4"
        ];

        println!("\nIP TOR Exonerator Benchmarks:");
        for ip in ips {
            let start = Instant::now();
            for _ in 0..100_000 {
                let _ = ip_checker.is_ip_tor_exonerator(ip).await;
            }
            let avg_time = start.elapsed() / 100_000;
            println!("IP: {:<15} Average time: {:?}", ip, avg_time);
        }
    }

    #[actix_rt::test]
    async fn test_ipv4_tor() {
        let ip_checker = IpChecker::new("redis://127.0.0.1/").unwrap();

        // Residential IP
        assert!(
            !ip_checker.is_ipv4_tor("75.123.45.67").await.expect("Failed to check residential IP address"),
            "Residential IP address was incorrectly identified as a Tor exit node"
        );

        // Cloudflare Public DNS
        assert!(
            !ip_checker.is_ipv4_tor("1.1.1.1").await.expect("Failed to check Cloudflare DNS IP address"),
            "Cloudflare Public DNS IP address was incorrectly identified as a Tor exit node"
        );

        // Google Public DNS
        assert!(
            !ip_checker.is_ipv4_tor("8.8.8.8").await.expect("Failed to check Google DNS IP address"),
            "Google Public DNS IP address was incorrectly identified as a Tor exit node"
        );

        // IPv6 Address
        assert!(
            !ip_checker.is_ipv4_tor("2a0d:c2c0:1:4::2").await.expect("Failed to check IPv6 address"),
            "IPv6 address was incorrectly processed by IPv4 Tor checker"
        );

        // Before testing, gather new IP addresses, as some of these
        // may be inactive and no longer considered valid TOR exit nodes.
        assert!(
            ip_checker.is_ipv4_tor("92.246.84.133").await.expect("Failed to check known Tor exit node"),
            "Known Tor exit node was not correctly identified"
        );
        assert!(
            ip_checker.is_ipv4_tor("178.20.55.182").await.expect("Failed to check known Tor exit node"),
            "Known Tor exit node was not correctly identified"
        );
        assert!(
            ip_checker.is_ipv4_tor("195.47.238.91").await.expect("Failed to check known Tor exit node"),
            "Known Tor exit node was not correctly identified"
        );
        assert!(
            ip_checker.is_ipv4_tor("185.220.101.52").await.expect("Failed to check known Tor exit node"),
            "Known Tor exit node was not correctly identified"
        );
    }

    #[actix_rt::test]
    async fn test_tor_exonerator() {
        let ip_checker = IpChecker::new("redis://127.0.0.1/").unwrap();

        // Residential IP
        assert!(
            !ip_checker.is_ip_tor_exonerator("75.123.45.67").await.expect("Failed to check residential IP address"),
            "Residential IP address was incorrectly identified as a Tor exit node"
        );

        // Cloudflare Public DNS
        assert!(
            !ip_checker.is_ip_tor_exonerator("1.1.1.1").await.expect("Failed to check Cloudflare DNS IP address"),
            "Cloudflare Public DNS IP address was incorrectly identified as a Tor exit node"
        );

        // Google Public DNS
        assert!(
            !ip_checker.is_ip_tor_exonerator("8.8.8.8").await.expect("Failed to check Google DNS IP address"),
            "Google Public DNS IP address was incorrectly identified as a Tor exit node"
        );

        // Cloudflare Public DNS
        assert!(
            !ip_checker.is_ip_tor_exonerator("2606:4700:4700::1111").await.expect("Failed to check Cloudflare DNS IP address"),
            "Cloudflare Public DNS IPv6 address was incorrectly identified as a Tor exit node"
        );

        // Google Public DNS
        assert!(
            !ip_checker.is_ip_tor_exonerator("2001:4860:4860::8888").await.expect("Failed to check IPv6 address"),
            "Google Public DNS IPv6 address was incorrectly identified as a Tor exit node"
        );

        // OpenDNS Public DNS
        assert!(
            !ip_checker.is_ip_tor_exonerator("2620:119:35::35").await.expect("Failed to check IPv6 address"),
            "OpenDNS Public DNS IPv6 address was incorrectly identified as a Tor exit node"
        );

        // Before testing, gather new IP addresses, as some of these
        // may be inactive and no longer considered valid TOR exit nodes.
        assert!(
            ip_checker.is_ip_tor_exonerator("92.246.84.133").await.expect("Failed to check IPv4 address in Tor exonerator"),
            "Known Tor exit node was not found in exonerator database"
        );
        assert!(
            ip_checker.is_ip_tor_exonerator("178.20.55.182").await.expect("Failed to check IPv4 address in Tor exonerator"),
            "Known Tor exit node was not found in exonerator database"
        );
        assert!(
            ip_checker.is_ip_tor_exonerator("2a0d:c2c0:1:4::2").await.expect("Failed to check IPv6 address in Tor exonerator"),
            "Known IPv6 Tor exit node was not found in exonerator database"
        );
        assert!(
            ip_checker.is_ip_tor_exonerator("2a00:1b88:4::4").await.expect("Failed to check IPv6 address in Tor exonerator"),
            "Known IPv6 Tor exit node was not found in exonerator database"
        );
    }

    #[test]
    fn test_valid_public_ipv4() {
        assert!(is_valid_public_ip("203.0.114.0"));
        assert!(is_valid_public_ip("8.8.8.8"));
        assert!(is_valid_public_ip("1.1.1.1"));
    }

    #[test]
    fn test_invalid_ipv4() {
        assert!(!is_valid_public_ip("10.0.0.1"));        // Private
        assert!(!is_valid_public_ip("127.0.0.1"));       // Loopback
        assert!(!is_valid_public_ip("192.168.1.1"));     // Private
        assert!(!is_valid_public_ip("169.254.0.1"));     // Link local
        assert!(!is_valid_public_ip("224.0.0.1"));       // Multicast
        assert!(!is_valid_public_ip("0.0.0.0"));         // Unspecified
        assert!(!is_valid_public_ip("255.255.255.255")); // Broadcast
        assert!(!is_valid_public_ip("not an ip"));       // Invalid format
    }

    #[test]
    fn test_valid_public_ipv6() {
        assert!(is_valid_public_ip("2001:0db7:85a3:0000:0000:8a2e:0370:7334")); // Valid public address
        assert!(is_valid_public_ip("2606:4700:4700::1111")); // Cloudflare DNS
        assert!(is_valid_public_ip("2404:6800:4003:c00::64")); // Google
    }

    #[test]
    fn test_invalid_ipv6() {
        assert!(!is_valid_public_ip("::1"));                 // Loopback
        assert!(!is_valid_public_ip("::\""));                // Unspecified
        assert!(!is_valid_public_ip("fe80::1234:5678"));     // Link-local
        assert!(!is_valid_public_ip("fc00::1"));             // Unique local
        assert!(!is_valid_public_ip("ff00::1"));             // Multicast
        assert!(!is_valid_public_ip("2001:db8::1"));         // Documentation
    }
}