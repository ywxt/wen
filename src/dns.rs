use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use hickory_resolver::{
    config::{LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    system_conf, TokioAsyncResolver,
};
use log::debug;

#[derive(Debug)]
pub struct DnsResolver {
    inner: TokioAsyncResolver,
}

impl DnsResolver {
    pub fn new(resolver_config: ResolverConfig, ipv6_supported: bool) -> Self {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = false;
        opts.cache_size = 128;
        opts.ip_strategy = if ipv6_supported {
            LookupIpStrategy::Ipv4thenIpv6
        } else {
            LookupIpStrategy::Ipv4Only
        };
        let inner = TokioAsyncResolver::tokio(resolver_config, opts);
        Self { inner }
    }
    #[cfg(any(unix, target_os = "windows"))]
    pub fn from_system_config(ipv6_supported: bool) -> anyhow::Result<Self> {
        let (conf, mut opts) = system_conf::read_system_conf()?;
        opts.cache_size = 128;
        opts.ip_strategy = if ipv6_supported {
            LookupIpStrategy::Ipv4thenIpv6
        } else {
            LookupIpStrategy::Ipv4Only
        };
        let inner =
            TokioAsyncResolver::new_with_conn(conf, opts, TokioConnectionProvider::default());
        Ok(Self { inner })
    }

    pub async fn lookup(&self, host: &str) -> anyhow::Result<IpAddr> {
        debug!("DnsResolver: DNS lookup {}", host);
        let lookup = self.inner.lookup_ip(host).await?;
        let result = lookup
            .into_iter()
            .next()
            .context("No IP found by DNS lookup");
        debug!("DnsResolver: DNS lookup result: {:?}", result);
        result
    }
}

/// DNS server
///
/// This is a simplified version of `NameServerConfig` from `hickory_resolver` crate
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServer {
    Udp {
        address: SocketAddr,
    },
    Tls {
        address: SocketAddr,
        dns_name: String,
    },
    Https {
        address: SocketAddr,
        dns_name: String,
    },
}

/// Create a resolver config from a list of DNS servers.
///
/// Please ensure certificates included in `tls_config` are trusted by your system.
pub fn create_resolver_config(dns_servers: impl IntoIterator<Item = DnsServer>) -> ResolverConfig {
    let group: Vec<NameServerConfig> = dns_servers
        .into_iter()
        .map(|dns_server| match dns_server {
            DnsServer::Udp { address } => NameServerConfig {
                socket_addr: address,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
                tls_config: None,
            },
            DnsServer::Tls { address, dns_name } => NameServerConfig {
                socket_addr: address,
                protocol: Protocol::Tls,
                tls_dns_name: Some(dns_name),
                trust_negative_responses: true,
                bind_addr: None,
                tls_config: None,
            },
            DnsServer::Https { address, dns_name } => NameServerConfig {
                socket_addr: address,
                protocol: Protocol::Https,
                tls_dns_name: Some(dns_name),
                trust_negative_responses: true,
                tls_config: None,
                bind_addr: None,
            },
        })
        .collect();
    ResolverConfig::from_parts(None, vec![], group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    #[tokio::test]
    async fn test_lookup_ipv6() {
        let config = ResolverConfig::quad9_tls();
        let resolver = DnsResolver::new(config, true);
        let ip = resolver.lookup("ipv6.lookup.test-ipv6.com").await.unwrap();
        assert!(
            ip == IpAddr::V6(Ipv6Addr::from_str("2a00:dd80:3c::b3f").unwrap())
                || ip == IpAddr::V6(Ipv6Addr::from_str("2001:470:1:18::223:250").unwrap())
        );
    }

    #[tokio::test]
    async fn test_lookup_ipv4() {
        let config = ResolverConfig::google_tls();
        let resolver = DnsResolver::new(config, false);
        let ip = resolver.lookup("ipv4.lookup.test-ipv6.com").await.unwrap();
        println!("{:?}", ip);
        assert!(
            ip == IpAddr::V4(Ipv4Addr::new(176, 58, 89, 223))
                || ip == IpAddr::V4(Ipv4Addr::new(216, 218, 223, 250))
        );
    }
}
