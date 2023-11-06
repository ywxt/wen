use std::net::IpAddr;

use anyhow::Context;
use hickory_resolver::{
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    system_conf, TokioAsyncResolver,
};

#[derive(Debug)]
pub struct DnsResolver {
    ipv6_supported: bool,
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
        Self {
            ipv6_supported,
            inner,
        }
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
        Ok(Self {
            ipv6_supported,
            inner,
        })
    }

    pub fn ipv6_supported(&self) -> bool {
        self.ipv6_supported
    }

    pub async fn lookup(&self, host: &str) -> anyhow::Result<IpAddr> {
        let lookup = self.inner.lookup_ip(host).await?;
        lookup
            .into_iter()
            .next()
            .context("No IP found by DNS lookup")
    }
}
