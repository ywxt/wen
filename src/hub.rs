use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use hyper::{upgrade::Upgraded, Request};
use log::{trace, info, error};
use std::sync::Arc;
use wildflower::Pattern;

use crate::{dns, tls::Connection};

pub struct Hub {
    blocked_address: Vec<Pattern<String>>,
    dns_resolver: dns::DnsResolver,
}

impl Hub {
    pub fn new(blocked_address: Vec<Pattern<String>>, dns_resolver: dns::DnsResolver) -> Self {
        Self {
            blocked_address,
            dns_resolver,
        }
    }

    pub async fn proxy(self: Arc<Self>, req: Request<Body>) -> Result<Response, hyper::Error> {
        if let Some((address, Some(port))) = req
            .uri()
            .authority()
            .map(|auth| (auth.host().to_string(), auth.port_u16()))
        {
            tokio::task::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    info!("upgrade to http proxy");
                    if let Err(err) = self.tunnel(upgraded, (address, port)).await {
                        trace!("tunnel error: {}", err);
                    }
                } else {
                    error!("upgrade to http proxy failed");
                }
            });

            Ok(Response::default())
        } else {
            Ok((
                StatusCode::BAD_REQUEST,
                "CONNECT must be to a socket address",
            )
                .into_response())
        }
    }

    async fn tunnel(&self, upgraded: Upgraded, address: (String, u16)) -> anyhow::Result<()> {
        info!("tunneling to {}:{}", address.0, address.1);
        let ip = self.dns_resolver.lookup(&address.0).await?;
        info!("resolved {} to {}", address.0, ip);
        let stream = tokio::net::TcpStream::connect((ip, address.1)).await?;
        info!("connected to {}:{}", ip, address.1);
        let mut connection = Connection::upgrade(upgraded).await?;
        if self
            .blocked_address
            .iter()
            .any(|rule| rule.matches(&address.0) || rule.matches(&ip.to_string()))
        {
            info!("remove sni from tls: {}", address.0);
            connection.remove_server_name(|_| true);
        }
        info!(
            "start transmit data between local and {}:{}",
            address.0,
            address.1
        );
        connection.bi_transmit(stream).await?;
        Ok(())
    }
}
