use std::{net::SocketAddr, sync::Arc};

use axum::{routing::get, Router};
use hickory_resolver::config::ResolverConfig;
use hyper::{Body, Method, Request};
use log::{debug, trace, LevelFilter};
use tower::{make::Shared, ServiceExt};
use wildflower::Pattern;

mod dns;
mod hub;
mod tls;
mod utils;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter(None, LevelFilter::Trace)
        .is_test(true)
        .try_init()
        .unwrap();
    let blocked_address = vec![Pattern::new("*steamcommunity.com".to_string()), Pattern::new("*github.com".to_string())];
    let hub = hub::Hub::new(
        blocked_address,
        dns::DnsResolver::new(ResolverConfig::quad9_tls(), false),
    );
    let hub = Arc::new(hub);
    let router_svc = Router::new().route("/", get(|| async { "Hello, World!" }));

    let service = tower::service_fn(move |req: Request<_>| {
        debug!("request: {:?}", req);
        let hub = hub.clone();
        let router_svc = router_svc.clone();
        let req = req.map(Body::from);
        async move {
            if req.method() == Method::CONNECT {
                trace!("get CONNECT request");
                hub.proxy(req).await
            } else {
                router_svc.oneshot(req).await.map_err(|err| match err {})
            }
        }
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    hyper::Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(Shared::new(service))
        .await
        .unwrap();
}
