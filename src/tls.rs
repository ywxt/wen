use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use rustls::{ClientConfig, RootCertStore, ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

pub async fn connect_with_client_config(
    addr: SocketAddr,
    domain: &str,
    client_config: impl Into<Arc<ClientConfig>>,
) -> anyhow::Result<impl AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    let connector = TlsConnector::from(client_config.into());
    let stream = TcpStream::connect(addr).await?;
    let stream = connector
        .connect(
            ServerName::try_from(domain).with_context(|| format!("Invalid domain: {}", domain))?,
            stream,
        )
        .await?;
    Ok(stream)
}

pub fn load_native_root_certificates() -> RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(&rustls_native_certs::load_native_certs().expect("Could not load platform certs."));
    
    roots
}

pub fn create_client_config(
    root_store: impl Into<Arc<RootCertStore>>,
    enable_sni: bool,
) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_sni = enable_sni;
    config
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_connect_without_sni() {
        let addr = SocketAddr::from(([23, 49, 124, 204], 443));
        let root_store = super::load_native_root_certificates();
        let client_config = super::create_client_config(root_store, false);
        let domain = "steamcommunity.com";
        let mut stream = super::connect_with_client_config(addr, domain, client_config)
            .await
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: steamcommunity.com\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 200 OK");
        stream.shutdown().await.unwrap();
    }
}
