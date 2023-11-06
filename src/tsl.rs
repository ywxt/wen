use std::net::SocketAddr;

use native_tls::TlsConnector;
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

pub async fn connect_without_sni(
    addr: SocketAddr,
    domain: &str,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::builder()
        .use_sni(false)
        .danger_accept_invalid_certs(true)
        .build()?;
    let connector = tokio_native_tls::TlsConnector::from(connector);
    let stream = TcpStream::connect(addr).await?;
    let stream = connector.connect(domain, stream).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_connect_without_sni() {
        let addr = SocketAddr::from(([23, 49, 124, 204], 443));
        let domain = "steamcommunity.com";
        let mut stream = super::connect_without_sni(addr, domain).await.unwrap();
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
