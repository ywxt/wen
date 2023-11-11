use std::io::Cursor;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::utils::u32_to_tls_handshake_len;

#[derive(Debug)]
pub struct Connection<S> {
    stream: S,
    inner: SocketConnection,
    buffer: Vec<u8>,
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Removes the server name if the connection TLS connection.
    pub fn remove_server_name(&mut self, removed: impl Fn(&Vec<(u8, String)>) -> bool) {
        if let SocketConnection::TlsConnection(ref mut tls) = self.inner {
            tls.remove_server_name(removed);
        }
    }

    async fn receive_client_hello(stream: &mut S) -> Result<TlsConnection, TlsConnectionError> {
        TlsConnection::read(stream).await
    }

    pub async fn upgrade(stream: S) -> std::io::Result<Self> {
        let mut stream = stream;
        let tls_connection = Self::receive_client_hello(&mut stream).await;
        match tls_connection {
            Ok(tls_connection) => Ok(Self {
                stream,
                inner: SocketConnection::TlsConnection(tls_connection),
                buffer: Vec::new(),
            }),
            Err(TlsConnectionError::NotTlsConnection(header)) => Ok(Self {
                stream,
                inner: SocketConnection::TcpConnection,
                buffer: header,
            }),
            Err(TlsConnectionError::Io(err)) => Err(err),
        }
    }

    pub async fn bi_transmit<W>(&mut self, mut remote: W) -> std::io::Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
    {
        match &mut self.inner {
            SocketConnection::TlsConnection(tls_connection) => {
                tls_connection.write(&mut remote).await?
            }
            SocketConnection::TcpConnection => remote.write_all(&self.buffer).await?,
        }
        tokio::io::copy_bidirectional(&mut self.stream, &mut remote).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum SocketConnection {
    TlsConnection(TlsConnection),
    TcpConnection,
}

#[derive(Debug, Error)]
pub enum TlsConnectionError {
    #[error("Not a TLS connection")]
    NotTlsConnection(Vec<u8>),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct TlsConnection {
    pub protocol_version: u16,
    pub client_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl TlsConnection {
    const TLS_HANDSHAKE_RECORD: u8 = 0x16;
    const TLS_VERSION_VERIFICATION: u16 = 0x0300;
    const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
    const TLS_STRICT_LENGTH: usize = 512;

    pub fn remove_server_name(&mut self, removed: impl Fn(&Vec<(u8, String)>) -> bool) {
        self.extensions.retain(
            |extension| !matches!(extension, Extension::ServerName(names) if removed(names)),
        );
    }

    pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Self, TlsConnectionError> {
        let mut pre_read = Vec::with_capacity(11);
        let record_type = stream.read_u8().await?;
        pre_read.push(record_type);
        if record_type != Self::TLS_HANDSHAKE_RECORD {
            return Err(TlsConnectionError::NotTlsConnection(pre_read));
        }
        let protocol_version = stream.read_u16().await?;
        pre_read.extend_from_slice(&protocol_version.to_be_bytes());
        if protocol_version & Self::TLS_VERSION_VERIFICATION != Self::TLS_VERSION_VERIFICATION {
            return Err(TlsConnectionError::NotTlsConnection(pre_read));
        }
        let record_len = stream.read_u16().await?;
        pre_read.extend_from_slice(record_len.to_be_bytes().as_ref());
        if record_len == 0 {
            return Err(TlsConnectionError::NotTlsConnection(pre_read));
        }
        let handshake_type = stream.read_u8().await?;
        pre_read.push(handshake_type);
        if handshake_type != Self::TLS_HANDSHAKE_CLIENT_HELLO {
            return Err(TlsConnectionError::NotTlsConnection(pre_read));
        }
        let mut packet_size = [0u8; 3];
        stream.read_exact(&mut packet_size).await?; // ignore packet size
        pre_read.extend_from_slice(&packet_size);
        let client_version = stream.read_u16().await?;
        pre_read.extend_from_slice(&client_version.to_be_bytes());
        if client_version & Self::TLS_VERSION_VERIFICATION != Self::TLS_VERSION_VERIFICATION {
            return Err(TlsConnectionError::NotTlsConnection(pre_read));
        }
        let mut random = [0u8; 32];
        stream.read_exact(&mut random).await?;
        let session_id_len = stream.read_u8().await?;
        let mut session_id = vec![0u8; session_id_len as usize];
        stream.read_exact(&mut session_id).await?;
        let cipher_suites_len = stream.read_u16().await?;
        let mut cipher_suites = vec![0u16; (cipher_suites_len / 2) as usize];
        for cipher_suite in cipher_suites.iter_mut() {
            *cipher_suite = stream.read_u16().await?;
        }
        let compression_methods_len = stream.read_u8().await?;
        let mut compression_methods = vec![0u8; compression_methods_len as usize];
        stream.read_exact(&mut compression_methods).await?;
        let extensions_len = stream.read_u16().await?;
        let mut extensions = Vec::new();
        let mut extensions_data = vec![0u8; extensions_len as usize];
        stream.read_exact(&mut extensions_data).await?;
        let mut cursor = Cursor::new(extensions_data);
        while cursor.position() < extensions_len as u64 {
            if let Some(extension) = Extension::read(&mut cursor).await? {
                extensions.push(extension);
            }
        }
        Ok(Self {
            protocol_version,
            client_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> std::io::Result<()> {
        let len = self.len() + 4; // handshake_type, handshake_len, data
        let packet_size = if self.has_extension() {
            Self::TLS_STRICT_LENGTH
        } else {
            len
        };
        stream.write_u8(Self::TLS_HANDSHAKE_RECORD).await?;
        stream.write_u16(self.protocol_version).await?;
        stream.write_u16(packet_size as u16).await?;
        stream.write_u8(Self::TLS_HANDSHAKE_CLIENT_HELLO).await?;
        stream
            .write_all(&u32_to_tls_handshake_len((packet_size - 4) as u32))
            .await?; // remove handshake_type and handshake_len
        stream.write_u16(self.client_version).await?;
        stream.write_all(&self.random).await?;
        stream.write_u8(self.session_id.len() as u8).await?;
        stream.write_all(&self.session_id).await?;
        stream
            .write_u16((self.cipher_suites.len() as u16) * 2) // bytes
            .await?;
        for cipher_suite in self.cipher_suites.iter() {
            stream.write_u16(*cipher_suite).await?;
        }
        stream
            .write_u8(self.compression_methods.len() as u8)
            .await?;
        stream.write_all(&self.compression_methods).await?;
        if self.has_extension() {
            stream
                .write_u16((packet_size - len + self.extensions_len()) as u16)
                .await?;
            for extension in self.extensions.iter() {
                extension.write(stream).await?;
            }

            Extension::write_padding(stream, packet_size - len).await?;
        }
        Ok(())
    }
    pub fn has_extension(&self) -> bool {
        !self.extensions.is_empty()
    }
    pub fn len(&self) -> usize {
        let mut len = 2 // version
            + 32 // random
            + 1 // session_id_len
            + self.session_id.len() // session_id
            + 2 // cipher_suites_len
            + self.cipher_suites.len() * 2 // cipher_suites
            + 1 // compression_methods_len
            + self.compression_methods.len(); // compression_methods
        if !self.extensions.is_empty() {
            len += 2 // extensions_len
        }
        len += self.extensions_len(); // extensions
        len
    }
    pub fn extensions_len(&self) -> usize {
        let mut len = 0;
        for extension in self.extensions.iter() {
            len += 4 + extension.len(); // extension_type, extension_len, extension_data
        }
        len
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Extension {
    ServerName(Vec<(u8, String)>),
    Other(u16, Vec<u8>),
}

impl Extension {
    const SERVER_NAME: u16 = 0x0000;
    const PADDING: u16 = 0x0015;
    pub fn len(&self) -> usize {
        match self {
            Self::ServerName(names) => {
                let mut len = 2;
                len + names.iter().map(|name| 3 + name.1.len()).sum::<usize>()
            }
            Self::Other(_, data) => data.len(),
        }
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, stream: &mut W) -> std::io::Result<()> {
        let len = self.len();
        match self {
            Self::ServerName(names) => {
                stream.write_u16(Self::SERVER_NAME).await?;
                stream.write_u16(len as u16).await?;
                stream.write_u16((len - 2) as u16).await?;
                for (name_type, name) in names {
                    stream.write_u8(*name_type).await?;
                    stream.write_u16(name.len() as u16).await?;
                    stream.write_all(name.as_bytes()).await?;
                }
            }
            Self::Other(r#type, data) => {
                stream.write_u16(*r#type).await?;
                stream.write_u16(len as u16).await?;
                stream.write_all(&data).await?;
            }
        }
        Ok(())
    }

    /// Returns `None` if the type is padding.
    pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<Option<Self>> {
        let ext_type = stream.read_u16().await?;
        let ext_len = stream.read_u16().await?;
        match ext_type {
            Self::SERVER_NAME => {
                let mut names = Vec::new();
                let names_len = stream.read_u16().await?;
                let mut read_len: usize = 0;
                while read_len < names_len as usize {
                    let name_type = stream.read_u8().await?;
                    let name_len = stream.read_u16().await?;
                    let mut name = vec![0u8; name_len as usize];
                    stream.read_exact(&mut name).await?;
                    names.push((name_type, unsafe { String::from_utf8_unchecked(name) }));
                    read_len += 3 + name_len as usize;
                }
                Ok(Some(Self::ServerName(names)))
            }
            Self::PADDING => {
                stream
                    .read_exact(vec![0u8; ext_len as usize].as_mut_slice())
                    .await?;
                Ok(None)
            }
            _ => {
                let mut ext_data = vec![0u8; ext_len as usize];
                stream.read_exact(&mut ext_data).await?;
                Ok(Some(Self::Other(ext_type, ext_data)))
            }
        }
    }

    pub async fn write_padding<W: AsyncWrite + Unpin>(
        stream: &mut W,
        len: usize,
    ) -> std::io::Result<()> {
        stream.write_u16(Self::PADDING).await?;
        stream.write_u16((len - 4) as u16).await?;
        stream.write_all(&vec![0u8; len - 4]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    const TLS_HANDSHAKE_CLIENT_HELLO: [u8; 517] = [
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x57, 0x16, 0xea, 0xce,
        0xec, 0x93, 0x89, 0x5c, 0x4a, 0x18, 0xd3, 0x1c, 0x5f, 0x37, 0x9b, 0xb3, 0x05, 0xb4, 0x32,
        0x08, 0x29, 0x39, 0xb8, 0x3e, 0xe0, 0x9f, 0x9a, 0x96, 0xba, 0xbe, 0x0a, 0x40, 0x00, 0x00,
        0x02, 0x00, 0x33, 0x01, 0x00, 0x01, 0xd1, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x69, 0x6b, 0x69, 0x70,
        0x65, 0x64, 0x69, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x06,
        0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03,
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00,
        0x18, 0x00, 0x15, 0x01, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    #[tokio::test]
    async fn test_read_tls_connection() {
        let mut stream = Cursor::new(TLS_HANDSHAKE_CLIENT_HELLO);
        let tls_connection = super::TlsConnection::read(&mut stream).await.unwrap();
        assert_eq!(tls_connection.client_version, 0x0303);
        assert_eq!(tls_connection.session_id.len(), 0);
        assert_eq!(tls_connection.cipher_suites.len(), 1);
        assert_eq!(tls_connection.compression_methods.len(), 1);
        assert_eq!(tls_connection.extensions.len(), 5);
        assert_eq!(
            tls_connection.extensions[1],
            super::Extension::ServerName(vec![(0x00, "www.wikipedia.org".to_string())])
        );
        assert_eq!(tls_connection.len(), 112);
        assert_eq!(tls_connection.extensions_len(), 69);
    }
    #[tokio::test]
    async fn test_read_not_tls_connection() {
        let mut stream = Cursor::new(vec![0u8; 1024]);
        let tls_connection = super::TlsConnection::read(&mut stream).await;
        assert!(tls_connection.is_err());
        assert!(
            matches!(tls_connection, Err(super::TlsConnectionError::NotTlsConnection(header)) if header == vec![0u8; 1])
        );
    }
    #[tokio::test]
    async fn test_write_tls_connection() {
        let mut stream = Cursor::new(TLS_HANDSHAKE_CLIENT_HELLO);
        let tls_connection = super::TlsConnection::read(&mut stream).await.unwrap();
        let mut stream = vec![0u8; 517];
        let mut writer = Cursor::new(stream.as_mut_slice());
        tls_connection.write(&mut writer).await.unwrap();
        assert_eq!(stream, TLS_HANDSHAKE_CLIENT_HELLO);
    }
}
