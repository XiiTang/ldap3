use std::collections::{HashMap, HashSet};
#[cfg(feature = "tls-rustls")]
use std::net::IpAddr;
use std::pin::Pin;
#[cfg(feature = "tls-rustls")]
use std::str::FromStr;
#[cfg(feature = "tls-rustls")]
use std::sync::LazyLock;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::RequestId;
#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use crate::exop_impl::StartTLS;
use crate::ldap::Ldap;
use crate::protocol::{ItemSender, LdapCodec, LdapOp, MaybeControls, MiscSender, ResultSender};
use crate::result::{LdapError, Result};
use crate::search::SearchItem;

use lber::structures::{Null, Tag};

#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use futures_util::future::TryFutureExt;
#[cfg(feature = "tls-native")]
use native_tls::TlsConnector;
#[cfg(unix)]
use percent_encoding::percent_decode;
#[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-rustls"))]
use ring::digest::{self, Algorithm, digest};
#[cfg(feature = "tls-rustls")]
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer, pki_types::ServerName};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::mpsc;
#[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
use tokio::sync::oneshot;
use tokio::time;
#[cfg(all(feature = "tls-native", not(feature = "tls-rustls")))]
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream};
#[cfg(all(feature = "tls-rustls", not(feature = "tls-native")))]
use tokio_rustls::{TlsConnector as TokioTlsConnector, client::TlsStream};
use tokio_stream::StreamExt;
#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!(r#"Only one of "tls-native" and "tls-rustls" may be enabled for TLS support"#);
#[cfg(all(feature = "tls-rustls", not(feature = "rustls-provider")))]
compile_error!(
    r#"No crypto provider selected for Rustls, use "tls-rustls-aws-lc-rs" or "tls-rustls-ring", or see the README for instructions"#
);
use tokio_util::codec::{Decoder, Encoder, Framed};
use url::{self, Url};

/// A transport already authorized and secured by the caller.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
impl std::fmt::Debug for dyn AsyncStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SuppliedTransport")
    }
}

#[derive(Debug)]
enum ConnType {
    Supplied(Box<dyn AsyncStream>),
    Tcp(TcpStream),
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    Tls(TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(UnixStream),
}

#[cfg(feature = "tls-rustls")]
#[derive(Debug)]
struct NoCertVerification;

#[cfg(feature = "tls-rustls")]
impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer,
        _: &[CertificateDer],
        _: &ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(feature = "tls-rustls")]
static CACERTS: LazyLock<RootCertStore> = LazyLock::new(|| {
    let mut store = RootCertStore::empty();
    let cert_res = rustls_native_certs::load_native_certs();
    let cert_vec = if cert_res.errors.is_empty() {
        cert_res.certs
    } else {
        vec![]
    };
    for cert in cert_vec {
        if let Ok(_) = store.add(cert) {}
    }
    store
});

#[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-rustls"))]
static ENDPOINT_ALG: LazyLock<HashMap<&'static str, &'static Algorithm>> = LazyLock::new(|| {
    HashMap::from([
        ("1.2.840.113549.1.1.4", &digest::SHA256),
        ("1.2.840.113549.1.1.5", &digest::SHA256),
        ("1.2.840.113549.1.1.11", &digest::SHA256),
        ("1.2.840.113549.1.1.12", &digest::SHA384),
        ("1.2.840.113549.1.1.13", &digest::SHA512),
        ("1.2.840.10045.4.3.2", &digest::SHA256),
        ("1.2.840.10045.4.3.3", &digest::SHA384),
        ("1.2.840.10045.4.3.4", &digest::SHA512),
    ])
});

impl AsyncRead for ConnType {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Supplied(ts) => Pin::new(ts).poll_read(cx, buf),
            ConnType::Tcp(ts) => Pin::new(ts).poll_read(cx, buf),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnType {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnType::Supplied(ts) => Pin::new(ts).poll_write(cx, buf),
            ConnType::Tcp(ts) => Pin::new(ts).poll_write(cx, buf),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Supplied(ts) => Pin::new(ts).poll_flush(cx),
            ConnType::Tcp(ts) => Pin::new(ts).poll_flush(cx),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_flush(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Supplied(ts) => Pin::new(ts).poll_shutdown(cx),
            ConnType::Tcp(ts) => Pin::new(ts).poll_shutdown(cx),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            ConnType::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_shutdown(cx),
        }
    }
}

/// Existing stream from which a connection can be created.
///
/// A connection may be created from a previously opened TCP or Unix
/// stream (the latter only if Unix domain sockets are supported) by
/// placing an instance of this structure in `LdapConnSettings`.
///
/// Since the stdlib streams can't be cloned, and `LdapConnSettings`
/// derives `Clone`, cloning the enum will produce the `Invalid`
/// variant. Thus, the settings should not be cloned if they
/// contain an existing stream.
pub enum StdStream {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Invalid,
}

impl Clone for StdStream {
    fn clone(&self) -> StdStream {
        StdStream::Invalid
    }
}

/// Additional settings for an LDAP connection.
///
/// The structure is opaque for better extensibility. An instance with
/// default values is constructed by [`new()`](#method.new), and all
/// available settings can be replaced through a builder-like interface,
/// by calling the appropriate functions.
#[derive(Clone, Default)]
pub struct LdapConnSettings {
    conn_timeout: Option<Duration>,
    #[cfg(feature = "tls-native")]
    connector: Option<TlsConnector>,
    #[cfg(feature = "tls-rustls")]
    config: Option<Arc<ClientConfig>>,
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    starttls: bool,
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    no_tls_verify: bool,
    std_stream: Option<StdStream>,
}

impl LdapConnSettings {
    /// Create an instance of the structure with default settings.
    pub fn new() -> LdapConnSettings {
        LdapConnSettings {
            ..Default::default()
        }
    }

    /// Set the connection timeout. If a connetion to the server can't
    /// be established before the timeout expires, an error will be
    /// returned to the user. Defaults to `None`, meaning an infinite
    /// timeout.
    pub fn set_conn_timeout(mut self, timeout: Duration) -> Self {
        self.conn_timeout = Some(timeout);
        self
    }

    #[cfg(feature = "tls-native")]
    /// Set a custom TLS connector, which enables setting various options
    /// when establishing a secure connection. The default of `None` will
    /// use a connector with default settings.
    pub fn set_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    #[cfg(feature = "tls-rustls")]
    /// Set a custom TLS configuration, which enables setting various options
    /// when establishing a secure connection. The default of `None` will
    /// use a configuration with default values.
    ///
    /// The default configuration will try to load the system certificate store
    /// and use it for verification.
    pub fn set_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.config = Some(config);
        self
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// If `true`, use the StartTLS extended operation to establish a
    /// secure connection. Defaults to `false`.
    pub fn set_starttls(mut self, starttls: bool) -> Self {
        self.starttls = starttls;
        self
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// The `starttls` settings indicates whether the StartTLS extended
    /// operation will be used to establish a secure connection.
    pub fn starttls(&self) -> bool {
        self.starttls
    }

    #[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
    /// Always `false` when no TLS support is compiled in.
    pub fn starttls(&self) -> bool {
        false
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    /// If `true`, try to establish a TLS connection without certificate
    /// verification. Defaults to `false`.
    pub fn set_no_tls_verify(mut self, no_tls_verify: bool) -> Self {
        self.no_tls_verify = no_tls_verify;
        self
    }

    /// Create an LDAP connection using a previously opened standard library
    /// stream (TCP or Unix, if applicable.) The full URL must still be provided
    /// in order to select connection details, such as TLS establishment or
    /// Unix domain socket operation.
    ///
    /// For Unix streams, the URL can be __ldapi:///__, since the path won't
    /// be used.
    ///
    /// If the provided stream doesn't match the URL (e.g., a Unix stream is
    /// given with the __ldap__ or __ldaps__ URL), an error will be returned.
    pub fn set_std_stream(mut self, stream: StdStream) -> Self {
        self.std_stream = Some(stream);
        self
    }
}

enum LoopMode {
    #[allow(dead_code)]
    SingleOp,
    Continuous,
}

#[allow(clippy::needless_doctest_main)]
/// Asynchronous connection to an LDAP server. __*__
///
/// In this version of the interface, opening a connection with [`new()`](#method.new)
/// will return a tuple consisting of the connection itself and an [`Ldap`](struct.Ldap.html)
/// handle for performing the LDAP operations. The connection must be spawned on the active
/// Tokio executor before using the handle. A convenience macro, [`drive!`](macro.drive.html), is
/// provided by the library. For the connection `conn`, it does the equivalent of:
///
/// ```rust,no_run
/// # use ldap3::LdapConnAsync;
/// # use log::warn;
/// # #[tokio::main]
/// # async fn main() {
/// # let (conn, _ldap) = LdapConnAsync::new("ldap://localhost:2389").await.unwrap();
/// tokio::spawn(async move {
///     if let Err(e) = conn.drive().await {
///         warn!("LDAP connection error: {}", e);
///     }
/// });
/// # }
/// ```
///
/// If you need custom connection lifecycle handling, use the [`drive()`](#method.drive) method
/// on the connection inside your own `async` block.
///
/// The `Ldap` handle can be freely cloned, with each clone capable of launching a separate
/// LDAP operation multiplexed on the original connection. Dropping the last handle will automatically
/// close the connection.
///
/// Some connections need additional parameters, but providing many separate functions to initialize
/// them, singly or in combination, would result in a cumbersome interface. Instead, connection
/// initialization is optimized for the expected most frequent usage, and additional customization
/// is possible through the [`LdapConnSettings`](struct.LdapConnSettings.html) struct, which can be
/// passed to [`with_settings()`](#method.with_settings).
pub struct LdapConnAsync {
    raw: Option<crate::raw::Driver>,
    msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    resultmap: HashMap<i32, ResultSender>,
    searchmap: HashMap<i32, ItemSender>,
    rx: mpsc::UnboundedReceiver<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    id_scrub_rx: mpsc::UnboundedReceiver<RequestId>,
    misc_rx: mpsc::UnboundedReceiver<MiscSender>,
    stream: Framed<ConnType, LdapCodec>,
}

/// Drive the connection until its completion. __*__
///
/// See the introduction of [LdapConnAsync](struct.LdapConnAsync.html) for the exact code produced by
/// the macro.
#[macro_export]
macro_rules! drive {
    ($conn:expr) => {
        $crate::tokio::spawn(async move {
            if let Err(e) = $conn.drive().await {
                $crate::log::warn!("LDAP connection error: {}", e);
            }
        });
    };
}

impl LdapConnAsync {
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub async fn with_settings(settings: LdapConnSettings, url: &str) -> Result<(Self, Ldap)> {
        let url = Url::parse(url)?;
        Self::from_url_with_settings(settings, &url).await
    }

    /// Open a connection to an LDAP server specified by `url`.
    ///
    /// The `url` is an LDAP URL. Depending on the platform and compile-time features, the
    /// library will recognize one or more URL schemes.
    ///
    /// The __ldap__ scheme, which uses a plain TCP connection, is always available. Unix-like
    /// platforms also support __ldapi__, using Unix domain sockets. With the __tls__ or
    /// __tls-rustls__ feature, the __ldaps__ scheme and StartTLS over __ldap__ are additionally
    /// supported.
    ///
    /// The connection element in the returned tuple must be spawned on the current Tokio
    /// executor before using the `Ldap` element. See the introduction to this struct's
    /// documentation.
    pub async fn new(url: &str) -> Result<(Self, Ldap)> {
        Self::with_settings(LdapConnSettings::new(), url).await
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`, using
    /// `settings` to specify additional parameters.
    pub async fn from_url_with_settings(
        settings: LdapConnSettings,
        url: &Url,
    ) -> Result<(Self, Ldap)> {
        if url.scheme() == "ldapi" {
            LdapConnAsync::new_unix(url, settings).await
        } else {
            // For some reason, "mut settings" is transformed to "__arg0" in the docs,
            // this is a workaround. On GitHub, at the time of writing, there is:
            //
            // https://github.com/rust-lang/docs.rs/issues/737
            //
            // But no issue in the Rust repo.
            let mut settings = settings;
            let timeout = settings.conn_timeout.take();
            let conn_future = LdapConnAsync::new_tcp(url, settings);
            Ok(if let Some(timeout) = timeout {
                time::timeout(timeout, conn_future).await?
            } else {
                conn_future.await
            }?)
        }
    }

    /// Open a connection to an LDAP server specified by an already parsed `Url`.
    pub async fn from_url(url: &Url) -> Result<(Self, Ldap)> {
        Self::from_url_with_settings(LdapConnSettings::new(), url).await
    }

    #[cfg(unix)]
    async fn new_unix(url: &Url, settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let stream = match settings.std_stream {
            None => {
                let path = url.host_str().unwrap_or("");
                if path.is_empty() {
                    return Err(LdapError::EmptyUnixPath);
                }
                if path.contains(':') {
                    return Err(LdapError::PortInUnixPath);
                }
                let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
                UnixStream::connect(dec_path.as_ref()).await?
            }
            Some(StdStream::Unix(stream)) => {
                stream.set_nonblocking(true)?;
                UnixStream::from_std(stream)?
            }
            Some(StdStream::Tcp(_)) | Some(StdStream::Invalid) => {
                return Err(LdapError::MismatchedStreamType);
            }
        };
        Ok(Self::conn_pair(ConnType::Unix(stream)))
    }

    #[cfg(not(unix))]
    async fn new_unix(_url: &Url, _settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        unimplemented!("no Unix domain sockets on non-Unix platforms");
    }

    #[allow(unused_mut)]
    async fn new_tcp(url: &Url, mut settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => {
                if settings.starttls() {
                    "starttls"
                } else {
                    s
                }
            }
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            s @ "ldaps" => {
                settings = settings.set_starttls(false);
                port = 636;
                s
            }
            s => return Err(LdapError::UnknownScheme(String::from(s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let (_hostname, host_port) = match url.host_str() {
            Some("") => ("localhost", format!("localhost:{}", port)),
            Some(h) => (h, format!("{}:{}", h, port)),
            _ => panic!("unexpected None from url.host_str()"),
        };
        let stream = match settings.std_stream {
            None => TcpStream::connect(host_port.as_str()).await?,
            Some(StdStream::Tcp(_)) => {
                let stream = match settings.std_stream.take().expect("StdStream") {
                    StdStream::Tcp(stream) => stream,
                    _ => panic!("non-tcp stream in enum"),
                };
                stream.set_nonblocking(true)?;
                TcpStream::from_std(stream)?
            }
            Some(_) => return Err(LdapError::MismatchedStreamType),
        };
        let (mut conn, mut ldap) = Self::conn_pair(ConnType::Tcp(stream));
        match scheme {
            "ldap" => (),
            #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
            s @ "ldaps" | s @ "starttls" => {
                if s == "starttls" {
                    let (tx, rx) = oneshot::channel();
                    tokio::spawn(async move {
                        conn.single_op(tx).await;
                    });
                    let res =
                        tokio::try_join!(rx.map_err(LdapError::from), ldap.extended(StartTLS));
                    match res {
                        Ok((conn_res, res)) => {
                            conn = conn_res?;
                            res.success()?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                let parts = conn.stream.into_parts();
                if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected plaintext at LDAP TLS boundary",
                    )
                    .into());
                }
                let tls_stream = if let ConnType::Tcp(stream) = parts.io {
                    LdapConnAsync::create_tls_stream(settings, _hostname, stream).await?
                } else {
                    panic!("underlying stream not TCP");
                };
                #[cfg(any(feature = "gssapi", feature = "ntlm"))]
                {
                    ldap.tls_endpoint_token =
                        Arc::new(LdapConnAsync::get_tls_endpoint_token(&tls_stream));
                }
                conn.stream = parts.codec.framed(ConnType::Tls(tls_stream));
                ldap.has_tls = true;
            }
            _ => unimplemented!(),
        }
        Ok((conn, ldap))
    }

    #[cfg(feature = "tls-native")]
    async fn create_tls_stream(
        settings: LdapConnSettings,
        hostname: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        let connector = match settings.connector {
            Some(connector) => connector,
            None => LdapConnAsync::create_connector(&settings),
        };
        TokioTlsConnector::from(connector)
            .connect(hostname, stream)
            .await
            .map_err(LdapError::from)
    }

    #[cfg(feature = "tls-rustls")]
    async fn create_tls_stream(
        settings: LdapConnSettings,
        hostname: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>> {
        let no_tls_verify = settings.no_tls_verify;
        let config = match settings.config {
            Some(config) => config,
            None => LdapConnAsync::create_config(&settings),
        };
        TokioTlsConnector::from(config)
            .connect(
                ServerName::try_from(hostname)
                    .map(|sn| sn.to_owned())
                    .or_else(|e| {
                        if no_tls_verify {
                            if let Ok(_addr) = IpAddr::from_str(hostname) {
                                ServerName::try_from("_irrelevant")
                            } else {
                                Err(e)
                            }
                        } else {
                            Err(e)
                        }
                    })?,
                stream,
            )
            .await
            .map_err(LdapError::from)
    }

    #[cfg(feature = "tls-rustls")]
    fn create_config(settings: &LdapConnSettings) -> Arc<ClientConfig> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(CACERTS.clone())
            .with_no_client_auth();
        if settings.no_tls_verify {
            let no_cert_verifier = NoCertVerification;
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(no_cert_verifier));
        }
        Arc::new(config)
    }

    #[cfg(feature = "tls-native")]
    fn create_connector(settings: &LdapConnSettings) -> TlsConnector {
        let mut builder = TlsConnector::builder();
        if settings.no_tls_verify {
            builder.danger_accept_invalid_certs(true);
        }
        builder.build().expect("connector")
    }

    #[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-native"))]
    fn get_tls_endpoint_token(s: &TlsStream<TcpStream>) -> Option<Vec<u8>> {
        match s.get_ref().tls_server_end_point() {
            Ok(ep) => {
                if ep.is_none() {
                    warn!("no endpoint token returned");
                }
                ep
            }
            Err(e) => {
                warn!("error calculating endpoint token: {}", e);
                None
            }
        }
    }

    #[cfg(all(any(feature = "gssapi", feature = "ntlm"), feature = "tls-rustls"))]
    fn get_tls_endpoint_token(s: &TlsStream<TcpStream>) -> Option<Vec<u8>> {
        use x509_parser::prelude::*;

        if let Some(certs) = s.get_ref().1.peer_certificates() {
            let peer_cert = &certs[0].as_ref();
            let leaf = match X509Certificate::from_der(peer_cert) {
                Ok(leaf) => leaf,
                Err(e) => {
                    warn!("error parsing peer certificate: {}", e);
                    return None;
                }
            };
            let sigalg = leaf.1.signature_algorithm.algorithm.to_id_string();
            if let Some(alg) = ENDPOINT_ALG.get(&*sigalg) {
                Some(Vec::from(digest(alg, peer_cert).as_ref()))
            } else {
                warn!("unknown signature algorithm, oid={}", sigalg);
                None
            }
        } else {
            warn!("no peer certificates found");
            None
        }
    }

    /// Use exactly the supplied stream. No DNS, sockets, proxy or TLS fallback is performed.
    pub fn from_stream<T: AsyncStream + 'static>(
        stream: T,
        limits: crate::CodecLimits,
    ) -> Result<(Self, Ldap)> {
        let codec = LdapCodec::new(limits)?;
        Ok(Self::conn_pair_with_codec(
            ConnType::Supplied(Box::new(stream)),
            codec,
        ))
    }
    /// Supplied-transport raw operations use the existing connection driver,
    /// with globally bounded request, outstanding and response capacity.
    pub fn from_stream_bounded<T: AsyncStream + 'static>(
        stream: T,
        limits: crate::DriverLimits,
    ) -> Result<(Self, crate::RawHandle, crate::RawResponses)> {
        let limits = limits.validate()?;
        let (mut conn, ldap) = Self::from_stream(stream, limits.codec)?;
        let (raw, handle, responses) = crate::raw::Driver::new(ldap, limits);
        conn.raw = Some(raw);
        Ok((conn, handle, responses))
    }
    fn conn_pair(ctype: ConnType) -> (Self, Ldap) {
        Self::conn_pair_with_codec(
            ctype,
            LdapCodec::new(Default::default()).expect("valid default codec limits"),
        )
    }
    fn conn_pair_with_codec(ctype: ConnType, codec: LdapCodec) -> (Self, Ldap) {
        #[cfg(feature = "gssapi")]
        let client_ctx = codec.client_ctx.clone();
        #[cfg(feature = "gssapi")]
        let sasl_param = codec.sasl_param.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let (id_scrub_tx, id_scrub_rx) = mpsc::unbounded_channel();
        let (misc_tx, misc_rx) = mpsc::unbounded_channel();
        let conn = LdapConnAsync {
            raw: None,
            msgmap: Arc::new(Mutex::new((0, HashSet::new()))),
            resultmap: HashMap::new(),
            searchmap: HashMap::new(),
            rx,
            id_scrub_rx,
            misc_rx,
            stream: codec.framed(ctype),
        };
        let ldap = Ldap {
            msgmap: conn.msgmap.clone(),
            tx,
            id_scrub_tx,
            misc_tx,
            #[cfg(feature = "gssapi")]
            sasl_param,
            #[cfg(feature = "gssapi")]
            client_ctx,
            #[cfg(any(feature = "gssapi", feature = "ntlm"))]
            tls_endpoint_token: Arc::new(None),
            has_tls: false,
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        };
        (conn, ldap)
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    fn get_peer_certificate(&self) -> Result<Option<Vec<u8>>> {
        let tls = match self.stream.get_ref() {
            ConnType::Tls(tls) => tls.get_ref(),
            _ => return Ok(None),
        };
        match () {
            #[cfg(feature = "tls-native")]
            () => {
                let cert = tls.peer_certificate();
                match cert {
                    Ok(c) => match c {
                        Some(x) => match x.to_der() {
                            Ok(ret) => Ok(Some(ret)),
                            Err(e) => Err(LdapError::from(e)),
                        },
                        None => Ok(None),
                    },
                    Err(e) => Err(LdapError::from(e)),
                }
            }
            #[cfg(feature = "tls-rustls")]
            () => {
                let certs = match tls.1.peer_certificates() {
                    Some(certs) => certs,
                    None => return Ok(None),
                };
                if certs.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(certs[0].to_vec()))
                }
            }
        }
    }

    /// Drive exactly one terminal raw response and finish its physical write.
    /// Used for explicit authentication or STARTTLS before continuous driving.
    /// No transport security transition is performed by this method.
    pub async fn drive_one(self) -> Result<Self> {
        if self.raw.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "raw driver required").into());
        }
        self.turn(LoopMode::SingleOp).await?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "LDAP driver ended during exchange",
            )
            .into()
        })
    }
    /// Recover the exact supplied transport after a completed upgrade response.
    /// Buffered plaintext, queued commands or outstanding requests are rejected.
    pub fn into_stream(self) -> Result<Box<dyn AsyncStream>> {
        if !self.rx.is_empty() || !self.msgmap.lock().expect("msgmap mutex").1.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LDAP operations remain during upgrade",
            )
            .into());
        }
        let parts = self.stream.into_parts();
        if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffered LDAP plaintext during upgrade",
            )
            .into());
        }
        match parts.io {
            ConnType::Supplied(stream) => Ok(stream),
            _ => Err(
                io::Error::new(io::ErrorKind::InvalidInput, "supplied transport required").into(),
            ),
        }
    }

    /// Repeatedly poll the connection until it exits.
    pub async fn drive(self) -> Result<()> {
        self.turn(LoopMode::Continuous).await.map(|_| ())
    }

    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    pub(crate) async fn single_op(self, tx: oneshot::Sender<Result<Self>>) {
        if tx
            .send(self.turn(LoopMode::SingleOp).await.and_then(|value| {
                value.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "LDAP connection ended during upgrade",
                    )
                    .into()
                })
            }))
            .is_err()
        {
            warn!("single op send error");
        }
    }

    async fn turn(self, mode: LoopMode) -> Result<Option<Self>> {
        #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
        let certificate = self.get_peer_certificate()?;
        let Self {
            mut raw,
            msgmap,
            mut resultmap,
            mut searchmap,
            mut rx,
            mut id_scrub_rx,
            mut misc_rx,
            stream,
        } = self;
        let parts = stream.into_parts();
        let (read_half, write_half) = io::split(parts.io);
        let mut reader = tokio_util::codec::FramedRead::new(read_half, parts.codec.clone());
        *reader.read_buffer_mut() = parts.read_buf;
        let mut initial_writer = tokio_util::codec::FramedWrite::new(write_half, parts.codec);
        *initial_writer.write_buffer_mut() = parts.write_buf;
        type Writer = tokio_util::codec::FramedWrite<io::WriteHalf<ConnType>, LdapCodec>;
        type Completed = (
            Writer,
            RequestId,
            LdapOp,
            Option<ResultSender>,
            io::Result<()>,
        );
        let mut writer = Some(initial_writer);
        let mut writing: Option<Pin<Box<dyn std::future::Future<Output = Completed> + Send>>> =
            None;
        let mut operation_complete = false;
        loop {
            if let Some(raw) = &raw {
                raw.observe_buffers(reader.read_buffer().capacity());
            }
            if operation_complete && writing.is_none() && matches!(mode, LoopMode::SingleOp) {
                let read = reader.into_parts();
                let write = writer.take().expect("idle writer").into_parts();
                let mut parts =
                    tokio_util::codec::FramedParts::new(read.io.unsplit(write.io), read.codec);
                parts.read_buf = read.read_buf;
                parts.write_buf = write.write_buf;
                return Ok(Some(Self {
                    raw,
                    msgmap,
                    resultmap,
                    searchmap,
                    rx,
                    id_scrub_rx,
                    misc_rx,
                    stream: Framed::from_parts(parts),
                }));
            }
            tokio::select! {biased;
                completed=async {writing.as_mut().expect("enabled writer").await}, if writing.is_some()=>{
                    writing=None;
                    let (returned,id,mut op,reply,result)=completed;
                    writer=Some(returned);
                    result?;
                    match &mut op {
                        LdapOp::Raw(op)=>crate::raw::Driver::completed(op),
                        LdapOp::Single=>{},
                        LdapOp::Search(_)=>{},
                        LdapOp::Abandon(target)=>{
                            resultmap.remove(target);searchmap.remove(target);
                            let mut ids=msgmap.lock().expect("msgmap mutex");
                            ids.1.remove(target);ids.1.remove(&id);
                        },
                        LdapOp::Unbind=>{msgmap.lock().expect("msgmap mutex").1.remove(&id);},
                    }
                    if let Some(reply)=reply {let _=reply.send((Tag::Null(Null::default()),vec![]));}
                    if matches!(op,LdapOp::Unbind) || matches!(op,LdapOp::Raw(crate::raw::RawOperation {kind:crate::raw::Kind::Unbind,..})) {return Ok(None);}
                },
                req_id=id_scrub_rx.recv()=>{
                    if let Some(id)=req_id {
                        resultmap.remove(&id);searchmap.remove(&id);
                        msgmap.lock().expect("msgmap mutex").1.remove(&id);
                    }
                },
                operation=rx.recv(), if writing.is_none() && !operation_complete=>{
                    let Some((id,mut op,tag,controls,reply))=operation else {return Ok(None);};
                    let mut reply=Some(reply);
                    match &mut op {
                        LdapOp::Raw(op)=>{
                            if let Err(error)=raw.as_mut().expect("raw driver").register(id,op){crate::raw::Driver::rejected(op,error);continue;}
                            crate::raw::Driver::started(op);
                        },
                        LdapOp::Single=>{resultmap.insert(id,reply.take().expect("result sender"));},
                        LdapOp::Search(sender)=>{searchmap.insert(id,sender.clone());},
                        _=>{},
                    }
                    let mut output=writer.take().expect("idle writer");
                    writing=Some(Box::pin(async move {
                        let result=async {
                            let mut encoded=bytes::BytesMut::new();
                            output.encoder_mut().encode((id,tag,controls),&mut encoded)?;
                            let bytes=zeroize::Zeroizing::new(encoded.to_vec());
                            zeroize::Zeroize::zeroize(&mut encoded[..]);
                            drop(encoded);
                            output.get_mut().write_all(&bytes).await?;
                            output.get_mut().flush().await?;
                            if matches!(op,LdapOp::Unbind) || matches!(op,LdapOp::Raw(crate::raw::RawOperation {kind:crate::raw::Kind::Unbind,..})) {output.get_mut().shutdown().await?;}
                            Ok(())
                        }.await;
                        (output,id,op,reply,result)
                    }));
                },
                misc=misc_rx.recv()=>{
                    match misc {
                        #[cfg(any(feature="tls-native",feature="tls-rustls"))]
                        Some(MiscSender::Cert(reply))=>{let _=reply.send(certificate.clone());},
                        None=>return Ok(None),
                    }
                },
                response=reader.next(), if !operation_complete=>{
                    let Some(response)=response else {return Ok(None);};
                    let response=response?;
                    if let Some(raw)=&mut raw {
                        let complete=raw.response(response)?;
                        operation_complete=complete && matches!(mode,LoopMode::SingleOp);
                        continue;
                    }
                    let (id,tag,controls)=(response.id,Tag::StructureTag(response.operation),response.controls);
                    if let Some(sender)=searchmap.get(&id) {
                        let Tag::StructureTag(operation)=tag else {unreachable!()};
                        let (item,complete)=match operation.id {
                            4|25=>(SearchItem::Entry(operation),false),
                            5=>(SearchItem::Done(Tag::StructureTag(operation).into()),true),
                            19=>(SearchItem::Referral(operation),false),
                            _=>return Err(io::Error::new(io::ErrorKind::InvalidData,"unexpected LDAP search response").into()),
                        };
                        if sender.send((item,controls)).is_err() || complete {
                            searchmap.remove(&id);msgmap.lock().expect("msgmap mutex").1.remove(&id);
                        }
                    } else if let Some(sender)=resultmap.remove(&id) {
                        let _=sender.send((tag,controls));
                        msgmap.lock().expect("msgmap mutex").1.remove(&id);
                    }
                    operation_complete=matches!(mode,LoopMode::SingleOp);
                }
            }
        }
    }
}
