//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use std::{
    error::Error,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use proto::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[clap(name = "insecure_client")]
struct Opt {
    /// Address to connect to
    #[clap(long = "connect", default_value = "[::1]:4433")]
    connect: SocketAddr,

    /// Address to bind on
    #[clap(long = "bind", default_value = "[::]:0")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let opt = Opt::parse();
    run_client(opt).await?;
    Ok(())
}

async fn run_client(options: Opt) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut endpoint = Endpoint::client(options.bind)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    // Use the same simple protocol identifier as the server
    client_crypto.alpn_protocols = vec![b"solana-tpu".to_vec()];

    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_crypto,
    )?)));

    // connect to server
    let connection = endpoint
        .connect(options.connect, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
    let semaphore = Arc::new(Semaphore::new(2000));  // Allow 2000 concurrent streams
    let mut handles = Vec::new();

    for i in 0..10000 {
        let connection = connection.clone();
        let semaphore = semaphore.clone();

        // Acquire permit before spawning task
        let permit = semaphore.acquire_owned().await.unwrap();

        let handle = tokio::spawn(async move {
            // Permit is held for the duration of this scope
            let _permit = permit;  // Will be dropped when task completes

            let mut stream = connection.open_uni().await.unwrap();
            stream.write_all(b"hello").await.unwrap();
            stream.finish().unwrap();

            let res = tokio::time::timeout(Duration::from_secs(1), stream.stopped()).await;
            match res {
                Ok(res) => {
                    if let Err(e) = res {
                        println!("stream.stopped() failed: {}", e);
                    }
                }
                Err(e) => {
                    println!("timeout {}", e);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await;
    }

    drop(connection);
    println!("dropped connection");
    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
