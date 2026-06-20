//! CURVE encryption mechanism (RFC 26)
//!
//! CurveZMQ provides public-key cryptography with perfect forward secrecy:
//! - Elliptic curve Diffie-Hellman key exchange (X25519)
//! - Authenticated encryption (ChaCha20-Poly1305)
//! - Resistance to man-in-the-middle attacks
//! - Zero-knowledge password proofs
//!
//! ## Security Properties
//!
//! - **Confidentiality**: All messages encrypted with ephemeral keys
//! - **Authentication**: Server key verified by client
//! - **Perfect Forward Secrecy**: Compromise of long-term keys doesn't reveal past messages
//! - **Replay Protection**: Nonces prevent message replay
//!
//! ## Protocol Flow (CurveZMQ)
//!
//! ```text
//! Client                                Server
//!   |                                      |
//!   |--- HELLO (client ephemeral key) --->|
//!   |                                      |
//!   |<-- WELCOME (server ephemeral key) ---|
//!   |         + encrypted cookie           |
//!   |                                      |
//!   |--- INITIATE (proof of key) -------->|
//!   |      + encrypted metadata            |
//!   |                                      |
//!   |<-- READY (confirmation) ------------|
//!   |                                      |
//!   |<=== Encrypted MESSAGE frames ======>|
//! ```
//!
//! ## Key Types
//!
//! - **Long-term keys**: Server's permanent identity (32-byte public/secret pair)
//! - **Short-term keys**: Ephemeral keys per connection
//! - **Shared secrets**: Computed via X25519 key exchange
//!
//! ## References
//!
//! - RFC 26: <https://rfc.zeromq.org/spec/26/>
//! - CurveCP: <https://curvecp.org/>

use bytes::{Bytes, BytesMut};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use compio::io::{AsyncRead, AsyncWrite};
use rand::RngCore;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::codec::ZmtpError;
use crate::security::protocol::read_command_prefix;
use crate::security::zap::{ZapMechanism, ZapRequest, ZapStatus};

/// CURVE command identifiers
const CURVE_HELLO: &[u8] = b"\x05HELLO";
const CURVE_WELCOME: &[u8] = b"\x07WELCOME";
const CURVE_INITIATE: &[u8] = b"\x08INITIATE";
const CURVE_READY: &[u8] = b"\x05READY";
const CURVE_MESSAGE: &[u8] = b"\x07MESSAGE";
const CURVE_MESSAGE_NONCE_SIZE: usize = 8;
const CURVE_HELLO_NONCE_PREFIX: &[u8; 16] = b"CurveZMQHELLO---";
const CURVE_WELCOME_NONCE_PREFIX: &[u8; 8] = b"WELCOME-";
const CURVE_COOKIE_NONCE_PREFIX: &[u8; 8] = b"COOKIE--";
const CURVE_INITIATE_NONCE_PREFIX: &[u8; 16] = b"CurveZMQINITIATE";
const CURVE_VOUCH_NONCE_PREFIX: &[u8; 8] = b"VOUCH---";
const CURVE_READY_NONCE_PREFIX: &[u8; 16] = b"CurveZMQREADY---";

fn random_nonce<const N: usize>(prefix: &[u8]) -> ([u8; N], [u8; CURVE_NONCE_SIZE]) {
    assert_eq!(prefix.len() + N, CURVE_NONCE_SIZE);

    let mut suffix = [0u8; N];
    rand::thread_rng().fill_bytes(&mut suffix);

    let mut nonce = [0u8; CURVE_NONCE_SIZE];
    nonce[..prefix.len()].copy_from_slice(prefix);
    nonce[prefix.len()..].copy_from_slice(&suffix);

    (suffix, nonce)
}

/// CURVE key sizes
pub const CURVE_KEY_SIZE: usize = 32;
/// Size of a CURVE nonce in bytes.
pub const CURVE_NONCE_SIZE: usize = 24;
/// Overhead added by the Poly1305 authentication tag.
pub const CURVE_BOX_OVERHEAD: usize = 16; // Poly1305 tag

/// CURVE public key (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurvePublicKey([u8; CURVE_KEY_SIZE]);

impl CurvePublicKey {
    /// Create from bytes
    pub const fn from_bytes(bytes: [u8; CURVE_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub const fn as_bytes(&self) -> &[u8; CURVE_KEY_SIZE] {
        &self.0
    }

    /// Convert to X25519 public key
    pub fn to_x25519(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

impl From<[u8; CURVE_KEY_SIZE]> for CurvePublicKey {
    fn from(bytes: [u8; CURVE_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for CurvePublicKey {
    fn from(key: PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl AsRef<[u8]> for CurvePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// CURVE secret key (32 bytes)
#[derive(Clone)]
pub struct CurveSecretKey(StaticSecret);

impl CurveSecretKey {
    /// Generate a new random secret key
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; CURVE_KEY_SIZE]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Get public key
    pub fn public_key(&self) -> CurvePublicKey {
        CurvePublicKey::from(PublicKey::from(&self.0))
    }

    /// Compute shared secret via ECDH
    pub fn diffie_hellman(
        &self,
        peer_public: &CurvePublicKey,
    ) -> Result<CurveSharedSecret, CurveError> {
        let shared = *self.0.diffie_hellman(&peer_public.to_x25519()).as_bytes();
        if shared == [0u8; CURVE_KEY_SIZE] {
            return Err(CurveError::ProtocolViolation);
        }
        Ok(CurveSharedSecret::from_bytes(shared))
    }
}

impl std::fmt::Debug for CurveSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CurveSecretKey([REDACTED])")
    }
}

/// CURVE shared secret (32 bytes).
#[derive(Clone)]
pub struct CurveSharedSecret([u8; CURVE_KEY_SIZE]);

impl CurveSharedSecret {
    /// Create from bytes.
    pub const fn from_bytes(bytes: [u8; CURVE_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes.
    pub const fn as_bytes(&self) -> &[u8; CURVE_KEY_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for CurveSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CurveSharedSecret([REDACTED])")
    }
}

/// CURVE key pair (public + secret)
#[derive(Debug, Clone)]
pub struct CurveKeyPair {
    /// Long-term public key.
    pub public: CurvePublicKey,
    /// Long-term secret key.
    pub secret: CurveSecretKey,
}

impl CurveKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let secret = CurveSecretKey::generate();
        let public = secret.public_key();
        Self { public, secret }
    }

    /// Create from existing keys
    pub fn from_keys(_public: CurvePublicKey, secret: CurveSecretKey) -> Self {
        let public = secret.public_key();
        Self { public, secret }
    }
}

/// CURVE encryption box (ChaCha20-Poly1305)
struct CurveBox {
    cipher: ChaCha20Poly1305,
}

impl CurveBox {
    /// Create new box from shared secret
    fn new(shared_secret: &CurveSharedSecret) -> Self {
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt message with nonce
    fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8; CURVE_NONCE_SIZE],
    ) -> Result<Vec<u8>, CurveError> {
        // ChaCha20Poly1305 uses 12-byte nonces. Keep the counter-bearing suffix
        // of the CurveZMQ nonce so each message uses a distinct AEAD nonce.
        let nonce = Nonce::from_slice(&nonce[12..]);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CurveError::EncryptionFailed)
    }

    /// Decrypt message with nonce
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; CURVE_NONCE_SIZE],
    ) -> Result<Vec<u8>, CurveError> {
        // ChaCha20Poly1305 uses 12-byte nonces. Keep the counter-bearing suffix
        // of the CurveZMQ nonce so each message uses a distinct AEAD nonce.
        let nonce = Nonce::from_slice(&nonce[12..]);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CurveError::DecryptionFailed)
    }
}

struct CurveHello {
    client_short_public: CurvePublicKey,
}

impl CurveHello {
    async fn read_from<S>(
        stream: &mut S,
        timeout: Option<Duration>,
        server_keypair: &CurveKeyPair,
    ) -> Result<Self, ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::read_exact_with_timeout;

        read_command_prefix(stream, CURVE_HELLO, timeout).await?;

        let body = vec![0u8; 194];
        let buf_result = read_exact_with_timeout(stream, body, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, body) = buf_result;
        result?;

        if body[0..2] != [1, 0] {
            return Err(ZmtpError::Protocol);
        }
        if !body[2..74].iter().all(|&byte| byte == 0) {
            return Err(ZmtpError::Protocol);
        }

        let mut client_short_public = [0u8; CURVE_KEY_SIZE];
        client_short_public.copy_from_slice(&body[74..106]);
        if client_short_public == [0u8; CURVE_KEY_SIZE] {
            return Err(ZmtpError::Protocol);
        }

        let mut short_nonce = [0u8; 8];
        short_nonce.copy_from_slice(&body[106..114]);
        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..CURVE_HELLO_NONCE_PREFIX.len()].copy_from_slice(CURVE_HELLO_NONCE_PREFIX);
        nonce[CURVE_HELLO_NONCE_PREFIX.len()..].copy_from_slice(&short_nonce);

        let shared_secret = server_keypair
            .secret
            .diffie_hellman(&CurvePublicKey::from_bytes(client_short_public))
            .map_err(|_| ZmtpError::Protocol)?;
        let proof = CurveBox::new(&shared_secret)
            .decrypt(&body[114..194], &nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        if proof.len() != 64 || !proof.iter().all(|&byte| byte == 0) {
            return Err(ZmtpError::Protocol);
        }

        Ok(Self {
            client_short_public: CurvePublicKey::from_bytes(client_short_public),
        })
    }
}

struct CurveWelcome {
    server_short_public: CurvePublicKey,
    cookie: [u8; 96],
}

impl CurveWelcome {
    async fn read_from<S>(
        stream: &mut S,
        timeout: Option<Duration>,
        client_short_keypair: &CurveKeyPair,
        server_public: &CurvePublicKey,
    ) -> Result<Self, ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::read_exact_with_timeout;

        read_command_prefix(stream, CURVE_WELCOME, timeout).await?;

        let welcome_nonce = vec![0u8; 16];
        let buf_result = read_exact_with_timeout(stream, welcome_nonce, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, welcome_nonce) = buf_result;
        result?;

        let welcome_box = vec![0u8; 144];
        let buf_result = read_exact_with_timeout(stream, welcome_box, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, welcome_box) = buf_result;
        result?;

        let shared_secret = client_short_keypair
            .secret
            .diffie_hellman(server_public)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..CURVE_WELCOME_NONCE_PREFIX.len()].copy_from_slice(CURVE_WELCOME_NONCE_PREFIX);
        nonce[CURVE_WELCOME_NONCE_PREFIX.len()..].copy_from_slice(&welcome_nonce);

        let plaintext = CurveBox::new(&shared_secret)
            .decrypt(&welcome_box, &nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        if plaintext.len() != CURVE_KEY_SIZE + 96 {
            return Err(ZmtpError::Protocol);
        }

        let mut server_short_public = [0u8; CURVE_KEY_SIZE];
        server_short_public.copy_from_slice(&plaintext[..CURVE_KEY_SIZE]);

        let mut cookie = [0u8; 96];
        cookie.copy_from_slice(&plaintext[CURVE_KEY_SIZE..]);

        if server_short_public == [0u8; CURVE_KEY_SIZE] {
            return Err(ZmtpError::Protocol);
        }

        Ok(Self {
            server_short_public: CurvePublicKey::from_bytes(server_short_public),
            cookie,
        })
    }
}

struct CurveInitiate {
    client_public: CurvePublicKey,
}

impl CurveInitiate {
    async fn read_from<S>(
        stream: &mut S,
        timeout: Option<Duration>,
        server_keypair: &CurveKeyPair,
        server_short_keypair: &CurveKeyPair,
        client_short_public: &CurvePublicKey,
        cookie_key: &[u8; CURVE_KEY_SIZE],
    ) -> Result<Self, ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::read_exact_with_timeout;

        read_command_prefix(stream, CURVE_INITIATE, timeout).await?;

        let cookie = vec![0u8; 96];
        let buf_result = read_exact_with_timeout(stream, cookie, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, cookie) = buf_result;
        result?;

        let initiate_nonce = vec![0u8; 8];
        let buf_result = read_exact_with_timeout(stream, initiate_nonce, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, initiate_nonce) = buf_result;
        result?;

        let initiate_box = vec![0u8; 144];
        let buf_result = read_exact_with_timeout(stream, initiate_box, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, initiate_box) = buf_result;
        result?;

        let initiate_shared = server_short_keypair
            .secret
            .diffie_hellman(client_short_public)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut initiate_nonce_full = [0u8; CURVE_NONCE_SIZE];
        initiate_nonce_full[..CURVE_INITIATE_NONCE_PREFIX.len()]
            .copy_from_slice(CURVE_INITIATE_NONCE_PREFIX);
        initiate_nonce_full[CURVE_INITIATE_NONCE_PREFIX.len()..].copy_from_slice(&initiate_nonce);

        let initiate_plaintext = CurveBox::new(&initiate_shared)
            .decrypt(&initiate_box, &initiate_nonce_full)
            .map_err(|_| ZmtpError::Protocol)?;

        if initiate_plaintext.len() < CURVE_KEY_SIZE + 96 {
            return Err(ZmtpError::Protocol);
        }

        let mut client_public_bytes = [0u8; CURVE_KEY_SIZE];
        client_public_bytes.copy_from_slice(&initiate_plaintext[..CURVE_KEY_SIZE]);
        let client_public = CurvePublicKey::from_bytes(client_public_bytes);

        let vouch_bytes = &initiate_plaintext[CURVE_KEY_SIZE..CURVE_KEY_SIZE + 96];
        let mut vouch_nonce = [0u8; 16];
        vouch_nonce.copy_from_slice(&vouch_bytes[..16]);
        let mut vouch_nonce_full = [0u8; CURVE_NONCE_SIZE];
        vouch_nonce_full[..CURVE_VOUCH_NONCE_PREFIX.len()]
            .copy_from_slice(CURVE_VOUCH_NONCE_PREFIX);
        vouch_nonce_full[CURVE_VOUCH_NONCE_PREFIX.len()..].copy_from_slice(&vouch_nonce);

        let vouch_shared = server_short_keypair
            .secret
            .diffie_hellman(&client_public)
            .map_err(|_| ZmtpError::Protocol)?;
        let vouch_plaintext = CurveBox::new(&vouch_shared)
            .decrypt(&vouch_bytes[16..], &vouch_nonce_full)
            .map_err(|_| ZmtpError::Protocol)?;

        if vouch_plaintext.len() != CURVE_KEY_SIZE * 2 {
            return Err(ZmtpError::Protocol);
        }

        let mut vouch_client_short = [0u8; CURVE_KEY_SIZE];
        vouch_client_short.copy_from_slice(&vouch_plaintext[..CURVE_KEY_SIZE]);
        let mut vouch_server_public = [0u8; CURVE_KEY_SIZE];
        vouch_server_public.copy_from_slice(&vouch_plaintext[CURVE_KEY_SIZE..]);

        if vouch_client_short != *client_short_public.as_bytes()
            || vouch_server_public != *server_keypair.public.as_bytes()
        {
            return Err(ZmtpError::Protocol);
        }

        let mut cookie_nonce = [0u8; 16];
        cookie_nonce.copy_from_slice(&cookie[..16]);
        let mut cookie_nonce_full = [0u8; CURVE_NONCE_SIZE];
        cookie_nonce_full[..CURVE_COOKIE_NONCE_PREFIX.len()]
            .copy_from_slice(CURVE_COOKIE_NONCE_PREFIX);
        cookie_nonce_full[CURVE_COOKIE_NONCE_PREFIX.len()..].copy_from_slice(&cookie_nonce);

        let cookie_shared = CurveSharedSecret::from_bytes(*cookie_key);
        let cookie_plaintext = CurveBox::new(&cookie_shared)
            .decrypt(&cookie[16..], &cookie_nonce_full)
            .map_err(|_| ZmtpError::Protocol)?;

        if cookie_plaintext.len() != CURVE_KEY_SIZE * 2 {
            return Err(ZmtpError::Protocol);
        }

        let mut cookie_client_short = [0u8; CURVE_KEY_SIZE];
        cookie_client_short.copy_from_slice(&cookie_plaintext[..CURVE_KEY_SIZE]);
        let mut cookie_server_secret = [0u8; CURVE_KEY_SIZE];
        cookie_server_secret.copy_from_slice(&cookie_plaintext[CURVE_KEY_SIZE..]);

        if cookie_client_short != *client_short_public.as_bytes() {
            return Err(ZmtpError::Protocol);
        }
        if CurveSecretKey::from_bytes(cookie_server_secret).public_key()
            != server_short_keypair.public
        {
            return Err(ZmtpError::Protocol);
        }

        Ok(Self { client_public })
    }
}

struct CurveReady;

impl CurveReady {
    async fn read_from<S>(
        stream: &mut S,
        timeout: Option<Duration>,
        client_short_keypair: &CurveKeyPair,
        server_short_public: &CurvePublicKey,
    ) -> Result<Self, ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::read_exact_with_timeout;

        read_command_prefix(stream, CURVE_READY, timeout).await?;

        let ready_nonce = vec![0u8; 8];
        let buf_result = read_exact_with_timeout(stream, ready_nonce, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, ready_nonce) = buf_result;
        result?;

        let ready_box = vec![0u8; 16];
        let buf_result = read_exact_with_timeout(stream, ready_box, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, ready_box) = buf_result;
        result?;

        let shared_secret = client_short_keypair
            .secret
            .diffie_hellman(server_short_public)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..CURVE_READY_NONCE_PREFIX.len()].copy_from_slice(CURVE_READY_NONCE_PREFIX);
        nonce[CURVE_READY_NONCE_PREFIX.len()..].copy_from_slice(&ready_nonce);

        let metadata = CurveBox::new(&shared_secret)
            .decrypt(&ready_box, &nonce)
            .map_err(|_| ZmtpError::Protocol)?;
        if !metadata.is_empty() {
            return Err(ZmtpError::Protocol);
        }

        Ok(Self)
    }
}

struct CurveMessageFrame<'a> {
    counter: u64,
    ciphertext: &'a [u8],
}

impl<'a> CurveMessageFrame<'a> {
    fn parse(message: &'a [u8]) -> Result<Self, CurveError> {
        let command_len = CURVE_MESSAGE.len();
        if message.len() < command_len + CURVE_MESSAGE_NONCE_SIZE {
            return Err(CurveError::ProtocolViolation);
        }

        if &message[..command_len] != CURVE_MESSAGE {
            return Err(CurveError::ProtocolViolation);
        }

        let counter = u64::from_be_bytes(
            message[command_len..command_len + CURVE_MESSAGE_NONCE_SIZE]
                .try_into()
                .map_err(|_| CurveError::ProtocolViolation)?,
        );

        Ok(Self {
            counter,
            ciphertext: &message[command_len + CURVE_MESSAGE_NONCE_SIZE..],
        })
    }
}

struct CurveSessionCipher {
    cipher: CurveBox,
    send_nonce: u64,
    recv_nonce: u64,
    send_prefix: [u8; 16],
    recv_prefix: [u8; 16],
}

impl CurveSessionCipher {
    fn new(shared_secret: CurveSharedSecret, send_prefix: [u8; 16], recv_prefix: [u8; 16]) -> Self {
        Self {
            cipher: CurveBox::new(&shared_secret),
            send_nonce: 0,
            recv_nonce: 0,
            send_prefix,
            recv_prefix,
        }
    }

    fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Bytes, CurveError> {
        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..16].copy_from_slice(&self.send_prefix);
        let counter = self.send_nonce;
        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or(CurveError::ProtocolViolation)?;
        nonce[16..].copy_from_slice(&counter.to_be_bytes());

        let ciphertext = self.cipher.encrypt(plaintext, &nonce)?;
        let mut message = BytesMut::new();
        message.extend_from_slice(CURVE_MESSAGE);
        message.extend_from_slice(&nonce[16..]);
        message.extend_from_slice(&ciphertext);
        Ok(message.freeze())
    }

    fn decrypt_message(&mut self, message: &[u8]) -> Result<Bytes, CurveError> {
        let frame = CurveMessageFrame::parse(message)?;
        if frame.counter < self.recv_nonce {
            return Err(CurveError::ProtocolViolation);
        }
        let next_recv_nonce = frame
            .counter
            .checked_add(1)
            .ok_or(CurveError::ProtocolViolation)?;

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..16].copy_from_slice(&self.recv_prefix);
        nonce[16..].copy_from_slice(&message[CURVE_MESSAGE.len()..CURVE_MESSAGE.len() + 8]);

        let plaintext = self.cipher.decrypt(frame.ciphertext, &nonce)?;
        self.recv_nonce = next_recv_nonce;
        Ok(Bytes::from(plaintext))
    }
}

/// CURVE-specific errors
#[derive(Debug, Error)]
pub enum CurveError {
    /// Symmetric encryption failed.
    #[error("Encryption failed")]
    EncryptionFailed,
    /// Symmetric decryption or authentication-tag verification failed.
    #[error("Decryption failed")]
    DecryptionFailed,
    /// A key did not have the expected length.
    #[error("Invalid key size")]
    InvalidKeySize,
    /// A nonce had an unexpected format or length.
    #[error("Invalid nonce")]
    InvalidNonce,
    /// The peer violated the CurveZMQ protocol.
    #[error("Protocol violation")]
    ProtocolViolation,
    /// The peer's identity could not be verified.
    #[error("Authentication failed")]
    AuthenticationFailed,
    /// An underlying I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// CURVE client state machine
pub struct CurveClient {
    /// Client's long-term key pair
    client_keypair: CurveKeyPair,
    /// Server's long-term public key.
    server_public: CurvePublicKey,
    /// Client's short-term (ephemeral) key pair
    client_short_keypair: CurveKeyPair,
    /// Server's short-term public key (received in WELCOME)
    server_short_public: Option<CurvePublicKey>,
    /// Server cookie received in WELCOME.
    welcome_cookie: Option<[u8; 96]>,
    /// Message cipher (after READY)
    session_cipher: Option<CurveSessionCipher>,
}

impl CurveClient {
    /// Create new CURVE client
    pub fn new(client_keypair: CurveKeyPair, server_public: CurvePublicKey) -> Self {
        Self {
            client_keypair,
            server_public,
            client_short_keypair: CurveKeyPair::generate(),
            server_short_public: None,
            welcome_cookie: None,
            session_cipher: None,
        }
    }

    /// Perform client handshake
    pub async fn handshake<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.send_hello(stream, timeout).await?;
        self.recv_welcome(stream, timeout).await?;
        self.send_initiate(stream, timeout).await?;
        self.recv_ready(stream, timeout).await?;
        Ok(())
    }

    /// Send HELLO command
    async fn send_hello<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncWrite + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::write_all_with_timeout;

        debug!("[CURVE CLIENT] Sending HELLO");

        let mut hello = BytesMut::new();
        hello.extend_from_slice(CURVE_HELLO);

        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&[0u8; 72]);
        hello.extend_from_slice(self.client_short_keypair.public.as_bytes());

        let (short_nonce, nonce) = random_nonce::<8>(CURVE_HELLO_NONCE_PREFIX);
        hello.extend_from_slice(&short_nonce);

        let shared_secret = self
            .client_short_keypair
            .secret
            .diffie_hellman(&self.server_public)
            .map_err(|_| ZmtpError::Protocol)?;
        let proof = CurveBox::new(&shared_secret)
            .encrypt(&[0u8; 64], &nonce)
            .map_err(|_| ZmtpError::Protocol)?;
        hello.extend_from_slice(&proof);

        let buf_result = write_all_with_timeout(stream, hello.freeze().to_vec(), timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, _) = buf_result;
        result.map_err(Into::into)
    }

    /// Receive WELCOME command
    async fn recv_welcome<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        debug!("[CURVE CLIENT] Waiting for WELCOME");
        let welcome = CurveWelcome::read_from(
            stream,
            timeout,
            &self.client_short_keypair,
            &self.server_public,
        )
        .await?;
        self.server_short_public = Some(welcome.server_short_public);
        self.welcome_cookie = Some(welcome.cookie);

        debug!("[CURVE CLIENT] Received WELCOME");
        Ok(())
    }

    /// Send INITIATE command
    async fn send_initiate<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncWrite + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::write_all_with_timeout;

        debug!("[CURVE CLIENT] Sending INITIATE");

        let server_short_public = self.server_short_public.ok_or(ZmtpError::Protocol)?;
        let cookie = self.welcome_cookie.take().ok_or(ZmtpError::Protocol)?;

        let (vouch_short_nonce, vouch_nonce) = random_nonce::<16>(CURVE_VOUCH_NONCE_PREFIX);
        let vouch_shared = self
            .client_keypair
            .secret
            .diffie_hellman(&server_short_public)
            .map_err(|_| ZmtpError::Protocol)?;
        let mut vouch_plaintext = BytesMut::new();
        vouch_plaintext.extend_from_slice(self.client_short_keypair.public.as_bytes());
        vouch_plaintext.extend_from_slice(self.server_public.as_bytes());
        let vouch_box = CurveBox::new(&vouch_shared)
            .encrypt(&vouch_plaintext, &vouch_nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut initiate_plaintext = BytesMut::new();
        initiate_plaintext.extend_from_slice(self.client_keypair.public.as_bytes());
        initiate_plaintext.extend_from_slice(&vouch_short_nonce);
        initiate_plaintext.extend_from_slice(&vouch_box);

        let (initiate_short_nonce, initiate_nonce) = random_nonce::<8>(CURVE_INITIATE_NONCE_PREFIX);
        let initiate_shared = self
            .client_short_keypair
            .secret
            .diffie_hellman(&server_short_public)
            .map_err(|_| ZmtpError::Protocol)?;
        let initiate_box = CurveBox::new(&initiate_shared)
            .encrypt(&initiate_plaintext, &initiate_nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut initiate = BytesMut::new();
        initiate.extend_from_slice(CURVE_INITIATE);
        initiate.extend_from_slice(&cookie);
        initiate.extend_from_slice(&initiate_short_nonce);
        initiate.extend_from_slice(&initiate_box);

        let buf_result = write_all_with_timeout(stream, initiate.freeze().to_vec(), timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, _) = buf_result;
        result.map_err(Into::into)
    }

    /// Receive READY command
    async fn recv_ready<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        debug!("[CURVE CLIENT] Waiting for READY");
        let server_short_public = self.server_short_public.ok_or(ZmtpError::Protocol)?;
        let _ready = CurveReady::read_from(
            stream,
            timeout,
            &self.client_short_keypair,
            &server_short_public,
        )
        .await?;

        // Compute shared secret for message encryption
        let shared_secret = self
            .client_short_keypair
            .secret
            .diffie_hellman(&server_short_public)
            .map_err(|_| ZmtpError::Protocol)?;

        self.session_cipher = Some(CurveSessionCipher::new(
            shared_secret,
            *b"CurveZMQMESSAGEC",
            *b"CurveZMQMESSAGES",
        ));

        debug!("[CURVE CLIENT] Handshake complete");
        Ok(())
    }

    /// Encrypt a message
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Bytes, CurveError> {
        let cipher = self
            .session_cipher
            .as_mut()
            .ok_or(CurveError::ProtocolViolation)?;
        cipher.encrypt_message(plaintext)
    }

    /// Decrypt a message
    pub fn decrypt_message(&mut self, message: &[u8]) -> Result<Bytes, CurveError> {
        let cipher = self
            .session_cipher
            .as_mut()
            .ok_or(CurveError::ProtocolViolation)?;
        cipher.decrypt_message(message)
    }
}

/// CURVE server state machine
pub struct CurveServer {
    /// Server's long-term key pair.
    server_keypair: CurveKeyPair,
    /// Server's short-term (ephemeral) key pair
    server_short_keypair: CurveKeyPair,
    /// Cookie key used to authenticate the server's transient key pair.
    cookie_key: Option<[u8; CURVE_KEY_SIZE]>,
    /// Client's short-term public key (received in HELLO)
    client_short_public: Option<CurvePublicKey>,
    /// Client's long-term public key (received in INITIATE)
    client_public: Option<CurvePublicKey>,
    /// Send nonce counter
    session_cipher: Option<CurveSessionCipher>,
}

impl CurveServer {
    /// Create new CURVE server
    pub fn new(server_keypair: CurveKeyPair) -> Self {
        Self {
            server_keypair,
            server_short_keypair: CurveKeyPair::generate(),
            cookie_key: None,
            client_short_public: None,
            client_public: None,
            session_cipher: None,
        }
    }

    /// Perform server handshake
    pub async fn handshake<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<CurvePublicKey, ZmtpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.recv_hello(stream, timeout).await?;
        self.send_welcome(stream, timeout).await?;
        self.recv_initiate(stream, timeout).await?;
        self.send_ready(stream, timeout).await?;

        // Return client's public key for authentication
        Ok(self.client_public.unwrap())
    }

    /// Receive HELLO command
    async fn recv_hello<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        debug!("[CURVE SERVER] Waiting for HELLO");
        let hello = CurveHello::read_from(stream, timeout, &self.server_keypair).await?;
        self.client_short_public = Some(hello.client_short_public);

        debug!("[CURVE SERVER] Received HELLO");
        Ok(())
    }

    /// Send WELCOME command
    async fn send_welcome<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncWrite + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::write_all_with_timeout;

        debug!("[CURVE SERVER] Sending WELCOME");

        let client_short_public = self.client_short_public.ok_or(ZmtpError::Protocol)?;
        let (welcome_short_nonce, welcome_nonce) = random_nonce::<16>(CURVE_WELCOME_NONCE_PREFIX);
        let (cookie_short_nonce, cookie_nonce) = random_nonce::<16>(CURVE_COOKIE_NONCE_PREFIX);

        let cookie_key = {
            let mut key = [0u8; CURVE_KEY_SIZE];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };
        self.cookie_key = Some(cookie_key);

        let mut cookie_plaintext = BytesMut::new();
        cookie_plaintext.extend_from_slice(client_short_public.as_bytes());
        let server_short_secret = self.server_short_keypair.secret.0.to_bytes();
        cookie_plaintext.extend_from_slice(&server_short_secret);

        let cookie_shared = CurveSharedSecret::from_bytes(cookie_key);
        let cookie_box = CurveBox::new(&cookie_shared)
            .encrypt(&cookie_plaintext, &cookie_nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut cookie = BytesMut::new();
        cookie.extend_from_slice(&cookie_short_nonce);
        cookie.extend_from_slice(&cookie_box);

        let mut welcome_plaintext = BytesMut::new();
        welcome_plaintext.extend_from_slice(self.server_short_keypair.public.as_bytes());
        welcome_plaintext.extend_from_slice(&cookie);

        let welcome_shared = self
            .server_keypair
            .secret
            .diffie_hellman(&client_short_public)
            .map_err(|_| ZmtpError::Protocol)?;

        let welcome_box = CurveBox::new(&welcome_shared)
            .encrypt(&welcome_plaintext, &welcome_nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut welcome = BytesMut::new();
        welcome.extend_from_slice(CURVE_WELCOME);
        welcome.extend_from_slice(&welcome_short_nonce);
        welcome.extend_from_slice(&welcome_box);

        let buf_result = write_all_with_timeout(stream, welcome.freeze().to_vec(), timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, _) = buf_result;
        result.map_err(Into::into)
    }

    /// Receive INITIATE command
    async fn recv_initiate<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncRead + Unpin,
    {
        debug!("[CURVE SERVER] Waiting for INITIATE");
        if self.client_short_public.is_none() {
            return Err(ZmtpError::Protocol);
        }

        let client_short_public = self.client_short_public.ok_or(ZmtpError::Protocol)?;
        let cookie_key = self.cookie_key.ok_or(ZmtpError::Protocol)?;
        let initiate = CurveInitiate::read_from(
            stream,
            timeout,
            &self.server_keypair,
            &self.server_short_keypair,
            &client_short_public,
            &cookie_key,
        )
        .await?;
        self.client_public = Some(initiate.client_public);
        self.cookie_key = None;

        debug!("[CURVE SERVER] Received INITIATE");
        Ok(())
    }

    /// Send READY command
    async fn send_ready<S>(
        &mut self,
        stream: &mut S,
        timeout: Option<Duration>,
    ) -> Result<(), ZmtpError>
    where
        S: AsyncWrite + Unpin,
    {
        use compio::buf::BufResult;
        use monocoque_core::timeout::write_all_with_timeout;

        debug!("[CURVE SERVER] Sending READY");

        let client_short_public = self.client_short_public.ok_or(ZmtpError::Protocol)?;
        let (ready_short_nonce, ready_nonce) = random_nonce::<8>(CURVE_READY_NONCE_PREFIX);
        let shared_secret = self
            .server_short_keypair
            .secret
            .diffie_hellman(&client_short_public)
            .map_err(|_| ZmtpError::Protocol)?;

        let ready_box = CurveBox::new(&shared_secret)
            .encrypt(&[], &ready_nonce)
            .map_err(|_| ZmtpError::Protocol)?;

        let mut ready = BytesMut::new();
        ready.extend_from_slice(CURVE_READY);
        ready.extend_from_slice(&ready_short_nonce);
        ready.extend_from_slice(&ready_box);
        let buf_result = write_all_with_timeout(stream, ready, timeout)
            .await
            .map_err(ZmtpError::from)?;
        let BufResult(result, _) = buf_result;
        result?;

        // Compute shared secret for message encryption
        self.session_cipher = Some(CurveSessionCipher::new(
            shared_secret,
            *b"CurveZMQMESSAGES",
            *b"CurveZMQMESSAGEC",
        ));

        debug!("[CURVE SERVER] Handshake complete");
        Ok(())
    }

    /// Encrypt a message
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Bytes, CurveError> {
        let cipher = self
            .session_cipher
            .as_mut()
            .ok_or(CurveError::ProtocolViolation)?;
        cipher.encrypt_message(plaintext)
    }

    /// Decrypt a message
    pub fn decrypt_message(&mut self, message: &[u8]) -> Result<Bytes, CurveError> {
        let cipher = self
            .session_cipher
            .as_mut()
            .ok_or(CurveError::ProtocolViolation)?;
        cipher.decrypt_message(message)
    }
}

/// Create a ZAP request for CURVE authentication
pub fn create_curve_zap_request(
    request_id: impl Into<String>,
    domain: impl Into<String>,
    address: impl Into<String>,
    identity: Bytes,
    client_public_key: &CurvePublicKey,
) -> ZapRequest {
    ZapRequest::new(
        request_id,
        domain,
        address,
        identity,
        ZapMechanism::Curve,
        vec![Bytes::copy_from_slice(client_public_key.as_bytes())],
    )
}

/// CURVE server handshake with ZAP authentication
///
/// Performs CURVE handshake and authenticates the client via ZAP protocol.
/// After receiving the client's public key during INITIATE, sends a ZAP request
/// to verify the client is authorized. On failure, sends a ZMTP ERROR command
/// to the client before closing the connection.
///
/// # Arguments
/// * `stream` - Network stream for the connection
/// * `server_keypair` - Server's long-term CURVE key pair
/// * `domain` - ZAP authentication domain
/// * `timeout` - Optional timeout for ZAP request
/// * `peer_addr` - Remote peer address for ZAP logging (pass peer socket's addr string)
///
/// # Returns
/// * `Ok(CurvePublicKey)` - Authenticated client's public key
/// * `Err(ZmtpError)` - Authentication failed or protocol error
///
/// # Example
///
/// ```rust,no_run
/// use monocoque_zmtp::security::curve::{curve_server_handshake_zap, CurveKeyPair};
/// use std::time::Duration;
///
/// async fn accept_curve_client(mut stream: compio::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
///     let peer = stream.peer_addr()?.to_string();
///     let server_keypair = CurveKeyPair::generate();
///     let client_key = curve_server_handshake_zap(
///         &mut stream,
///         server_keypair,
///         "production".to_string(),
///         Some(Duration::from_secs(5)),
///         &peer,
///     ).await?;
///     println!("Authenticated client: {:?}", client_key);
///     Ok(())
/// }
/// ```
pub async fn curve_server_handshake_zap<S>(
    stream: &mut S,
    server_keypair: CurveKeyPair,
    domain: String,
    timeout: Option<Duration>,
    peer_addr: &str,
) -> Result<CurvePublicKey, ZmtpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use crate::security::zap_client::ZapClient;

    debug!("[CURVE SERVER ZAP] Starting ZAP-authenticated handshake");

    // Perform CURVE handshake
    let mut curve_server = CurveServer::new(server_keypair);
    let client_public_key = curve_server.handshake(stream, timeout).await?;

    debug!("[CURVE SERVER ZAP] CURVE handshake complete, authenticating via ZAP");

    // Create ZAP client
    let zap_timeout = timeout.unwrap_or(Duration::from_secs(5));
    let mut zap_client = ZapClient::new(zap_timeout).map_err(|e| {
        warn!("[CURVE SERVER ZAP] Failed to create ZAP client: {}", e);
        ZmtpError::AuthenticationFailed
    })?;

    let zap_response = zap_client
        .authenticate_curve(client_public_key.as_bytes(), &domain, peer_addr)
        .await
        .map_err(|e| {
            warn!("[CURVE SERVER ZAP] ZAP request failed: {}", e);
            ZmtpError::AuthenticationFailed
        })?;

    // Check ZAP response status
    if matches!(zap_response.status_code, ZapStatus::Success) {
        debug!(
            "[CURVE SERVER ZAP] Authentication successful for client key: {:?}",
            client_public_key
        );
        Ok(client_public_key)
    } else {
        warn!(
            "[CURVE SERVER ZAP] Authentication failed for {}: {} (status: {:?})",
            peer_addr, zap_response.status_text, zap_response.status_code
        );

        // Send ZMTP ERROR command to the client so it knows why we're closing
        send_zmtp_error(stream, &zap_response.status_text).await;

        Err(ZmtpError::AuthenticationFailed)
    }
}

/// Send a ZMTP ERROR command frame to the peer.
///
/// Best-effort: errors are silently ignored since we're already rejecting the connection.
async fn send_zmtp_error<S>(stream: &mut S, reason: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use bytes::BytesMut;
    use compio::buf::BufResult;
    use compio::io::AsyncWrite;
    // ZMTP ERROR command body: [5]"ERROR" [reason_len][reason...]
    // Command name is "ERROR" (5 bytes), prefixed with its 1-byte length
    let reason_bytes = reason.as_bytes();
    let reason_len = reason_bytes.len().min(255) as u8;

    let mut body = BytesMut::with_capacity(7 + reason_len as usize);
    body.extend_from_slice(b"\x05ERROR"); // command name with length prefix
    body.extend_from_slice(&[reason_len]);
    body.extend_from_slice(&reason_bytes[..reason_len as usize]);

    // Frame: flags=0x04 (COMMAND), body_len, body
    let body_len = body.len();
    let mut frame = BytesMut::with_capacity(2 + body_len);
    frame.extend_from_slice(&[0x04, body_len as u8]);
    frame.extend_from_slice(&body);

    let BufResult(_, _) = AsyncWrite::write(stream, frame.freeze()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = CurveKeyPair::generate();
        assert_eq!(keypair.public.as_bytes().len(), CURVE_KEY_SIZE);

        // Verify public key matches secret key
        let derived_public = keypair.secret.public_key();
        assert_eq!(keypair.public, derived_public);
    }

    #[test]
    fn curve_keypair_rejects_public_key_that_does_not_match_secret_key() {
        let public = CurveKeyPair::generate().public;
        let secret = CurveSecretKey::generate();
        let keypair = CurveKeyPair::from_keys(public, secret);

        assert_eq!(
            keypair.public,
            keypair.secret.public_key(),
            "CURVE keypair accepted a public key that does not match its secret key"
        );
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = CurveKeyPair::generate();
        let bob = CurveKeyPair::generate();

        let alice_shared = alice.secret.diffie_hellman(&bob.public).unwrap();
        let bob_shared = bob.secret.diffie_hellman(&alice.public).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn diffie_hellman_rejects_non_contributory_peer_public_key() {
        let secret = CurveSecretKey::generate();
        let low_order_public = CurvePublicKey::from_bytes([0u8; CURVE_KEY_SIZE]);

        let shared = secret.diffie_hellman(&low_order_public);

        assert!(
            shared.is_err(),
            "CURVE accepted a non-contributory X25519 peer key and produced an all-zero shared secret"
        );
    }

    #[test]
    fn test_curve_box_encrypt_decrypt() {
        let box_ = curve_box([42u8; CURVE_KEY_SIZE]);

        let plaintext = b"Hello, CURVE!";
        let nonce = [1u8; CURVE_NONCE_SIZE];

        let ciphertext = box_.encrypt(plaintext, &nonce).unwrap();
        let decrypted = box_.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn curve_box_uses_message_counter_bytes_in_aead_nonce() {
        let box_ = curve_box([42u8; CURVE_KEY_SIZE]);
        let plaintext = b"same plaintext";

        let mut nonce_one = [0u8; CURVE_NONCE_SIZE];
        nonce_one[..16].copy_from_slice(b"CurveZMQMESSAGEC");
        nonce_one[16..].copy_from_slice(&1u64.to_be_bytes());

        let mut nonce_two = [0u8; CURVE_NONCE_SIZE];
        nonce_two[..16].copy_from_slice(b"CurveZMQMESSAGEC");
        nonce_two[16..].copy_from_slice(&2u64.to_be_bytes());

        let ciphertext_one = box_.encrypt(plaintext, &nonce_one).unwrap();
        let ciphertext_two = box_.encrypt(plaintext, &nonce_two).unwrap();

        assert_ne!(
            ciphertext_one, ciphertext_two,
            "CURVE encryption ignored the message counter bytes and reused the AEAD nonce"
        );
    }

    fn rfc_curve_hello(version: [u8; 2], client_short_public: &[u8; CURVE_KEY_SIZE]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(CURVE_HELLO);
        hello.extend_from_slice(&version);
        hello.extend_from_slice(&[0u8; 72]);
        hello.extend_from_slice(client_short_public);
        hello.extend_from_slice(&[0u8; 8]);
        hello.extend_from_slice(&[0u8; 80]);
        hello
    }

    async fn server_recv_hello_result(command: Vec<u8>) -> Result<(), ZmtpError> {
        use compio::buf::BufResult;
        use compio::net::{TcpListener, TcpStream};
        use compio::runtime;
        use monocoque_core::timeout::write_all_with_timeout;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = runtime::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut server = CurveServer::new(CurveKeyPair::generate());
            server
                .recv_hello(&mut stream, Some(Duration::from_secs(1)))
                .await
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let BufResult(write_result, _) =
            write_all_with_timeout(&mut stream, command, Some(Duration::from_secs(1)))
                .await
                .unwrap();
        write_result.unwrap();

        server_task.await
    }

    fn rfc_curve_initiate() -> Vec<u8> {
        let mut initiate = Vec::new();
        initiate.extend_from_slice(CURVE_INITIATE);
        initiate.extend_from_slice(&[0u8; 96]);
        initiate.extend_from_slice(&[0u8; 8]);
        initiate.extend_from_slice(&[0u8; 144]);
        initiate
    }

    fn curve_box(shared_secret: [u8; CURVE_KEY_SIZE]) -> CurveBox {
        let shared_secret = CurveSharedSecret::from_bytes(shared_secret);
        CurveBox::new(&shared_secret)
    }

    fn client_session_cipher(shared_secret: &[u8; CURVE_KEY_SIZE]) -> CurveSessionCipher {
        CurveSessionCipher::new(
            CurveSharedSecret::from_bytes(*shared_secret),
            *b"CurveZMQMESSAGEC",
            *b"CurveZMQMESSAGES",
        )
    }

    fn server_session_cipher(shared_secret: &[u8; CURVE_KEY_SIZE]) -> CurveSessionCipher {
        CurveSessionCipher::new(
            CurveSharedSecret::from_bytes(*shared_secret),
            *b"CurveZMQMESSAGES",
            *b"CurveZMQMESSAGEC",
        )
    }

    async fn server_recv_initiate_result(
        command: Vec<u8>,
        hello_completed: bool,
    ) -> Result<(), ZmtpError> {
        use compio::buf::BufResult;
        use compio::net::{TcpListener, TcpStream};
        use compio::runtime;
        use monocoque_core::timeout::write_all_with_timeout;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = runtime::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut server = CurveServer::new(CurveKeyPair::generate());
            if hello_completed {
                server.client_short_public = Some(CurveKeyPair::generate().public);
            }
            server
                .recv_initiate(&mut stream, Some(Duration::from_secs(1)))
                .await
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let BufResult(write_result, _) =
            write_all_with_timeout(&mut stream, command, Some(Duration::from_secs(1)))
                .await
                .unwrap();
        write_result.unwrap();

        server_task.await
    }

    #[compio::test]
    async fn curve_server_rejects_hello_with_unsupported_version() {
        let client_short = CurveKeyPair::generate();
        let hello = rfc_curve_hello([2, 0], client_short.public.as_bytes());
        let result = server_recv_hello_result(hello).await;
        assert!(
            result.is_err(),
            "CURVE server accepted a HELLO command with an unsupported version byte"
        );
    }

    #[compio::test]
    async fn curve_server_rejects_hello_with_all_zero_client_short_key() {
        let hello = rfc_curve_hello([1, 0], &[0u8; CURVE_KEY_SIZE]);
        let result = server_recv_hello_result(hello).await;
        assert!(
            result.is_err(),
            "CURVE server accepted an all-zero client short-term public key in HELLO"
        );
    }

    #[compio::test]
    async fn curve_server_rejects_hello_without_client_proof() {
        let client_short = CurveKeyPair::generate();
        let hello = rfc_curve_hello([1, 0], client_short.public.as_bytes());
        let result = server_recv_hello_result(hello).await;
        assert!(
            result.is_err(),
            "CURVE server accepted a HELLO command with an all-zero unauthenticated client proof"
        );
    }

    #[compio::test]
    async fn curve_server_rejects_initiate_without_client_proof() {
        let initiate = rfc_curve_initiate();
        let result = server_recv_initiate_result(initiate, true).await;
        assert!(
            result.is_err(),
            "CURVE server accepted an INITIATE command with an all-zero unauthenticated client proof"
        );
    }

    #[compio::test]
    async fn curve_server_rejects_initiate_before_hello() {
        let initiate = rfc_curve_initiate();
        let result = server_recv_initiate_result(initiate, false).await;
        assert!(
            result.is_err(),
            "CURVE server accepted INITIATE before a HELLO established the client short-term key"
        );
    }

    #[test]
    fn client_decrypt_message_accepts_valid_curve_message_command_header() {
        let box_ = curve_box([42u8; CURVE_KEY_SIZE]);

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..16].copy_from_slice(b"CurveZMQMESSAGES");
        nonce[16..].copy_from_slice(&1u64.to_be_bytes());

        let ciphertext = box_.encrypt(b"server message", &nonce).unwrap();
        let mut frame = BytesMut::new();
        frame.extend_from_slice(CURVE_MESSAGE);
        frame.extend_from_slice(&nonce[16..]);
        frame.extend_from_slice(&ciphertext);

        let client_keypair = CurveKeyPair::generate();
        let server_public = CurveKeyPair::generate().public;
        let mut client = CurveClient::new(client_keypair, server_public);
        client.session_cipher = Some(client_session_cipher(&[42u8; CURVE_KEY_SIZE]));

        let plaintext = client.decrypt_message(&frame).unwrap();

        assert_eq!(plaintext.as_ref(), b"server message");
    }

    #[test]
    fn decrypt_message_rejects_replayed_message_counter() {
        let box_ = curve_box([42u8; CURVE_KEY_SIZE]);

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..16].copy_from_slice(b"CurveZMQMESSAGES");
        nonce[16..].copy_from_slice(&1u64.to_be_bytes());

        let ciphertext = box_.encrypt(b"server message", &nonce).unwrap();
        let mut frame = BytesMut::new();
        frame.extend_from_slice(CURVE_MESSAGE);
        frame.extend_from_slice(&nonce[16..]);
        frame.extend_from_slice(&ciphertext);

        let client_keypair = CurveKeyPair::generate();
        let server_public = CurveKeyPair::generate().public;
        let mut client = CurveClient::new(client_keypair, server_public);
        client.session_cipher = Some(client_session_cipher(&[42u8; CURVE_KEY_SIZE]));

        client.decrypt_message(&frame).unwrap();
        let replay_result = client.decrypt_message(&frame);

        assert!(
            replay_result.is_err(),
            "CURVE accepted the same encrypted MESSAGE counter twice"
        );
    }

    #[compio::test]
    async fn curve_client_rejects_handshake_from_unconfigured_server_key() {
        use compio::net::{TcpListener, TcpStream};
        use compio::runtime;
        use std::time::Duration;

        let expected_server = CurveKeyPair::generate();
        let attacker_server = CurveKeyPair::generate();
        let client_keypair = CurveKeyPair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_task = runtime::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut server = CurveServer::new(attacker_server);
            let _ = server
                .handshake(&mut stream, Some(Duration::from_secs(1)))
                .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut client = CurveClient::new(client_keypair, expected_server.public);
        let result = client
            .handshake(&mut stream, Some(Duration::from_secs(1)))
            .await;

        assert!(
            result.is_err(),
            "CURVE client completed a handshake with a server whose key did not match the configured server public key"
        );

        let _ = peer_task.await;
    }

    #[compio::test]
    async fn curve_client_server_handshake_completes_with_expected_server_key() {
        use compio::net::{TcpListener, TcpStream};
        use compio::runtime;
        use std::time::Duration;

        let server_keypair = CurveKeyPair::generate();
        let expected_server_public = server_keypair.public;
        let client_keypair = CurveKeyPair::generate();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = runtime::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut server = CurveServer::new(server_keypair);
            server
                .handshake(&mut stream, Some(Duration::from_secs(1)))
                .await
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut client = CurveClient::new(client_keypair.clone(), expected_server_public);
        client
            .handshake(&mut stream, Some(Duration::from_secs(1)))
            .await
            .expect("client should complete CURVE handshake with the expected server key");

        let client_public = server_task
            .await
            .expect("server should complete CURVE handshake");
        assert_eq!(client_public, client_keypair.public);
    }

    #[compio::test]
    async fn curve_client_rejects_ready_without_server_proof() {
        use compio::buf::BufResult;
        use compio::net::{TcpListener, TcpStream};
        use compio::runtime;
        use monocoque_core::timeout::write_all_with_timeout;

        let client_keypair = CurveKeyPair::generate();
        let server_keypair = CurveKeyPair::generate();
        let mut client = CurveClient::new(client_keypair, server_keypair.public);
        client.server_short_public = Some(server_keypair.public);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_task = runtime::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let BufResult(write_result, _) =
                write_all_with_timeout(&mut stream, CURVE_READY.to_vec(), None)
                    .await
                    .unwrap();
            write_result.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result = client.recv_ready(&mut stream, None).await;

        assert!(
            result.is_err(),
            "CURVE client accepted a bare READY command without authenticated server proof"
        );

        let _ = peer_task.await;
    }

    #[test]
    fn server_decrypt_message_accepts_valid_curve_message_command_header() {
        let box_ = curve_box([43u8; CURVE_KEY_SIZE]);

        let mut nonce = [0u8; CURVE_NONCE_SIZE];
        nonce[..16].copy_from_slice(b"CurveZMQMESSAGEC");
        nonce[16..].copy_from_slice(&2u64.to_be_bytes());

        let ciphertext = box_.encrypt(b"client message", &nonce).unwrap();
        let mut frame = BytesMut::new();
        frame.extend_from_slice(CURVE_MESSAGE);
        frame.extend_from_slice(&nonce[16..]);
        frame.extend_from_slice(&ciphertext);

        let server_keypair = CurveKeyPair::generate();
        let mut server = CurveServer::new(server_keypair);
        server.session_cipher = Some(server_session_cipher(&[43u8; CURVE_KEY_SIZE]));

        let plaintext = server.decrypt_message(&frame).unwrap();

        assert_eq!(plaintext.as_ref(), b"client message");
    }

    #[test]
    fn decrypt_message_rejects_invalid_curve_message_command_header() {
        let client_keypair = CurveKeyPair::generate();
        let server_public = CurveKeyPair::generate().public;
        let mut client = CurveClient::new(client_keypair, server_public);
        client.session_cipher = Some(client_session_cipher(&[42u8; CURVE_KEY_SIZE]));

        let mut frame = BytesMut::new();
        frame.extend_from_slice(b"\x05READY");
        frame.extend_from_slice(&1u64.to_be_bytes());
        frame.extend_from_slice(&[0u8; CURVE_BOX_OVERHEAD]);

        assert!(matches!(
            client.decrypt_message(&frame),
            Err(CurveError::ProtocolViolation)
        ));
    }

    #[test]
    fn decrypt_message_rejects_missing_curve_message_nonce() {
        let client_keypair = CurveKeyPair::generate();
        let server_public = CurveKeyPair::generate().public;
        let mut client = CurveClient::new(client_keypair, server_public);
        client.session_cipher = Some(client_session_cipher(&[42u8; CURVE_KEY_SIZE]));

        assert!(matches!(
            client.decrypt_message(CURVE_MESSAGE),
            Err(CurveError::ProtocolViolation)
        ));
    }

    #[test]
    fn test_curve_zap_request() {
        let keypair = CurveKeyPair::generate();
        let request = create_curve_zap_request(
            "req123",
            "production",
            "192.168.1.100:5555",
            Bytes::from("client1"),
            &keypair.public,
        );

        assert_eq!(request.mechanism, ZapMechanism::Curve);
        assert_eq!(request.credentials.len(), 1);
        assert_eq!(request.credentials[0].len(), CURVE_KEY_SIZE);
    }
}
