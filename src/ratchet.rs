use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use ksi_double_ratchet::{CryptoProvider, DecryptError, DoubleRatchet, KeyPair as DrKeyPair};
use rand_core_04::{CryptoRng, RngCore};
use sha2::Sha256;
use std::hash::Hash;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const KEY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; KEY_SIZE]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<X25519PublicKey> for PublicKey {
    fn from(key: X25519PublicKey) -> Self {
        Self(*key.as_bytes())
    }
}

impl From<PublicKey> for X25519PublicKey {
    fn from(key: PublicKey) -> Self {
        X25519PublicKey::from(key.0)
    }
}

#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish()
    }
}

impl DrKeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut secret_bytes = [0u8; KEY_SIZE];

        rng.fill_bytes(&mut secret_bytes);

        let secret = StaticSecret::from(secret_bytes);

        let public = X25519PublicKey::from(&secret);

        Self {
            secret,
            public: PublicKey(*public.as_bytes()),
        }
    }

    fn public(&self) -> &Self::PublicKey {
        &self.public
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RootKey(pub [u8; KEY_SIZE]);

#[derive(Clone, Copy, Debug)]
pub struct ChainKey(pub [u8; KEY_SIZE]);

#[derive(Clone, Copy, Debug)]
pub struct MessageKey(pub [u8; KEY_SIZE]);

#[derive(Clone, Copy, Debug)]
pub struct SharedSecret(pub [u8; KEY_SIZE]);

pub struct CryptoProviderImpl;

fn hkdf_expand(key: &[u8], info: &[u8]) -> [u8; KEY_SIZE] {
    let hkdf = Hkdf::<Sha256>::new(None, key);

    let mut output = [0u8; KEY_SIZE];

    hkdf.expand(info, &mut output)
        .expect("HKDF output length invalid");

    output
}

impl CryptoProvider for CryptoProviderImpl {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = SharedSecret;
    type RootKey = RootKey;
    type ChainKey = ChainKey;
    type MessageKey = MessageKey;

    fn diffie_hellman(us: &Self::KeyPair, them: &Self::PublicKey) -> Self::SharedSecret {
        let public = X25519PublicKey::from(them.0);

        let shared = us.secret.diffie_hellman(&public);
        if shared.as_bytes().iter().all(|&b| b == 0) {
            panic!("Invalid X25519 public key");
        }

        SharedSecret(*shared.as_bytes())
    }

    fn kdf_rk(
        root_key: &Self::RootKey,
        shared_secret: &Self::SharedSecret,
    ) -> (Self::RootKey, Self::ChainKey) {
        let hkdf = Hkdf::<Sha256>::new(Some(&root_key.0), &shared_secret.0);

        let mut output = [0u8; 64];

        hkdf.expand(b"private-messenger-root-ratchet", &mut output)
            .expect("HKDF output length invalid");

        let mut root = [0u8; KEY_SIZE];
        let mut chain = [0u8; KEY_SIZE];

        root.copy_from_slice(&output[..KEY_SIZE]);

        chain.copy_from_slice(&output[KEY_SIZE..]);

        (RootKey(root), ChainKey(chain))
    }

    fn kdf_ck(chain_key: &Self::ChainKey) -> (Self::ChainKey, Self::MessageKey) {
        let next_chain = hkdf_expand(&chain_key.0, b"private-messenger-chain");

        let message_key = hkdf_expand(&chain_key.0, b"private-messenger-message");

        (ChainKey(next_chain), MessageKey(message_key))
    }

    fn encrypt(key: &Self::MessageKey, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&Key::from(key.0));

        let nonce_bytes = hkdf_expand(&key.0, b"private-messenger-aead-nonce");

        let nonce_array: [u8; 12] = nonce_bytes[..12].try_into().expect("Invalid nonce length");

        let nonce = Nonce::try_from(nonce_array.as_slice()).expect("Invalid nonce");

        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .expect("AEAD encryption failed")
    }

    fn decrypt(
        key: &Self::MessageKey,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let cipher = ChaCha20Poly1305::new(&Key::from(key.0));

        let nonce_bytes = hkdf_expand(&key.0, b"private-messenger-aead-nonce");

        let nonce_array: [u8; 12] = nonce_bytes[..12]
            .try_into()
            .map_err(|_| DecryptError::DecryptFailure)?;

        let nonce =
            Nonce::try_from(nonce_array.as_slice()).map_err(|_| DecryptError::DecryptFailure)?;

        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| DecryptError::DecryptFailure)
    }
}

pub type Ratchet = DoubleRatchet<CryptoProviderImpl>;

pub fn root_key_from_shared_secret(shared_secret: [u8; KEY_SIZE]) -> RootKey {
    RootKey(shared_secret)
}

pub fn keypair_from_x25519(secret: [u8; KEY_SIZE]) -> KeyPair {
    let secret = StaticSecret::from(secret);

    let public = X25519PublicKey::from(&secret);

    KeyPair {
        secret,
        public: PublicKey(*public.as_bytes()),
    }
}
