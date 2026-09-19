use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core_04::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CHALLENGE_SIZE: usize = 32;
const HANDSHAKE_DOMAIN: &[u8] = b"private-messenger-handshake-v1";

pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    let mut challenge = [0u8; CHALLENGE_SIZE];

    crate::SystemRng.fill_bytes(&mut challenge);

    challenge
}

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let mut secret_bytes = [0u8; 32];

    crate::SystemRng.fill_bytes(&mut secret_bytes);

    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    (secret, public)
}

use sha2::{Digest, Sha256};

pub fn handshake_transcript_hash(
    challenge: &[u8; CHALLENGE_SIZE],
    server_identity: &VerifyingKey,
    client_identity: &VerifyingKey,
    server_x25519: &PublicKey,
    client_x25519: &PublicKey,
) -> [u8; 32] {
    let transcript = handshake_transcript(
        challenge,
        server_identity,
        client_identity,
        server_x25519,
        client_x25519,
    );
    let digest = Sha256::digest(&transcript);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn handshake_transcript(
    challenge: &[u8; CHALLENGE_SIZE],
    server_identity: &VerifyingKey,
    client_identity: &VerifyingKey,
    server_x25519: &PublicKey,
    client_x25519: &PublicKey,
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 1 + CHALLENGE_SIZE + 32 + 32 + 32 + 32);

    message.extend_from_slice(HANDSHAKE_DOMAIN);
    message.push(1u8); // protocol version

    message.extend_from_slice(challenge);

    message.extend_from_slice(server_identity.as_bytes());
    message.extend_from_slice(client_identity.as_bytes());

    message.extend_from_slice(server_x25519.as_bytes());
    message.extend_from_slice(client_x25519.as_bytes());

    message
}

pub fn sign_handshake_transcript(
    signing_key: &SigningKey,
    challenge: &[u8; CHALLENGE_SIZE],
    server_identity: &VerifyingKey,
    client_identity: &VerifyingKey,
    server_x25519: &PublicKey,
    client_x25519: &PublicKey,
) -> Signature {
    let message = handshake_transcript(
        challenge,
        server_identity,
        client_identity,
        server_x25519,
        client_x25519,
    );

    signing_key.sign(&message)
}

pub fn verify_handshake_transcript(
    verifying_key: &VerifyingKey,
    signature: &Signature,
    challenge: &[u8; CHALLENGE_SIZE],
    server_identity: &VerifyingKey,
    client_identity: &VerifyingKey,
    server_x25519: &PublicKey,
    client_x25519: &PublicKey,
) -> bool {
    let message = handshake_transcript(
        challenge,
        server_identity,
        client_identity,
        server_x25519,
        client_x25519,
    );

    verifying_key.verify(&message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (
        SigningKey,
        SigningKey,
        PublicKey,
        PublicKey,
        [u8; CHALLENGE_SIZE],
    ) {
        let server_signing = SigningKey::from_bytes(&[7u8; 32]);
        let client_signing = SigningKey::from_bytes(&[8u8; 32]);

        let server_x25519 = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let client_x25519 = PublicKey::from(&StaticSecret::from([10u8; 32]));

        let challenge = [11u8; CHALLENGE_SIZE];

        (
            server_signing,
            client_signing,
            server_x25519,
            client_x25519,
            challenge,
        )
    }

    #[test]
    fn transcript_signature_verifies() {
        let (server_signing, client_signing, server_x25519, client_x25519, challenge) = test_keys();

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let signature = sign_handshake_transcript(
            &server_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        );

        assert!(verify_handshake_transcript(
            &server_identity,
            &signature,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        ));
    }

    #[test]
    fn transcript_rejects_modified_challenge() {
        let (server_signing, client_signing, server_x25519, client_x25519, challenge) = test_keys();

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let signature = sign_handshake_transcript(
            &server_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        );

        let mut modified = challenge;
        modified[0] ^= 1;

        assert!(!verify_handshake_transcript(
            &server_identity,
            &signature,
            &modified,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        ));
    }

    #[test]
    fn transcript_rejects_modified_client_key() {
        let (server_signing, client_signing, server_x25519, client_x25519, challenge) = test_keys();

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let signature = sign_handshake_transcript(
            &server_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        );

        let modified_client_x25519 = PublicKey::from(&StaticSecret::from([12u8; 32]));

        assert!(!verify_handshake_transcript(
            &server_identity,
            &signature,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &modified_client_x25519,
        ));
    }

    #[test]
    fn transcript_rejects_modified_client_identity() {
        let (server_signing, client_signing, server_x25519, client_x25519, challenge) = test_keys();

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let signature = sign_handshake_transcript(
            &server_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        );

        let other_client = SigningKey::from_bytes(&[13u8; 32]);
        let modified_client_identity = other_client.verifying_key();

        assert!(!verify_handshake_transcript(
            &server_identity,
            &signature,
            &challenge,
            &server_identity,
            &modified_client_identity,
            &server_x25519,
            &client_x25519,
        ));
    }

    #[test]
    fn transcript_rejects_modified_server_key() {
        let (server_signing, client_signing, server_x25519, client_x25519, challenge) = test_keys();

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let signature = sign_handshake_transcript(
            &server_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
        );

        let modified_server_x25519 = PublicKey::from(&StaticSecret::from([14u8; 32]));

        assert!(!verify_handshake_transcript(
            &server_identity,
            &signature,
            &challenge,
            &server_identity,
            &client_identity,
            &modified_server_x25519,
            &client_x25519,
        ));
    }
}
