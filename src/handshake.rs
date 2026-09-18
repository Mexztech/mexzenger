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

fn handshake_message(
    role: u8,
    x25519_public: &PublicKey,
    challenge: &[u8; CHALLENGE_SIZE],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 1 + 1 + 32 + CHALLENGE_SIZE);

    message.extend_from_slice(HANDSHAKE_DOMAIN);
    message.push(role);
    message.push(1u8); // protocol version
    message.extend_from_slice(x25519_public.as_bytes());
    message.extend_from_slice(challenge);

    message
}

pub fn sign_handshake(
    signing_key: &SigningKey,
    x25519_public: &PublicKey,
    challenge: &[u8; CHALLENGE_SIZE],
    role: u8,
) -> Signature {
    let message = handshake_message(role, x25519_public, challenge);

    signing_key.sign(&message)
}

pub fn verify_handshake(
    verifying_key: &VerifyingKey,
    x25519_public: &PublicKey,
    challenge: &[u8; CHALLENGE_SIZE],
    signature: &Signature,
    role: u8,
) -> bool {
    let message = handshake_message(role, x25519_public, challenge);

    verifying_key.verify(&message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_rejects_modified_challenge() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let x25519 = PublicKey::from(&StaticSecret::from([8u8; 32]));
        let challenge = [9u8; CHALLENGE_SIZE];

        let signature = sign_handshake(&signing_key, &x25519, &challenge, 1);

        let mut modified = challenge;
        modified[0] ^= 1;

        assert!(!verify_handshake(
            &signing_key.verifying_key(),
            &x25519,
            &modified,
            &signature,
            1
        ));
    }

    #[test]
    fn signature_rejects_modified_x25519_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let x25519 = PublicKey::from(&StaticSecret::from([8u8; 32]));
        let other_x25519 = PublicKey::from(&StaticSecret::from([10u8; 32]));
        let challenge = [9u8; CHALLENGE_SIZE];

        let signature = sign_handshake(&signing_key, &x25519, &challenge, 1);

        assert!(!verify_handshake(
            &signing_key.verifying_key(),
            &other_x25519,
            &challenge,
            &signature,
            1
        ));
    }

    #[test]
    fn signature_rejects_wrong_role() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let x25519 = PublicKey::from(&StaticSecret::from([8u8; 32]));
        let challenge = [9u8; CHALLENGE_SIZE];

        let signature = sign_handshake(&signing_key, &x25519, &challenge, 1);

        assert!(!verify_handshake(
            &signing_key.verifying_key(),
            &x25519,
            &challenge,
            &signature,
            2
        ));
    }
}
