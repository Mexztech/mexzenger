mod handshake;
mod ratchet;

use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use ksi_double_ratchet::{DoubleRatchet, Header};
use rand_core_04::{CryptoRng, Error as RandError, RngCore};
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use ratchet::{
    CryptoProviderImpl, PublicKey as RatchetPublicKey, Ratchet, keypair_from_x25519,
    root_key_from_shared_secret,
};

const CONTACTS_FILE: &str = "contacts";
fn packet_associated_data(session_id: &[u8; 16]) -> Vec<u8> {
    let mut data = Vec::with_capacity(18);
    data.push(PROTOCOL_VERSION);
    data.push(MESSAGE_TYPE_TEXT);
    data.extend_from_slice(session_id);
    data
}

const PACKET_SIZE: usize = 4096;
const PROTOCOL_VERSION: u8 = 1;
const MESSAGE_TYPE_TEXT: u8 = 1;
#[cfg(test)]
fn generate_session_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("System RNG failed");
    id
}
const RATCHET_HEADER_SIZE: usize = 40;
const PACKET_HEADER_SIZE: usize = 1 + 1 + 16 + RATCHET_HEADER_SIZE;
const AEAD_TAG_SIZE: usize = 16;
const PLAINTEXT_SIZE: usize = PACKET_SIZE - PACKET_HEADER_SIZE - AEAD_TAG_SIZE;
const MAX_MESSAGE_SIZE: usize = PLAINTEXT_SIZE - 4;

struct SystemRng;

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("System RNG failed");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("System RNG failed");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("System RNG failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        getrandom::fill(dest)
            .map_err(|_| RandError::new(rand_core_04::ErrorKind::Unavailable, "System RNG failed"))
    }
}

impl CryptoRng for SystemRng {}

fn send_public_key(stream: &mut TcpStream, public_key: &[u8; 32]) -> io::Result<()> {
    stream.write_all(public_key)?;
    stream.flush()
}

fn receive_public_key(stream: &mut TcpStream) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn send_challenge(
    stream: &mut TcpStream,
    challenge: &[u8; handshake::CHALLENGE_SIZE],
) -> io::Result<()> {
    stream.write_all(challenge)?;
    stream.flush()
}

fn receive_challenge(stream: &mut TcpStream) -> io::Result<[u8; handshake::CHALLENGE_SIZE]> {
    let mut challenge = [0u8; handshake::CHALLENGE_SIZE];

    stream.read_exact(&mut challenge)?;

    Ok(challenge)
}

fn send_identity_key(stream: &mut TcpStream, signing_key: &SigningKey) -> io::Result<()> {
    let verifying_key = signing_key.verifying_key();
    stream.write_all(verifying_key.as_bytes())?;
    stream.flush()
}

fn send_signature(stream: &mut TcpStream, signature: &Signature) -> io::Result<()> {
    stream.write_all(signature.to_bytes().as_ref())?;
    stream.flush()
}

fn receive_identity(stream: &mut TcpStream) -> io::Result<VerifyingKey> {
    let mut identity_bytes = [0u8; 32];
    stream.read_exact(&mut identity_bytes)?;

    VerifyingKey::from_bytes(&identity_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid identity key"))
}

fn receive_signature(stream: &mut TcpStream) -> io::Result<Signature> {
    let mut signature_bytes = [0u8; 64];
    stream.read_exact(&mut signature_bytes)?;

    Ok(Signature::from_bytes(&signature_bytes))
}

fn fingerprint(key: &VerifyingKey) -> String {
    let hash = Sha256::digest(key.as_bytes());

    hash[..16]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn load_trusted_fingerprint() -> io::Result<Option<String>> {
    if !Path::new(CONTACTS_FILE).exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(CONTACTS_FILE)?;

    for line in contents.lines() {
        let fingerprint = line.trim();

        if !fingerprint.is_empty() {
            return Ok(Some(fingerprint.to_string()));
        }
    }

    Ok(None)
}

fn save_trusted_fingerprint(fingerprint: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(CONTACTS_FILE)?;

    writeln!(file, "{}", fingerprint)?;

    Ok(())
}

fn verify_or_pin_identity(identity: &VerifyingKey) -> bool {
    let current = fingerprint(identity);

    println!();
    println!("Remote identity fingerprint:");
    println!("{}", current);

    match load_trusted_fingerprint() {
        Ok(Some(trusted)) => {
            println!();
            println!("Trusted fingerprint:");
            println!("{}", trusted);

            if trusted == current {
                println!("Identity matches trusted fingerprint");

                true
            } else {
                println!();
                println!("WARNING");
                println!("Identity fingerprint changed");
                println!("Connection refused");

                false
            }
        }

        Ok(None) => {
            println!();
            println!("No trusted identity found");

            print!("Trust and save this identity? [y/N]: ");

            io::stdout().flush().ok();

            let mut answer = String::new();

            if io::stdin().read_line(&mut answer).is_err() {
                return false;
            }

            if answer.trim().eq_ignore_ascii_case("y") {
                match save_trusted_fingerprint(&current) {
                    Ok(()) => {
                        println!("Identity pinned");
                        true
                    }

                    Err(error) => {
                        println!("Could not save trusted identity: {}", error);

                        false
                    }
                }
            } else {
                println!("Identity not trusted");
                false
            }
        }

        Err(error) => {
            println!("Could not read contacts: {}", error);

            false
        }
    }
}

fn pad_message(message: &[u8]) -> io::Result<Vec<u8>> {
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Message too large (max {} bytes)", MAX_MESSAGE_SIZE),
        ));
    }

    let mut padded = vec![0u8; PLAINTEXT_SIZE];

    padded[..4].copy_from_slice(&(message.len() as u32).to_be_bytes());

    padded[4..4 + message.len()].copy_from_slice(message);

    if 4 + message.len() < PLAINTEXT_SIZE {
        SystemRng.fill_bytes(&mut padded[4 + message.len()..]);
    }

    Ok(padded)
}

fn send_ratchet_message(
    stream: &mut TcpStream,
    ratchet: &Arc<Mutex<Ratchet>>,
    session_id: &[u8; 16],
    message: &[u8],
) -> io::Result<()> {
    let mut rng = SystemRng;

    let mut ratchet = ratchet
        .lock()
        .map_err(|_| io::Error::other("Ratchet mutex poisoned"))?;

    let padded_message = pad_message(message)?;
    let associated_data = packet_associated_data(session_id);

    let (header, ciphertext) = ratchet.ratchet_encrypt(&padded_message, &associated_data, &mut rng);

    let mut packet = Vec::with_capacity(PACKET_SIZE);

    packet.extend_from_slice(&[PROTOCOL_VERSION]);
    packet.extend_from_slice(&[MESSAGE_TYPE_TEXT]);
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(header.dh.as_ref());
    packet.extend_from_slice(&header.n.to_be_bytes());
    packet.extend_from_slice(&header.pn.to_be_bytes());
    packet.extend_from_slice(&ciphertext);

    if packet.len() != PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid packet size: expected {}, got {}",
                PACKET_SIZE,
                packet.len()
            ),
        ));
    }

    stream.write_all(&(PACKET_SIZE as u32).to_be_bytes())?;
    stream.write_all(&packet)?;
    stream.flush()
}

fn unpad_message(padded: &[u8]) -> io::Result<Vec<u8>> {
    if padded.len() != PLAINTEXT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid padded message size",
        ));
    }

    let message_len = u32::from_be_bytes(
        padded[..4]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid message length"))?,
    ) as usize;

    if message_len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid message length",
        ));
    }

    Ok(padded[4..4 + message_len].to_vec())
}

fn receive_ratchet_message(
    stream: &mut TcpStream,
    ratchet: &Arc<Mutex<Ratchet>>,
    session_id: &[u8; 16],
) -> io::Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];

    stream.read_exact(&mut length_bytes)?;

    let length = u32::from_be_bytes(length_bytes) as usize;

    if length != PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid packet length",
        ));
    }

    let mut packet = vec![0u8; length];

    stream.read_exact(&mut packet)?;

    if packet[0] != PROTOCOL_VERSION
        || packet[1] != MESSAGE_TYPE_TEXT
        || packet[2..18] != session_id[..]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid packet protocol or session",
        ));
    }

    let dh_bytes: [u8; 32] = packet[18..50]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid ratchet public key"))?;

    let n_bytes: [u8; 4] = packet[50..54]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid message counter"))?;

    let pn_bytes: [u8; 4] = packet[54..58]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid previous counter"))?;

    let header = Header {
        dh: RatchetPublicKey(dh_bytes),
        n: u32::from_be_bytes(n_bytes),
        pn: u32::from_be_bytes(pn_bytes),
    };

    let ciphertext = &packet[58..];

    let mut ratchet = ratchet
        .lock()
        .map_err(|_| io::Error::other("Ratchet mutex poisoned"))?;

    let padded_message = ratchet
        .ratchet_decrypt(&header, ciphertext, &packet_associated_data(session_id))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Ratchet decrypt failed: {:?}", error),
            )
        })?;

    unpad_message(&padded_message)
}

fn chat(mut stream: TcpStream, ratchet: Ratchet, session_id: [u8; 16]) {
    let ratchet = Arc::new(Mutex::new(ratchet));

    let receive_ratchet = Arc::clone(&ratchet);

    let receive_stream = stream.try_clone().expect("Could not clone TCP stream");

    thread::spawn(move || {
        let mut stream = receive_stream;

        loop {
            match receive_ratchet_message(&mut stream, &receive_ratchet, &session_id) {
                Ok(message) => {
                    println!();
                    println!("Friend: {}", String::from_utf8_lossy(&message));

                    print!("You: ");
                    io::stdout().flush().ok();
                }

                Err(error) => {
                    println!();
                    println!("Connection closed: {}", error);

                    break;
                }
            }
        }
    });

    println!();
    println!("Double Ratchet chat started");
    println!("Per-message keys enabled");
    println!("Type a message and press Enter");
    println!("Type /quit to leave");
    println!();

    print!("You: ");
    io::stdout().flush().ok();

    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let message = match line {
            Ok(message) => message,
            Err(_) => break,
        };

        if message == "/quit" {
            println!("Closing connection...");
            break;
        }

        if message.is_empty() {
            print!("You: ");
            io::stdout().flush().ok();
            continue;
        }

        if let Err(error) =
            send_ratchet_message(&mut stream, &ratchet, &session_id, message.as_bytes())
        {
            println!("Failed to send message: {}", error);

            break;
        }

        print!("You: ");
        io::stdout().flush().ok();
    }
}

fn derive_session_secret(
    my_secret: &x25519_dalek::StaticSecret,
    my_public: &x25519_dalek::PublicKey,
    remote_public: &x25519_dalek::PublicKey,
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let shared = my_secret.diffie_hellman(remote_public);

    let mut public_keys = [*my_public.as_bytes(), *remote_public.as_bytes()];

    public_keys.sort();

    let mut info = Vec::with_capacity(96);

    info.extend_from_slice(&public_keys[0]);
    info.extend_from_slice(&public_keys[1]);
    info.extend_from_slice(transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(b"private-messenger-session-v2"), shared.as_bytes());

    let mut session_key = [0u8; 32];

    hk.expand(&info, &mut session_key)
        .expect("HKDF expansion failed");

    session_key
}

fn derive_session_id(shared_secret: &[u8; 32]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"private-messenger-session-id"), shared_secret);

    let mut session_id = [0u8; 16];
    hk.expand(b"v1", &mut session_id)
        .expect("HKDF expansion failed");

    session_id
}

fn create_ratchet_alice(shared_secret: [u8; 32], remote_public: [u8; 32]) -> Ratchet {
    let root = root_key_from_shared_secret(shared_secret);

    let remote = RatchetPublicKey(remote_public);

    let mut rng = SystemRng;

    DoubleRatchet::<CryptoProviderImpl>::new_alice(&root, remote, None, &mut rng)
}

fn create_ratchet_bob(shared_secret: [u8; 32], my_secret: [u8; 32]) -> Ratchet {
    let root = root_key_from_shared_secret(shared_secret);

    let keypair = keypair_from_x25519(my_secret);

    DoubleRatchet::<CryptoProviderImpl>::new_bob(root, keypair, None)
}

fn start_server(signing_key: &SigningKey) {
    let listener = TcpListener::bind("0.0.0.0:9000").expect("Could not start server");

    println!("Listening on port 9000...");
    println!("Waiting for connection...");

    let (mut stream, address) = listener.accept().expect("Could not accept connection");

    println!("Connected to {}", address);

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .expect("Could not set read timeout");

    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .expect("Could not set write timeout");

    let challenge = handshake::generate_challenge();
    send_challenge(&mut stream, &challenge).expect("Failed to send challenge");

    let (my_secret, my_public) = handshake::generate_keypair();
    send_public_key(&mut stream, my_public.as_bytes()).expect("Failed to send public key");

    send_identity_key(&mut stream, signing_key).expect("Failed to send server identity");

    let remote_public =
        receive_public_key(&mut stream).expect("Failed to receive client public key");
    let remote_identity = receive_identity(&mut stream).expect("Failed to receive client identity");

    let server_identity = signing_key.verifying_key();
    let remote_x25519 = x25519_dalek::PublicKey::from(remote_public);

    let server_signature = handshake::sign_handshake_transcript(
        signing_key,
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
    );

    send_signature(&mut stream, &server_signature)
        .expect("Failed to send server transcript signature");

    let client_signature =
        receive_signature(&mut stream).expect("Failed to receive client transcript signature");

    if !handshake::verify_handshake_transcript(
        &remote_identity,
        &client_signature,
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
    ) {
        panic!("Client transcript verification FAILED");
    }

    println!("Client identity verified");

    let transcript_hash = handshake::handshake_transcript_hash(
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
    );

    let shared_secret =
        derive_session_secret(&my_secret, &my_public, &remote_x25519, &transcript_hash);
    let session_id = derive_session_id(&shared_secret);

    println!("X25519 handshake successful");

    let ratchet = create_ratchet_bob(shared_secret, *my_secret.as_bytes());

    chat(stream, ratchet, session_id);
}

fn start_client(address: &str, signing_key: &SigningKey) {
    println!("Connecting to {}...", address);

    let mut stream = TcpStream::connect(address).expect("Could not connect");

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .expect("Could not set read timeout");

    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .expect("Could not set write timeout");

    println!("Connected");

    let challenge = receive_challenge(&mut stream).expect("Failed to receive challenge");

    let (my_secret, my_public) = handshake::generate_keypair();

    let server_public =
        receive_public_key(&mut stream).expect("Failed to receive server public key");

    println!("Server X25519 public key received");

    let server_identity = receive_identity(&mut stream).expect("Failed to receive server identity");

    let server_x25519 = x25519_dalek::PublicKey::from(server_public);

    println!("Server identity received");

    if !verify_or_pin_identity(&server_identity) {
        return;
    }

    send_public_key(&mut stream, my_public.as_bytes()).expect("Failed to send client public key");

    send_identity_key(&mut stream, signing_key).expect("Failed to send client identity");

    let client_identity = signing_key.verifying_key();

    let server_signature =
        receive_signature(&mut stream).expect("Failed to receive server transcript signature");

    if !handshake::verify_handshake_transcript(
        &server_identity,
        &server_signature,
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
    ) {
        panic!("Server transcript verification FAILED");
    }

    println!("Server transcript verified");

    let client_signature = handshake::sign_handshake_transcript(
        signing_key,
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
    );

    send_signature(&mut stream, &client_signature)
        .expect("Failed to send client transcript signature");

    println!("Client identity verified");

    let transcript_hash = handshake::handshake_transcript_hash(
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
    );

    let shared_secret =
        derive_session_secret(&my_secret, &my_public, &server_x25519, &transcript_hash);
    let session_id = derive_session_id(&shared_secret);

    println!("X25519 handshake successful");

    let ratchet = create_ratchet_alice(shared_secret, server_public);

    chat(stream, ratchet, session_id);
}

fn unlock_device() -> SigningKey {
    let data = fs::read("device.key").expect("Could not read device.key");

    if data.len() < 28 {
        panic!("device.key is invalid");
    }

    let salt = &data[0..16];
    let nonce_bytes = &data[16..28];
    let encrypted_key = &data[28..];

    let password = prompt_password("Device password: ").expect("Could not read password");

    let mut encryption_key = [0u8; 32];

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut encryption_key)
        .expect("Key derivation failed");

    let cipher = ChaCha20Poly1305::new(&Key::from(encryption_key));

    let nonce = Nonce::try_from(nonce_bytes).expect("Invalid nonce");

    let private_key = cipher
        .decrypt(&nonce, encrypted_key)
        .expect("Wrong password or corrupted device.key");

    let private_key: [u8; 32] = private_key.try_into().expect("Invalid private key");

    let signing_key = SigningKey::from_bytes(&private_key);

    let verifying_key = signing_key.verifying_key();

    println!("Device unlocked");
    println!("Identity fingerprint: {}", fingerprint(&verifying_key));

    signing_key
}

fn main() {
    println!("Private Messenger");

    let signing_key = unlock_device();

    println!();
    println!("Network");
    println!("1 = server");
    println!("2 = client");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    match input.trim() {
        "1" => {
            start_server(&signing_key);
        }

        "2" => {
            println!("Enter server address:");

            input.clear();

            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read address");

            start_client(input.trim(), &signing_key);
        }

        _ => {
            println!("Invalid choice");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_secret_is_symmetric_and_transcript_bound() {
        let alice_secret = x25519_dalek::StaticSecret::from([1u8; 32]);
        let bob_secret = x25519_dalek::StaticSecret::from([2u8; 32]);

        let alice_public = x25519_dalek::PublicKey::from(&alice_secret);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        let transcript_a = [3u8; 32];
        let transcript_b = [4u8; 32];

        let alice_key =
            derive_session_secret(&alice_secret, &alice_public, &bob_public, &transcript_a);

        let bob_key = derive_session_secret(&bob_secret, &bob_public, &alice_public, &transcript_a);

        let modified_transcript_key =
            derive_session_secret(&alice_secret, &alice_public, &bob_public, &transcript_b);

        assert_eq!(alice_key, bob_key);
        assert_ne!(alice_key, modified_transcript_key);
    }

    #[test]
    fn packet_constants_are_correct() {
        assert_eq!(PACKET_SIZE, 4096);
        assert_eq!(RATCHET_HEADER_SIZE, 40);
        assert_eq!(PACKET_HEADER_SIZE, 58);
        assert_eq!(AEAD_TAG_SIZE, 16);
        assert_eq!(PLAINTEXT_SIZE, 4022);
        assert_eq!(MAX_MESSAGE_SIZE, 4018);
    }

    #[test]
    fn packet_size_is_fixed() {
        assert_eq!(
            PACKET_HEADER_SIZE + PLAINTEXT_SIZE + AEAD_TAG_SIZE,
            PACKET_SIZE
        );
    }

    #[test]
    fn message_size_limit_is_correct() {
        const {
            assert!(MAX_MESSAGE_SIZE <= PLAINTEXT_SIZE - 4);
        }
        assert_eq!(MAX_MESSAGE_SIZE, 4018);
    }
    #[test]
    fn real_packet_round_trip_works() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let message = b"hello private messenger";

        send_ratchet_message(&mut client, &alice, &session_id, message).unwrap();
        let received = receive_ratchet_message(&mut server, &bob, &session_id).unwrap();

        assert_eq!(received, message);

        let messages = [
            b"message one".as_slice(),
            b"message two".as_slice(),
            b"message three".as_slice(),
            b"another message".as_slice(),
            b"".as_slice(),
        ];

        for message in messages {
            send_ratchet_message(&mut client, &alice, &session_id, message).unwrap();
            let received = receive_ratchet_message(&mut server, &bob, &session_id).unwrap();
            assert_eq!(received, message);
        }
    }

    #[test]
    fn oversized_message_is_rejected() {
        let message = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(pad_message(&message).is_err());
    }

    #[test]
    fn maximum_message_size_is_accepted() {
        let message = vec![0x42u8; MAX_MESSAGE_SIZE];
        let padded = pad_message(&message).unwrap();
        assert_eq!(padded.len(), PLAINTEXT_SIZE);
        assert_eq!(unpad_message(&padded).unwrap(), message);
    }

    #[test]
    fn wrong_packet_length_is_rejected() {
        let session_id = generate_session_id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        client
            .write_all(&(PACKET_SIZE as u32 - 1).to_be_bytes())
            .unwrap();

        let ratchet = create_ratchet_bob([7u8; 32], [8u8; 32]);
        let ratchet = Arc::new(Mutex::new(ratchet));

        assert!(receive_ratchet_message(&mut server, &ratchet, &session_id).is_err());
    }

    #[test]
    fn corrupted_ciphertext_is_rejected() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let message = pad_message(b"test").unwrap();
        let mut rng = SystemRng;
        let mut ratchet = alice.lock().unwrap();
        let (header, mut ciphertext) =
            ratchet.ratchet_encrypt(&message, &packet_associated_data(&session_id), &mut rng);
        ciphertext[0] ^= 1;
        drop(ratchet);

        let mut packet = Vec::with_capacity(PACKET_SIZE);
        packet.extend_from_slice(&[PROTOCOL_VERSION]);
        packet.extend_from_slice(&[MESSAGE_TYPE_TEXT]);
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(header.dh.as_ref());
        packet.extend_from_slice(&header.n.to_be_bytes());
        packet.extend_from_slice(&header.pn.to_be_bytes());
        packet.extend_from_slice(&ciphertext);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        assert!(receive_ratchet_message(&mut server, &bob, &session_id).is_err());
    }

    #[test]
    fn duplicate_packet_is_rejected() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let message = pad_message(b"duplicate test").unwrap();
        let mut rng = SystemRng;
        let mut ratchet = alice.lock().unwrap();
        let (header, ciphertext) =
            ratchet.ratchet_encrypt(&message, &packet_associated_data(&session_id), &mut rng);
        drop(ratchet);

        let mut packet = Vec::with_capacity(PACKET_SIZE);
        packet.extend_from_slice(&[PROTOCOL_VERSION]);
        packet.extend_from_slice(&[MESSAGE_TYPE_TEXT]);
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(header.dh.as_ref());
        packet.extend_from_slice(&header.n.to_be_bytes());
        packet.extend_from_slice(&header.pn.to_be_bytes());
        packet.extend_from_slice(&ciphertext);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        let received = receive_ratchet_message(&mut server, &bob, &session_id).unwrap();
        assert_eq!(received, b"duplicate test");

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        assert!(receive_ratchet_message(&mut server, &bob, &session_id).is_err());
    }
}
