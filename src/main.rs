mod handshake;
mod ratchet;
mod transport;

use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ksi_double_ratchet::{DoubleRatchet, Header};
use rand_core_04::{CryptoRng, Error as RandError, RngCore};
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use transport::Transport;
use zeroize::Zeroizing;

use ratchet::{
    ChainKey, CryptoProviderImpl, PublicKey as RatchetPublicKey, Ratchet, keypair_from_x25519,
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

fn send_public_key<T: Transport + ?Sized>(stream: &mut T, public_key: &[u8; 32]) -> io::Result<()> {
    eprintln!(
        "PUBLIC KEY SEND: sha256={}",
        Sha256::digest(public_key)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    stream.write_all(public_key)?;
    stream.flush()
}

fn receive_public_key<T: Transport + ?Sized>(stream: &mut T) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    stream.read_exact(&mut bytes)?;
    eprintln!(
        "PUBLIC KEY RECV: sha256={}",
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(bytes)
}

fn send_challenge<T: Transport + ?Sized>(
    stream: &mut T,
    challenge: &[u8; handshake::CHALLENGE_SIZE],
) -> io::Result<()> {
    stream.write_all(challenge)?;
    stream.flush()
}

fn receive_challenge<T: Transport + ?Sized>(
    stream: &mut T,
) -> io::Result<[u8; handshake::CHALLENGE_SIZE]> {
    let mut challenge = [0u8; handshake::CHALLENGE_SIZE];

    stream.read_exact(&mut challenge)?;

    Ok(challenge)
}

fn send_identity_key<T: Transport + ?Sized>(
    stream: &mut T,
    signing_key: &SigningKey,
) -> io::Result<()> {
    let verifying_key = signing_key.verifying_key();
    eprintln!(
        "IDENTITY SEND: sha256={}",
        Sha256::digest(verifying_key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    stream.write_all(verifying_key.as_bytes())?;
    stream.flush()
}

fn send_signature<T: Transport + ?Sized>(stream: &mut T, signature: &Signature) -> io::Result<()> {
    stream.write_all(signature.to_bytes().as_ref())?;
    stream.flush()
}

fn receive_identity<T: Transport + ?Sized>(stream: &mut T) -> io::Result<VerifyingKey> {
    let mut identity_bytes = [0u8; 32];
    stream.read_exact(&mut identity_bytes)?;

    eprintln!(
        "IDENTITY RECV: sha256={}",
        Sha256::digest(&identity_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    VerifyingKey::from_bytes(&identity_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid identity key"))
}

fn receive_signature<T: Transport + ?Sized>(stream: &mut T) -> io::Result<Signature> {
    let mut signature_bytes = [0u8; 64];
    stream.read_exact(&mut signature_bytes)?;

    Ok(Signature::from_bytes(&signature_bytes))
}

fn send_key_confirmation<T: Transport + ?Sized>(
    stream: &mut T,
    confirmation: &[u8; 32],
) -> io::Result<()> {
    stream.write_all(confirmation)?;
    stream.flush()
}

fn receive_key_confirmation<T: Transport + ?Sized>(
    stream: &mut T,
) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut confirmation = Zeroizing::new([0u8; 32]);
    stream.read_exact(&mut *confirmation)?;
    Ok(confirmation)
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

fn send_ratchet_message<T: Transport + ?Sized>(
    stream: &mut T,
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

fn receive_ratchet_message<T: Transport + ?Sized>(
    stream: &mut T,
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

    if !ratchet::is_valid_x25519_public_key(&dh_bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid ratchet public key",
        ));
    }

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

fn chat<T: Transport + 'static>(
    mut stream: T,
    ratchet: Ratchet,
    session_id: [u8; 16],
) -> io::Result<()> {
    stream.clear_timeouts()?;

    let ratchet = Arc::new(Mutex::new(ratchet));

    let receive_ratchet = Arc::clone(&ratchet);

    let receive_stream = stream.try_clone_transport()?;

    thread::spawn(move || {
        let mut stream = receive_stream;

        loop {
            match receive_ratchet_message(&mut *stream, &receive_ratchet, &session_id) {
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

    Ok(())
}

fn derive_session_secret(
    my_secret: &x25519_dalek::StaticSecret,
    my_public: &x25519_dalek::PublicKey,
    remote_public: &x25519_dalek::PublicKey,
    transcript_hash: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let shared = my_secret.diffie_hellman(remote_public);

    let mut public_keys = [*my_public.as_bytes(), *remote_public.as_bytes()];

    public_keys.sort();

    let mut info = Vec::with_capacity(96);

    info.extend_from_slice(&public_keys[0]);
    info.extend_from_slice(&public_keys[1]);
    info.extend_from_slice(transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(b"private-messenger-session-v2"), shared.as_bytes());

    let mut session_key = Zeroizing::new([0u8; 32]);

    hk.expand(&info, &mut *session_key)
        .expect("HKDF expansion failed");

    session_key
}

fn derive_confirmation_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"private-messenger-confirmation-v1"), shared_secret);

    let mut confirmation_key = Zeroizing::new([0u8; 32]);

    hk.expand(b"key-confirmation", &mut *confirmation_key)
        .expect("HKDF expansion failed");

    confirmation_key
}

fn create_key_confirmation(
    confirmation_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    role: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(confirmation_key).expect("HMAC key initialization failed");

    mac.update(b"private-messenger-key-confirmation-v1");
    mac.update(role);
    mac.update(transcript_hash);

    let result = mac.finalize().into_bytes();

    let mut confirmation = Zeroizing::new([0u8; 32]);
    confirmation.copy_from_slice(&result);

    confirmation
}

fn verify_key_confirmation(
    confirmation_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    role: &[u8],
    confirmation: &[u8; 32],
) -> bool {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(confirmation_key).expect("HMAC key initialization failed");

    mac.update(b"private-messenger-key-confirmation-v1");
    mac.update(role);
    mac.update(transcript_hash);

    mac.verify_slice(confirmation).is_ok()
}

fn derive_session_id(shared_secret: &[u8; 32]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"private-messenger-session-id"), shared_secret);

    let mut session_id = [0u8; 16];
    hk.expand(b"v1", &mut session_id)
        .expect("HKDF expansion failed");

    session_id
}

fn initial_send_chain_key(shared_secret: &[u8; 32]) -> ChainKey {
    let hkdf = Hkdf::<Sha256>::new(Some(b"private-messenger-initial-send-v1"), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"initial-send-chain", &mut key)
        .expect("HKDF expansion failed");
    ChainKey(key)
}

fn create_ratchet_alice(shared_secret: &[u8; 32], remote_public: [u8; 32]) -> Ratchet {
    let root = root_key_from_shared_secret(shared_secret);

    let remote = RatchetPublicKey(remote_public);
    let initial_send = initial_send_chain_key(shared_secret);

    let mut rng = SystemRng;

    DoubleRatchet::<CryptoProviderImpl>::new_alice(&root, remote, Some(initial_send), &mut rng)
}

fn create_ratchet_bob(shared_secret: &[u8; 32], my_secret: [u8; 32]) -> Ratchet {
    let root = root_key_from_shared_secret(shared_secret);

    let keypair = keypair_from_x25519(my_secret);
    let initial_send = initial_send_chain_key(shared_secret);

    DoubleRatchet::<CryptoProviderImpl>::new_bob(root, keypair, Some(initial_send))
}

fn start_server_on(bind_address: &str, label: &str, signing_key: &SigningKey) -> io::Result<()> {
    let listener = transport::listen(bind_address)?;

    println!("Listening on {bind_address} ({label})...");
    println!("Waiting for connection...");

    let (mut stream, address) = listener.accept()?;
    eprintln!("SERVER ACCEPT DEBUG: {address} ({label})");

    println!("Connected to {}", address);

    stream.set_handshake_timeouts()?;

    let challenge = handshake::generate_challenge();
    send_challenge(&mut stream, &challenge)?;

    let (my_secret, my_public) = handshake::generate_keypair();
    let (ratchet_secret, ratchet_public) = handshake::generate_keypair();

    send_public_key(&mut stream, my_public.as_bytes())?;

    send_identity_key(&mut stream, signing_key)?;

    send_public_key(&mut stream, ratchet_public.as_bytes())?;

    let remote_public = receive_public_key(&mut stream)?;
    if !ratchet::is_valid_x25519_public_key(&remote_public) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid peer X25519 public key",
        ));
    }
    let remote_identity = receive_identity(&mut stream)?;

    if !verify_or_pin_identity(&remote_identity) {
        return Ok(());
    }

    let server_identity = signing_key.verifying_key();
    let remote_x25519 = x25519_dalek::PublicKey::from(remote_public);

    let server_signature = handshake::sign_handshake_transcript(
        signing_key,
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
        &ratchet_public,
    );

    send_signature(&mut stream, &server_signature)?;

    let client_signature = receive_signature(&mut stream)?;

    if !handshake::verify_handshake_transcript(
        &remote_identity,
        &client_signature,
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
        &ratchet_public,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Client transcript verification failed",
        ));
    }

    println!("Client identity verified");

    let transcript_hash = handshake::handshake_transcript_hash(
        &challenge,
        &server_identity,
        &remote_identity,
        &my_public,
        &remote_x25519,
        &ratchet_public,
    );

    let shared_secret =
        derive_session_secret(&my_secret, &my_public, &remote_x25519, &transcript_hash);

    let confirmation_key = derive_confirmation_key(&shared_secret);
    let server_confirmation =
        create_key_confirmation(&confirmation_key, &transcript_hash, b"server");

    send_key_confirmation(&mut stream, &server_confirmation)?;

    let client_confirmation = receive_key_confirmation(&mut stream)?;

    if !verify_key_confirmation(
        &confirmation_key,
        &transcript_hash,
        b"client",
        &client_confirmation,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Client key confirmation failed",
        ));
    }

    println!("Mutual key confirmation successful");

    let session_id = derive_session_id(&shared_secret);

    println!("X25519 handshake successful");

    let ratchet = create_ratchet_bob(&shared_secret, *ratchet_secret.as_bytes());

    chat(stream, ratchet, session_id)
}

fn start_server(signing_key: &SigningKey) -> io::Result<()> {
    start_server_on("0.0.0.0:9000", "TCP", signing_key)
}

fn start_tor_server(signing_key: &SigningKey) -> io::Result<()> {
    use arti_client::{TorClient, TorClientConfig};
    use safelog::DisplayRedacted;
    use std::sync::mpsc;
    use tokio::runtime::Runtime;
    use tor_hsrproxy::OnionServiceReverseProxy;
    use tor_hsrproxy::config::{
        Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
    };
    use tor_hsservice::HsNickname;
    use tor_hsservice::config::OnionServiceConfigBuilder;
    use tor_rtcompat::SpawnExt;

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            let runtime =
                Runtime::new().map_err(|e| io::Error::other(format!("Tokio runtime: {e}")))?;

            let tx_ready = tx.clone();

            runtime.block_on(async move {
                let client = TorClient::create_bootstrapped(TorClientConfig::default())
                    .await
                    .map_err(|e| io::Error::other(format!("Arti bootstrap: {e}")))?;

                let nickname = HsNickname::new("private-messenger".to_string())
                    .map_err(|e| io::Error::other(format!("Onion nickname: {e}")))?;

                let config = OnionServiceConfigBuilder::default()
                    .nickname(nickname.clone())
                    .build()
                    .map_err(|e| io::Error::other(format!("Onion config: {e}")))?;

                let Some((running, requests)) = client
                    .launch_onion_service(config)
                    .map_err(|e| io::Error::other(format!("Onion service: {e}")))?
                else {
                    return Err(io::Error::other("Onion service disabled"));
                };

                let rule = ProxyRule::new(
                    ProxyPattern::one_port(9000)
                        .map_err(|e| io::Error::other(format!("Proxy port: {e}")))?,
                    ProxyAction::Forward(
                        Encapsulation::Simple,
                        TargetAddr::Inet(
                            "127.0.0.1:9000"
                                .parse()
                                .map_err(|e| io::Error::other(format!("Proxy target: {e}")))?,
                        ),
                    ),
                );

                let mut proxy_config = ProxyConfigBuilder::default();
                proxy_config.set_proxy_ports(vec![rule]);

                let proxy = OnionServiceReverseProxy::new(
                    proxy_config
                        .build()
                        .map_err(|e| io::Error::other(format!("Proxy config: {e}")))?,
                );
                let runtime_handle = client.runtime().clone();
                let proxy_clone = proxy.clone();

                client
                    .runtime()
                    .spawn(async move {
                        if let Err(e) = proxy_clone
                            .handle_requests(runtime_handle, nickname, requests)
                            .await
                        {
                            eprintln!("Tor proxy error: {e}");
                        }
                    })
                    .map_err(|e| io::Error::other(format!("Tor proxy spawn: {e}")))?;

                let address = running
                    .onion_address()
                    .ok_or_else(|| io::Error::other("Onion address unavailable"))?
                    .display_unredacted()
                    .to_string();

                tx_ready
                    .send(Ok(address))
                    .map_err(|_| io::Error::other("Main thread closed"))?;
                std::future::pending::<()>().await;
                Ok(())
            })
        })();

        if let Err(e) = result {
            let _ = tx.send(Err(e));
        }
    });

    let onion_address = rx
        .recv()
        .map_err(|_| io::Error::other("Tor thread stopped"))??;

    println!("Tor onion service: {onion_address}");
    println!("Forwarding onion port 9000 -> 127.0.0.1:9000");

    start_server_on("127.0.0.1:9000", "Tor", signing_key)
}

fn start_client(address: &str, signing_key: &SigningKey) -> io::Result<()> {
    println!("Connecting to {}...", address);

    let mut stream = if let Some(i2p_address) = address.strip_prefix("i2p://") {
        println!("Routing connection through I2P...");
        transport::connect_i2p(i2p_address)?
    } else if let Some(tor_address) = address.strip_prefix("tor://") {
        println!("Routing connection through Tor...");
        transport::connect_tor(tor_address)?
    } else {
        transport::connect(address)?
    };

    stream.set_handshake_timeouts()?;

    println!("Connected");

    let challenge = receive_challenge(&mut stream)?;

    let (my_secret, my_public) = handshake::generate_keypair();

    let server_public = receive_public_key(&mut stream)?;
    if !ratchet::is_valid_x25519_public_key(&server_public) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid server X25519 public key",
        ));
    }

    println!("Server X25519 public key received");

    let server_identity = receive_identity(&mut stream)?;

    let server_ratchet_public = receive_public_key(&mut stream)?;
    if !ratchet::is_valid_x25519_public_key(&server_ratchet_public) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid server ratchet X25519 public key",
        ));
    }

    let server_x25519 = x25519_dalek::PublicKey::from(server_public);
    let server_ratchet_x25519 = x25519_dalek::PublicKey::from(server_ratchet_public);

    println!("Server identity received");

    if !verify_or_pin_identity(&server_identity) {
        return Ok(());
    }

    send_public_key(&mut stream, my_public.as_bytes())?;

    send_identity_key(&mut stream, signing_key)?;

    let client_identity = signing_key.verifying_key();

    let server_signature = match receive_signature(&mut stream) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("Connection closed during handshake: {}", error);
            return Ok(());
        }
    };

    if !handshake::verify_handshake_transcript(
        &server_identity,
        &server_signature,
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
        &server_ratchet_x25519,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server transcript verification failed",
        ));
    }

    println!("Server transcript verified");

    let client_signature = handshake::sign_handshake_transcript(
        signing_key,
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
        &server_ratchet_x25519,
    );

    send_signature(&mut stream, &client_signature)?;

    println!("Client identity verified");

    let transcript_hash = handshake::handshake_transcript_hash(
        &challenge,
        &server_identity,
        &client_identity,
        &server_x25519,
        &my_public,
        &server_ratchet_x25519,
    );

    let shared_secret =
        derive_session_secret(&my_secret, &my_public, &server_x25519, &transcript_hash);

    let confirmation_key = derive_confirmation_key(&shared_secret);

    let server_confirmation = receive_key_confirmation(&mut stream)?;

    if !verify_key_confirmation(
        &confirmation_key,
        &transcript_hash,
        b"server",
        &server_confirmation,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server key confirmation failed",
        ));
    }

    let client_confirmation =
        create_key_confirmation(&confirmation_key, &transcript_hash, b"client");

    send_key_confirmation(&mut stream, &client_confirmation)?;

    println!("Mutual key confirmation successful");

    let session_id = derive_session_id(&shared_secret);

    println!("X25519 handshake successful");

    let ratchet = create_ratchet_alice(&shared_secret, *server_ratchet_x25519.as_bytes());

    chat(stream, ratchet, session_id)
}

fn start_i2p_server(signing_key: &SigningKey) -> io::Result<()> {
    use std::sync::mpsc;
    use tokio::runtime::Runtime;
    use yosemite::{Session as I2pSession, style::Stream as I2pStream};

    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let runtime = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = tx.send(Err(io::Error::other(format!("Tokio runtime: {error}"))));
                return;
            }
        };

        let tx_ready = tx.clone();
        let result = runtime.block_on(async move {
            let mut session = I2pSession::<I2pStream>::new(Default::default())
                .await
                .map_err(|error| io::Error::other(format!("I2P session: {error}")))?;

            let destination = session.destination().to_string();
            eprintln!(
                "I2P DEST DEBUG: len={} sha256={}",
                destination.len(),
                Sha256::digest(destination.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );

            tx_ready
                .send(Ok(destination))
                .map_err(|_| io::Error::other("Main thread closed"))?;

            session
                .forward(9000)
                .await
                .map_err(|error| io::Error::other(format!("I2P forward: {error}")))?;

            std::future::pending::<()>().await;
            Ok::<(), io::Error>(())
        });

        if let Err(error) = result {
            let _ = tx.send(Err(error));
        }
    });

    let destination = rx
        .recv()
        .map_err(|_| io::Error::other("I2P thread stopped"))??;

    println!("I2P destination: {destination}");
    println!("Forwarding I2P -> 127.0.0.1:9000");

    start_server_on("127.0.0.1:9000", "I2P", signing_key)
}

fn unlock_device() -> io::Result<SigningKey> {
    let data = fs::read("device.key")?;

    if data.len() < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "device.key is invalid",
        ));
    }

    let salt = &data[0..16];
    let nonce_bytes = &data[16..28];
    let encrypted_key = &data[28..];

    let password = Zeroizing::new(
        prompt_password("Device password: ")
            .map_err(|error| io::Error::other(format!("Could not read password: {}", error)))?,
    );

    let mut encryption_key = Zeroizing::new([0u8; 32]);

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Key derivation failed"))?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*encryption_key));

    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid nonce"))?;

    let private_key = cipher.decrypt(&nonce, encrypted_key).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Wrong password or corrupted device.key",
        )
    })?;

    let private_key: Zeroizing<[u8; 32]> = Zeroizing::new(
        private_key
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid private key"))?,
    );

    let signing_key = SigningKey::from_bytes(&private_key);

    let verifying_key = signing_key.verifying_key();

    println!("Device unlocked");
    println!("Identity fingerprint: {}", fingerprint(&verifying_key));

    Ok(signing_key)
}

fn change_device_password(signing_key: &SigningKey) -> io::Result<()> {
    let new_password = Zeroizing::new(
        prompt_password("New device password: ")
            .map_err(|e| io::Error::other(format!("Could not read password: {e}")))?,
    );
    let confirm = Zeroizing::new(
        prompt_password("Confirm new device password: ")
            .map_err(|e| io::Error::other(format!("Could not read password: {e}")))?,
    );
    if new_password.as_bytes() != confirm.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "New passwords do not match",
        ));
    }
    if new_password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "New password cannot be empty",
        ));
    }

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;

    let mut encryption_key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(new_password.as_bytes(), &salt, &mut *encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Key derivation failed"))?;

    let cipher = ChaCha20Poly1305::new(&Key::from(*encryption_key));
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| io::Error::other("Invalid nonce"))?;
    let encrypted_key = cipher
        .encrypt(&nonce, signing_key.to_bytes().as_ref())
        .map_err(|_| io::Error::other("Failed to encrypt device key"))?;

    let mut data = Vec::with_capacity(16 + 12 + encrypted_key.len());
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce_bytes);
    data.extend_from_slice(&encrypted_key);

    fs::write("device.key.tmp", &data)?;
    fs::rename("device.key.tmp", "device.key")?;
    println!("Device password changed successfully.");
    Ok(())
}

fn main() -> io::Result<()> {
    println!("Private Messenger");

    let signing_key = unlock_device()?;

    println!();
    println!("Network");
    println!("0 = change device password");
    println!("1 = server");
    println!("2 = client");
    println!("3 = Tor server");
    println!("4 = I2P server");

    let mut input = String::new();

    io::stdin().read_line(&mut input)?;

    match input.trim() {
        "0" => {
            change_device_password(&signing_key)?;
        }

        "1" => {
            start_server(&signing_key)?;
        }

        "2" => {
            println!("Enter server address:");

            input.clear();

            io::stdin().read_line(&mut input)?;

            start_client(input.trim(), &signing_key)?;
        }

        "3" => {
            start_tor_server(&signing_key)?;
        }

        "4" => {
            start_i2p_server(&signing_key)?;
        }

        _ => {
            println!("Invalid choice");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn key_confirmation_roles_cannot_be_swapped() {
        let shared_secret = [81u8; 32];
        let transcript_hash = [82u8; 32];
        let key = derive_confirmation_key(&shared_secret);

        let server_confirmation = create_key_confirmation(&key, &transcript_hash, b"server");
        let client_confirmation = create_key_confirmation(&key, &transcript_hash, b"client");

        assert!(!verify_key_confirmation(
            &key,
            &transcript_hash,
            b"client",
            &server_confirmation,
        ));

        assert!(!verify_key_confirmation(
            &key,
            &transcript_hash,
            b"server",
            &client_confirmation,
        ));
    }

    #[test]
    fn wrong_key_confirmation_is_rejected() {
        let shared_secret = [71u8; 32];
        let transcript_hash = [72u8; 32];

        let confirmation_key = derive_confirmation_key(&shared_secret);
        let wrong_key = derive_confirmation_key(&[73u8; 32]);

        let valid_confirmation =
            create_key_confirmation(&confirmation_key, &transcript_hash, b"server");
        let wrong_confirmation = create_key_confirmation(&wrong_key, &transcript_hash, b"server");

        assert!(!verify_key_confirmation(
            &confirmation_key,
            &transcript_hash,
            b"server",
            &wrong_confirmation,
        ));

        assert!(verify_key_confirmation(
            &confirmation_key,
            &transcript_hash,
            b"server",
            &valid_confirmation,
        ));
    }

    #[test]
    fn key_confirmation_is_bound_to_session_transcript_and_role() {
        let shared_secret = [1u8; 32];
        let other_secret = [2u8; 32];
        let transcript = [3u8; 32];
        let other_transcript = [4u8; 32];

        let key = derive_confirmation_key(&shared_secret);
        let other_key = derive_confirmation_key(&other_secret);

        let server_confirmation = create_key_confirmation(&key, &transcript, b"server");

        assert!(verify_key_confirmation(
            &key,
            &transcript,
            b"server",
            &server_confirmation
        ));

        assert!(!verify_key_confirmation(
            &key,
            &transcript,
            b"client",
            &server_confirmation
        ));

        assert!(!verify_key_confirmation(
            &other_key,
            &transcript,
            b"server",
            &server_confirmation
        ));

        assert!(!verify_key_confirmation(
            &key,
            &other_transcript,
            b"server",
            &server_confirmation
        ));

        let mut tampered = server_confirmation;
        tampered[0] ^= 1;

        assert!(!verify_key_confirmation(
            &key,
            &transcript,
            b"server",
            &tampered
        ));
    }

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
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

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

        let ratchet = create_ratchet_bob(&[7u8; 32], [8u8; 32]);
        let ratchet = Arc::new(Mutex::new(ratchet));

        assert!(receive_ratchet_message(&mut server, &ratchet, &session_id).is_err());
    }

    #[test]
    fn wrong_protocol_version_is_rejected() {
        let session_id = generate_session_id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = PROTOCOL_VERSION.wrapping_add(1);
        packet[1] = MESSAGE_TYPE_TEXT;
        packet[2..18].copy_from_slice(&session_id);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        let ratchet = create_ratchet_bob(&[7u8; 32], [8u8; 32]);
        let ratchet = Arc::new(Mutex::new(ratchet));

        assert!(receive_ratchet_message(&mut server, &ratchet, &session_id).is_err());
    }

    #[test]
    fn wrong_message_type_is_rejected() {
        let session_id = generate_session_id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = PROTOCOL_VERSION;
        packet[1] = MESSAGE_TYPE_TEXT.wrapping_add(1);
        packet[2..18].copy_from_slice(&session_id);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        let ratchet = create_ratchet_bob(&[7u8; 32], [8u8; 32]);
        let ratchet = Arc::new(Mutex::new(ratchet));

        assert!(receive_ratchet_message(&mut server, &ratchet, &session_id).is_err());
    }

    #[test]
    fn wrong_session_id_is_rejected() {
        let session_id = generate_session_id();
        let wrong_session_id = generate_session_id();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = PROTOCOL_VERSION;
        packet[1] = MESSAGE_TYPE_TEXT;
        packet[2..18].copy_from_slice(&wrong_session_id);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        let ratchet = create_ratchet_bob(&[7u8; 32], [8u8; 32]);
        let ratchet = Arc::new(Mutex::new(ratchet));

        assert!(receive_ratchet_message(&mut server, &ratchet, &session_id).is_err());
    }

    #[test]
    fn corrupted_ratchet_header_is_rejected() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let message = pad_message(b"header corruption test").unwrap();
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

        packet[18] ^= 1;

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        assert!(receive_ratchet_message(&mut server, &bob, &session_id).is_err());
    }

    #[test]
    fn out_of_order_messages_are_accepted() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let mut rng = SystemRng;

        let (header1, ciphertext1) = {
            let mut ratchet = alice.lock().unwrap();
            let message = pad_message(b"message one").unwrap();
            ratchet.ratchet_encrypt(&message, &packet_associated_data(&session_id), &mut rng)
        };

        let (header2, ciphertext2) = {
            let mut ratchet = alice.lock().unwrap();
            let message = pad_message(b"message two").unwrap();
            ratchet.ratchet_encrypt(&message, &packet_associated_data(&session_id), &mut rng)
        };

        {
            let mut ratchet = bob.lock().unwrap();

            let decrypted2 = ratchet
                .ratchet_decrypt(&header2, &ciphertext2, &packet_associated_data(&session_id))
                .expect("message two should decrypt out of order");

            assert_eq!(unpad_message(&decrypted2).unwrap(), b"message two");

            let decrypted1 = ratchet
                .ratchet_decrypt(&header1, &ciphertext1, &packet_associated_data(&session_id))
                .expect("message one should decrypt from skipped-key storage");

            assert_eq!(unpad_message(&decrypted1).unwrap(), b"message one");
        }
    }

    #[test]
    fn many_out_of_order_messages_are_accepted() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;
        let mut messages = Vec::new();

        for number in 0u32..1000 {
            let message = format!("message-{number}");
            let padded = pad_message(message.as_bytes()).unwrap();

            let (header, ciphertext) =
                alice.ratchet_encrypt(&padded, &packet_associated_data(&session_id), &mut rng);

            messages.push((number, header, ciphertext.to_vec()));
        }

        let (number, header, ciphertext) = messages.pop().unwrap();

        let decrypted = bob
            .ratchet_decrypt(&header, &ciphertext, &packet_associated_data(&session_id))
            .expect("message 999 should decrypt after a 999-message gap");

        let expected = format!("message-{number}");
        assert_eq!(unpad_message(&decrypted).unwrap(), expected.as_bytes());
    }

    #[test]
    fn excessive_ratchet_skip_is_rejected() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;

        let message0 = pad_message(b"message-0").unwrap();
        let (header0, ciphertext0) =
            alice.ratchet_encrypt(&message0, &packet_associated_data(&session_id), &mut rng);

        bob.ratchet_decrypt(&header0, &ciphertext0, &packet_associated_data(&session_id))
            .unwrap();

        let message1 = pad_message(b"message-1").unwrap();
        let (header1, ciphertext1) =
            alice.ratchet_encrypt(&message1, &packet_associated_data(&session_id), &mut rng);

        let mut malicious_header = header1.clone();
        malicious_header.n = 1002;

        let result = bob.ratchet_decrypt(
            &malicious_header,
            &ciphertext1,
            &packet_associated_data(&session_id),
        );

        assert!(result.is_err(), "excessive ratchet skip must be rejected");

        let result =
            bob.ratchet_decrypt(&header1, &ciphertext1, &packet_associated_data(&session_id));

        assert!(
            result.is_ok(),
            "ratchet state must remain usable after rejected skip"
        );
    }

    #[test]
    fn bidirectional_dh_ratchet_stress_test() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;
        let ad = packet_associated_data(&session_id);

        for i in 0..100 {
            let alice_message = pad_message(format!("alice-{i}").as_bytes()).unwrap();
            let (header, ciphertext) = alice.ratchet_encrypt(&alice_message, &ad, &mut rng);

            let decrypted = bob.ratchet_decrypt(&header, &ciphertext, &ad).unwrap();
            assert_eq!(decrypted, alice_message);

            let bob_message = pad_message(format!("bob-{i}").as_bytes()).unwrap();
            let (header, ciphertext) = bob.ratchet_encrypt(&bob_message, &ad, &mut rng);

            let decrypted = alice.ratchet_decrypt(&header, &ciphertext, &ad).unwrap();
            assert_eq!(decrypted, bob_message);
        }
    }

    #[test]
    fn skipped_key_storage_full_returns_exact_error() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;
        let ad = packet_associated_data(&session_id);

        let message0 = pad_message(b"message-0").unwrap();
        let (header0, ciphertext0) = alice.ratchet_encrypt(&message0, &ad, &mut rng);

        bob.ratchet_decrypt(&header0, &ciphertext0, &ad).unwrap();

        for round in 0..2 {
            for i in 0..1000 {
                alice.ratchet_encrypt(
                    &pad_message(format!("skip-{round}-{i}").as_bytes()).unwrap(),
                    &ad,
                    &mut rng,
                );
            }

            let message = pad_message(format!("stored-{round}").as_bytes()).unwrap();
            let (header, ciphertext) = alice.ratchet_encrypt(&message, &ad, &mut rng);

            bob.ratchet_decrypt(&header, &ciphertext, &ad).unwrap();
        }

        alice.ratchet_encrypt(&pad_message(b"overflow-skip").unwrap(), &ad, &mut rng);

        let message = pad_message(b"storage-full").unwrap();
        let (header, ciphertext) = alice.ratchet_encrypt(&message, &ad, &mut rng);

        assert_eq!(
            bob.ratchet_decrypt(&header, &ciphertext, &ad),
            Err(ksi_double_ratchet::DecryptError::StorageFull)
        );
    }

    #[test]
    fn excessive_ratchet_skip_returns_exact_error() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;
        let ad = packet_associated_data(&session_id);

        let message0 = pad_message(b"message-0").unwrap();
        let (header0, ciphertext0) = alice.ratchet_encrypt(&message0, &ad, &mut rng);

        bob.ratchet_decrypt(&header0, &ciphertext0, &ad).unwrap();

        let message1 = pad_message(b"message-1").unwrap();
        let (header1, ciphertext1) = alice.ratchet_encrypt(&message1, &ad, &mut rng);

        let mut malicious_header = header1.clone();
        malicious_header.n = 1002;

        let result = bob.ratchet_decrypt(&malicious_header, &ciphertext1, &ad);

        assert_eq!(result, Err(ksi_double_ratchet::DecryptError::SkipTooLarge));
    }

    #[test]
    fn invalid_x25519_public_key_is_rejected() {
        assert!(!ratchet::is_valid_x25519_public_key(&[0u8; 32]));
    }

    #[test]
    fn malformed_ratchet_inputs_never_panic() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let mut alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let mut bob = create_ratchet_bob(&shared_secret, bob_secret);

        let mut rng = SystemRng;
        let ad = packet_associated_data(&session_id);

        let message = pad_message(b"valid-message").unwrap();
        let (valid_header, valid_ciphertext) = alice.ratchet_encrypt(&message, &ad, &mut rng);

        let mut corrupted_headers = Vec::new();

        for i in 0..32 {
            let mut header = valid_header.clone();
            header.n = i * 1000;
            corrupted_headers.push(header);
        }

        for mut header in corrupted_headers {
            header.pn = u32::MAX;
            let _ = bob.ratchet_decrypt(&header, &valid_ciphertext, &ad);
        }

        for i in 0..32 {
            let mut corrupted_ciphertext = valid_ciphertext.clone();

            if !corrupted_ciphertext.is_empty() {
                let index = i % corrupted_ciphertext.len();
                corrupted_ciphertext[index] ^= (i as u8).wrapping_add(1);
            }

            let _ = bob.ratchet_decrypt(&valid_header, &corrupted_ciphertext, &ad);
        }
    }

    #[test]
    fn corrupted_ciphertext_is_rejected() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let alice = create_ratchet_alice(
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

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
            &shared_secret,
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret))
                .as_bytes(),
        );
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

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

        let message2 = pad_message(b"after replay").unwrap();
        let (header2, ciphertext2) = {
            let mut ratchet = alice.lock().unwrap();
            ratchet.ratchet_encrypt(&message2, &packet_associated_data(&session_id), &mut rng)
        };

        packet.clear();
        packet.extend_from_slice(&[PROTOCOL_VERSION]);
        packet.extend_from_slice(&[MESSAGE_TYPE_TEXT]);
        packet.extend_from_slice(&session_id);
        packet.extend_from_slice(header2.dh.as_ref());
        packet.extend_from_slice(&header2.n.to_be_bytes());
        packet.extend_from_slice(&header2.pn.to_be_bytes());
        packet.extend_from_slice(&ciphertext2);

        client
            .write_all(&(PACKET_SIZE as u32).to_be_bytes())
            .unwrap();
        client.write_all(&packet).unwrap();

        let received2 = receive_ratchet_message(&mut server, &bob, &session_id).unwrap();
        assert_eq!(received2, b"after replay");
    }
    #[test]
    fn full_handshake_tcp_integration_works() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let server_handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let server_signing = SigningKey::from_bytes(&[21u8; 32]);
            let server_identity = server_signing.verifying_key();
            let challenge = handshake::generate_challenge();
            send_challenge(&mut stream, &challenge).unwrap();

            let (server_secret, server_x25519) = handshake::generate_keypair();
            let (_, server_ratchet_x25519) = handshake::generate_keypair();
            send_public_key(&mut stream, server_x25519.as_bytes()).unwrap();
            send_identity_key(&mut stream, &server_signing).unwrap();
            send_public_key(&mut stream, server_ratchet_x25519.as_bytes()).unwrap();

            let client_x25519_bytes = receive_public_key(&mut stream).unwrap();
            assert!(ratchet::is_valid_x25519_public_key(&client_x25519_bytes));
            let client_x25519 = x25519_dalek::PublicKey::from(client_x25519_bytes);
            let client_identity = receive_identity(&mut stream).unwrap();

            let server_signature = handshake::sign_handshake_transcript(
                &server_signing,
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519,
            );
            send_signature(&mut stream, &server_signature).unwrap();

            let client_signature = receive_signature(&mut stream).unwrap();
            assert!(handshake::verify_handshake_transcript(
                &client_identity,
                &client_signature,
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519
            ));

            let transcript_hash = handshake::handshake_transcript_hash(
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519,
            );
            let shared_secret = derive_session_secret(
                &server_secret,
                &server_x25519,
                &client_x25519,
                &transcript_hash,
            );
            let confirmation_key = derive_confirmation_key(&shared_secret);
            let confirmation =
                create_key_confirmation(&confirmation_key, &transcript_hash, b"server");
            send_key_confirmation(&mut stream, &confirmation).unwrap();

            let client_confirmation = receive_key_confirmation(&mut stream).unwrap();
            assert!(verify_key_confirmation(
                &confirmation_key,
                &transcript_hash,
                b"client",
                &client_confirmation
            ));

            derive_session_id(&shared_secret)
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let client_signing = SigningKey::from_bytes(&[22u8; 32]);
        let client_identity = client_signing.verifying_key();

        let challenge = receive_challenge(&mut stream).unwrap();
        let (client_secret, client_x25519) = handshake::generate_keypair();
        let server_x25519_bytes = receive_public_key(&mut stream).unwrap();
        assert!(ratchet::is_valid_x25519_public_key(&server_x25519_bytes));
        let server_x25519 = x25519_dalek::PublicKey::from(server_x25519_bytes);
        let server_identity = receive_identity(&mut stream).unwrap();
        let server_ratchet_bytes = receive_public_key(&mut stream).unwrap();
        assert!(ratchet::is_valid_x25519_public_key(&server_ratchet_bytes));
        let server_ratchet_x25519 = x25519_dalek::PublicKey::from(server_ratchet_bytes);

        send_public_key(&mut stream, client_x25519.as_bytes()).unwrap();
        send_identity_key(&mut stream, &client_signing).unwrap();

        let server_signature = receive_signature(&mut stream).unwrap();
        assert!(handshake::verify_handshake_transcript(
            &server_identity,
            &server_signature,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519
        ));

        let client_signature = handshake::sign_handshake_transcript(
            &client_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );
        send_signature(&mut stream, &client_signature).unwrap();

        let transcript_hash = handshake::handshake_transcript_hash(
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );
        let shared_secret = derive_session_secret(
            &client_secret,
            &client_x25519,
            &server_x25519,
            &transcript_hash,
        );
        let confirmation_key = derive_confirmation_key(&shared_secret);

        let server_confirmation = receive_key_confirmation(&mut stream).unwrap();
        assert!(verify_key_confirmation(
            &confirmation_key,
            &transcript_hash,
            b"server",
            &server_confirmation
        ));

        let client_confirmation =
            create_key_confirmation(&confirmation_key, &transcript_hash, b"client");
        send_key_confirmation(&mut stream, &client_confirmation).unwrap();

        let client_session_id = derive_session_id(&shared_secret);
        let server_session_id = server_handle.join().unwrap();
        assert_eq!(client_session_id, server_session_id);
    }
    #[test]
    fn full_handshake_and_ratchet_tcp_integration_works() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let server_handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();

            let server_signing = SigningKey::from_bytes(&[31u8; 32]);
            let server_identity = server_signing.verifying_key();
            let challenge = handshake::generate_challenge();
            send_challenge(&mut stream, &challenge).unwrap();

            let (server_secret, server_x25519) = handshake::generate_keypair();
            let (server_ratchet_secret, server_ratchet_x25519) = handshake::generate_keypair();

            send_public_key(&mut stream, server_x25519.as_bytes()).unwrap();
            send_identity_key(&mut stream, &server_signing).unwrap();
            send_public_key(&mut stream, server_ratchet_x25519.as_bytes()).unwrap();

            let client_x25519_bytes = receive_public_key(&mut stream).unwrap();
            assert!(ratchet::is_valid_x25519_public_key(&client_x25519_bytes));
            let client_x25519 = x25519_dalek::PublicKey::from(client_x25519_bytes);
            let client_identity = receive_identity(&mut stream).unwrap();

            let server_signature = handshake::sign_handshake_transcript(
                &server_signing,
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519,
            );
            send_signature(&mut stream, &server_signature).unwrap();

            let client_signature = receive_signature(&mut stream).unwrap();
            assert!(handshake::verify_handshake_transcript(
                &client_identity,
                &client_signature,
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519,
            ));

            let transcript_hash = handshake::handshake_transcript_hash(
                &challenge,
                &server_identity,
                &client_identity,
                &server_x25519,
                &client_x25519,
                &server_ratchet_x25519,
            );
            let shared_secret = derive_session_secret(
                &server_secret,
                &server_x25519,
                &client_x25519,
                &transcript_hash,
            );
            let confirmation_key = derive_confirmation_key(&shared_secret);
            let server_confirmation =
                create_key_confirmation(&confirmation_key, &transcript_hash, b"server");
            send_key_confirmation(&mut stream, &server_confirmation).unwrap();

            let client_confirmation = receive_key_confirmation(&mut stream).unwrap();
            assert!(verify_key_confirmation(
                &confirmation_key,
                &transcript_hash,
                b"client",
                &client_confirmation,
            ));

            let session_id = derive_session_id(&shared_secret);
            let ratchet = Arc::new(Mutex::new(create_ratchet_bob(
                &shared_secret,
                *server_ratchet_secret.as_bytes(),
            )));

            let message = receive_ratchet_message(&mut stream, &ratchet, &session_id).unwrap();
            assert_eq!(message, b"ping");

            send_ratchet_message(&mut stream, &ratchet, &session_id, b"pong").unwrap();

            session_id
        });

        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();

        let client_signing = SigningKey::from_bytes(&[32u8; 32]);
        let client_identity = client_signing.verifying_key();

        let challenge = receive_challenge(&mut stream).unwrap();
        let (client_secret, client_x25519) = handshake::generate_keypair();
        let server_x25519_bytes = receive_public_key(&mut stream).unwrap();
        assert!(ratchet::is_valid_x25519_public_key(&server_x25519_bytes));
        let server_x25519 = x25519_dalek::PublicKey::from(server_x25519_bytes);
        let server_identity = receive_identity(&mut stream).unwrap();
        let server_ratchet_bytes = receive_public_key(&mut stream).unwrap();
        assert!(ratchet::is_valid_x25519_public_key(&server_ratchet_bytes));
        let server_ratchet_x25519 = x25519_dalek::PublicKey::from(server_ratchet_bytes);

        send_public_key(&mut stream, client_x25519.as_bytes()).unwrap();
        send_identity_key(&mut stream, &client_signing).unwrap();

        let server_signature = receive_signature(&mut stream).unwrap();
        assert!(handshake::verify_handshake_transcript(
            &server_identity,
            &server_signature,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        ));

        let client_signature = handshake::sign_handshake_transcript(
            &client_signing,
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );
        send_signature(&mut stream, &client_signature).unwrap();

        let transcript_hash = handshake::handshake_transcript_hash(
            &challenge,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );
        let shared_secret = derive_session_secret(
            &client_secret,
            &client_x25519,
            &server_x25519,
            &transcript_hash,
        );
        let confirmation_key = derive_confirmation_key(&shared_secret);

        let server_confirmation = receive_key_confirmation(&mut stream).unwrap();
        assert!(verify_key_confirmation(
            &confirmation_key,
            &transcript_hash,
            b"server",
            &server_confirmation,
        ));

        let client_confirmation =
            create_key_confirmation(&confirmation_key, &transcript_hash, b"client");
        send_key_confirmation(&mut stream, &client_confirmation).unwrap();

        let session_id = derive_session_id(&shared_secret);
        let ratchet = Arc::new(Mutex::new(create_ratchet_alice(
            &shared_secret,
            *server_ratchet_x25519.as_bytes(),
        )));

        send_ratchet_message(&mut stream, &ratchet, &session_id, b"ping").unwrap();
        let message = receive_ratchet_message(&mut stream, &ratchet, &session_id).unwrap();
        assert_eq!(message, b"pong");

        let server_session_id = server_handle.join().unwrap();
        assert_eq!(session_id, server_session_id);
    }
    #[test]
    fn session_id_changes_when_transcript_changes() {
        let shared_secret = [91u8; 32];
        let transcript1 = [92u8; 32];
        let mut transcript2 = transcript1;
        transcript2[0] ^= 1;

        let server_secret = x25519_dalek::StaticSecret::from([93u8; 32]);
        let client_secret = x25519_dalek::StaticSecret::from([94u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let client_public = x25519_dalek::PublicKey::from(&client_secret);

        let session_secret1 =
            derive_session_secret(&server_secret, &server_public, &client_public, &transcript1);
        let session_secret2 =
            derive_session_secret(&server_secret, &server_public, &client_public, &transcript2);

        let _ = shared_secret;
        assert_ne!(session_secret1, session_secret2);
        assert_ne!(
            derive_session_id(&session_secret1),
            derive_session_id(&session_secret2)
        );
    }

    #[test]
    fn reconnect_uses_a_new_session_id() {
        let server_signing = SigningKey::from_bytes(&[41u8; 32]);
        let client_signing = SigningKey::from_bytes(&[42u8; 32]);
        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();
        let (_, server_x25519) = handshake::generate_keypair();
        let (_, client_x25519) = handshake::generate_keypair();
        let (_, server_ratchet_x25519) = handshake::generate_keypair();

        let challenge1 = [51u8; handshake::CHALLENGE_SIZE];
        let challenge2 = [52u8; handshake::CHALLENGE_SIZE];

        let transcript1 = handshake::handshake_transcript_hash(
            &challenge1,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );
        let transcript2 = handshake::handshake_transcript_hash(
            &challenge2,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );

        let server_secret = x25519_dalek::StaticSecret::from([53u8; 32]);
        let client_secret = x25519_dalek::StaticSecret::from([54u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let client_public = x25519_dalek::PublicKey::from(&client_secret);

        let session_secret1 =
            derive_session_secret(&server_secret, &server_public, &client_public, &transcript1);
        let session_secret2 =
            derive_session_secret(&server_secret, &server_public, &client_public, &transcript2);

        let session_id1 = derive_session_id(&session_secret1);
        let session_id2 = derive_session_id(&session_secret2);

        assert_ne!(session_secret1, session_secret2);
        assert_ne!(session_id1, session_id2);
    }

    #[test]
    fn old_handshake_signature_cannot_verify_on_reconnect() {
        let server_signing = SigningKey::from_bytes(&[61u8; 32]);
        let client_signing = SigningKey::from_bytes(&[62u8; 32]);

        let server_identity = server_signing.verifying_key();
        let client_identity = client_signing.verifying_key();

        let server_secret = x25519_dalek::StaticSecret::from([63u8; 32]);
        let client_secret = x25519_dalek::StaticSecret::from([64u8; 32]);

        let server_x25519 = x25519_dalek::PublicKey::from(&server_secret);
        let client_x25519 = x25519_dalek::PublicKey::from(&client_secret);

        let server_ratchet_x25519 =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([65u8; 32]));

        let challenge1 = [66u8; handshake::CHALLENGE_SIZE];
        let mut challenge2 = challenge1;
        challenge2[0] ^= 1;

        let signature = handshake::sign_handshake_transcript(
            &server_signing,
            &challenge1,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        );

        assert!(!handshake::verify_handshake_transcript(
            &server_identity,
            &signature,
            &challenge2,
            &server_identity,
            &client_identity,
            &server_x25519,
            &client_x25519,
            &server_ratchet_x25519,
        ));
    }
}
