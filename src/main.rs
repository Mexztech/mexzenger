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
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use transport::Transport;
use zeroize::Zeroizing;

use ratchet::{
    ChainKey, CryptoProviderImpl, PublicKey as RatchetPublicKey, Ratchet, keypair_from_x25519,
    root_key_from_shared_secret,
};

const CONTACTS_FILE: &str = "contacts";
#[cfg(test)]
fn packet_associated_data(session_id: &[u8; 16]) -> Vec<u8> {
    packet_associated_data_for_type(session_id, MESSAGE_TYPE_TEXT)
}

fn packet_associated_data_for_type(session_id: &[u8; 16], message_type: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(18);
    data.push(PROTOCOL_VERSION);
    data.push(message_type);
    data.extend_from_slice(session_id);
    data
}

const PACKET_SIZE: usize = 4096;
const PROTOCOL_VERSION: u8 = 2;
const MESSAGE_TYPE_TEXT: u8 = 1;
const MESSAGE_TYPE_PING: u8 = 2;
const MESSAGE_TYPE_PONG: u8 = 3;
const KEEPALIVE_SILENCE_SECS: u64 = 60;
const KEEPALIVE_PONG_WAIT_SECS: u64 = 30;
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
    #[cfg(debug_assertions)]
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
    #[cfg(debug_assertions)]
    eprintln!(
        "PUBLIC KEY RECV: sha256={}",
        Sha256::digest(bytes)
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
    #[cfg(debug_assertions)]
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

    #[cfg(debug_assertions)]
    eprintln!(
        "IDENTITY RECV: sha256={}",
        Sha256::digest(identity_bytes)
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

const CONTACTS_MAGIC: &[u8; 4] = b"PMC1";
const CONTACTS_KEY_SALT: &[u8] = b"private-messenger-contacts-v1";
static CONTACTS_MASTER_KEY: Mutex<Option<Zeroizing<[u8; 32]>>> = Mutex::new(None);
fn set_contacts_key(password: &[u8]) -> io::Result<()> {
    let mut master = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, CONTACTS_KEY_SALT, &mut *master)
        .map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Contacts key derivation failed")
        })?;
    let mut slot = CONTACTS_MASTER_KEY
        .lock()
        .map_err(|_| io::Error::other("Contacts key mutex poisoned"))?;
    *slot = Some(master);
    Ok(())
}
fn contacts_cipher(salt: &[u8]) -> io::Result<ChaCha20Poly1305> {
    let master = CONTACTS_MASTER_KEY
        .lock()
        .map_err(|_| io::Error::other("Contacts key mutex poisoned"))?
        .clone()
        .ok_or_else(|| io::Error::other("Contacts key not initialized"))?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &*master);
    let mut file_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"contacts-file-key", &mut *file_key)
        .expect("HKDF expansion failed");
    Ok(ChaCha20Poly1305::new(&Key::from(*file_key)))
}
fn encrypt_contacts_file(path: &str, fingerprints: &[String]) -> io::Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let cipher = contacts_cipher(&salt)?;
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| io::Error::other("Invalid nonce"))?;
    let mut plaintext = String::new();
    for fingerprint in fingerprints {
        plaintext.push_str(fingerprint);
        plaintext.push('\n');
    }
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| io::Error::other("Failed to encrypt contacts"))?;
    let mut data = Vec::with_capacity(4 + 16 + 12 + ciphertext.len());
    data.extend_from_slice(CONTACTS_MAGIC);
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce_bytes);
    data.extend_from_slice(&ciphertext);
    let tmp_path = format!("{path}.tmp");
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}
fn decrypt_contacts_file(data: &[u8]) -> io::Result<Vec<String>> {
    if data.len() < 4 + 16 + 12 + 16 || !data.starts_with(CONTACTS_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid contacts file",
        ));
    }
    let salt = &data[4..20];
    let nonce_bytes = &data[20..32];
    let ciphertext = &data[32..];
    let cipher = contacts_cipher(salt)?;
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| io::Error::other("Invalid nonce"))?;
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Could not decrypt contacts (wrong password or corrupted file)",
        )
    })?;
    let text = String::from_utf8_lossy(&plaintext);
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}
fn load_trusted_fingerprints(path: &str) -> io::Result<Vec<String>> {
    if !Path::new(path).exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path)?;
    if data.starts_with(CONTACTS_MAGIC) {
        return decrypt_contacts_file(&data);
    }
    let text = String::from_utf8_lossy(&data);
    let fingerprints: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    encrypt_contacts_file(path, &fingerprints)?;
    Ok(fingerprints)
}
fn add_trusted_fingerprint(path: &str, fingerprint: &str) -> io::Result<()> {
    let mut fingerprints = load_trusted_fingerprints(path)?;
    fingerprints.push(fingerprint.to_string());
    encrypt_contacts_file(path, &fingerprints)
}
const HISTORY_MAGIC: &[u8; 4] = b"PMH1";
const HISTORY_FILE: &str = "history";
const HISTORY_KEY_INFO: &[u8] = b"history-file-key";
const FINGERPRINT_LEN: usize = 47;

#[derive(Debug, PartialEq, Eq)]
struct HistoryEntry {
    timestamp: u64,
    outgoing: bool,
    peer: String,
    message: Vec<u8>,
}

struct HistoryLogger {
    path: String,
}

impl HistoryLogger {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    fn log(&mut self, peer: &str, outgoing: bool, message: &[u8]) -> io::Result<()> {
        history_append(&self.path, peer, outgoing, message)
    }
}

fn history_cipher(salt: &[u8]) -> io::Result<ChaCha20Poly1305> {
    let master = CONTACTS_MASTER_KEY
        .lock()
        .map_err(|_| io::Error::other("History key mutex poisoned"))?
        .clone()
        .ok_or_else(|| io::Error::other("History key not initialized"))?;
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &*master);
    let mut file_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HISTORY_KEY_INFO, &mut *file_key)
        .expect("HKDF expansion failed");
    Ok(ChaCha20Poly1305::new(&Key::from(*file_key)))
}

fn history_append(path: &str, peer: &str, outgoing: bool, message: &[u8]) -> io::Result<()> {
    if peer.len() != FINGERPRINT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid peer fingerprint length",
        ));
    }
    if !Path::new(path).exists() {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
        let mut header = Vec::with_capacity(20);
        header.extend_from_slice(HISTORY_MAGIC);
        header.extend_from_slice(&salt);
        fs::write(path, &header)?;
    }
    let header = fs::read(path)?;
    if header.len() < 20 || !header.starts_with(HISTORY_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid history file",
        ));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&header[4..20]);
    let cipher = history_cipher(&salt)?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| io::Error::other("Invalid nonce"))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| io::Error::other(format!("System clock error: {e}")))?
        .as_secs();
    let mut record = Vec::with_capacity(8 + 1 + FINGERPRINT_LEN + 4 + message.len());
    record.extend_from_slice(&timestamp.to_be_bytes());
    record.push(u8::from(outgoing));
    record.extend_from_slice(peer.as_bytes());
    record.extend_from_slice(&(message.len() as u32).to_be_bytes());
    record.extend_from_slice(message);
    let ciphertext = cipher
        .encrypt(&nonce, record.as_slice())
        .map_err(|_| io::Error::other("Failed to encrypt history record"))?;
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

fn history_read(path: &str) -> io::Result<Vec<HistoryEntry>> {
    if !Path::new(path).exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path)?;
    if data.len() < 20 || !data.starts_with(HISTORY_MAGIC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid history file",
        ));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[4..20]);
    let cipher = history_cipher(&salt)?;
    let mut entries = Vec::new();
    let mut position = 20;
    while position < data.len() {
        if position + 4 > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated history record",
            ));
        }
        let length = u32::from_be_bytes(data[position..position + 4].try_into().unwrap()) as usize;
        position += 4;
        if position + 12 + length > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated history record",
            ));
        }
        let nonce = Nonce::try_from(&data[position..position + 12])
            .map_err(|_| io::Error::other("Invalid nonce"))?;
        let ciphertext = &data[position + 12..position + 12 + length];
        position += 12 + length;
        let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Could not decrypt history record (wrong password or corrupted file)",
            )
        })?;
        if plaintext.len() < 8 + 1 + FINGERPRINT_LEN + 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid history record",
            ));
        }
        let timestamp = u64::from_be_bytes(plaintext[0..8].try_into().unwrap());
        let outgoing = plaintext[8] != 0;
        let peer = String::from_utf8_lossy(&plaintext[9..9 + FINGERPRINT_LEN]).to_string();
        let message_length = u32::from_be_bytes(
            plaintext[9 + FINGERPRINT_LEN..9 + FINGERPRINT_LEN + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if plaintext.len() != 9 + FINGERPRINT_LEN + 4 + message_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid history record length",
            ));
        }
        let message = plaintext[9 + FINGERPRINT_LEN + 4..].to_vec();
        entries.push(HistoryEntry {
            timestamp,
            outgoing,
            peer,
            message,
        });
    }
    Ok(entries)
}

fn format_unix_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let seconds_of_day = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (year + i64::from(month <= 2), month, day)
}

fn show_history() {
    match history_read(HISTORY_FILE) {
        Ok(entries) if entries.is_empty() => println!("No history"),
        Ok(entries) => {
            for entry in entries {
                let direction = if entry.outgoing { "sent" } else { "recv" };
                println!(
                    "{} {:4} {} {}",
                    format_unix_time(entry.timestamp),
                    direction,
                    entry.peer,
                    String::from_utf8_lossy(&entry.message)
                );
            }
        }
        Err(error) => println!("Could not read history: {}", error),
    }
}
fn is_trusted(fingerprints: &[String], current: &str) -> bool {
    fingerprints.iter().any(|trusted| trusted == current)
}

fn verify_or_pin_identity(identity: &VerifyingKey) -> bool {
    let current = fingerprint(identity);

    println!();
    println!("Remote identity fingerprint:");
    println!("{}", current);

    let trusted = match load_trusted_fingerprints(CONTACTS_FILE) {
        Ok(trusted) => trusted,
        Err(error) => {
            println!("Could not read contacts: {}", error);
            return false;
        }
    };

    if is_trusted(&trusted, &current) {
        println!();
        println!("Identity matches a trusted contact");

        return true;
    }

    if trusted.is_empty() {
        println!();
        println!("No trusted identity found");
        print!("Trust and save this identity? [y/N]: ");
    } else {
        println!();
        println!(
            "Unknown identity ({} trusted contacts on file)",
            trusted.len()
        );
        print!("Trust and add this identity? [y/N]: ");
    }

    io::stdout().flush().ok();

    let mut answer = String::new();

    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("Identity not trusted");
        return false;
    }

    match add_trusted_fingerprint(CONTACTS_FILE, &current) {
        Ok(()) => {
            println!("Identity pinned");
            true
        }

        Err(error) => {
            println!("Could not save trusted identity: {}", error);
            false
        }
    }
}

fn list_contacts() {
    match load_trusted_fingerprints(CONTACTS_FILE) {
        Ok(fingerprints) if fingerprints.is_empty() => println!("No trusted contacts"),
        Ok(fingerprints) => {
            println!("Trusted contacts:");
            for (index, entry) in fingerprints.iter().enumerate() {
                println!("{}. {}", index + 1, entry);
            }
        }
        Err(error) => println!("Could not read contacts: {}", error),
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
    send_ratchet_packet(stream, ratchet, session_id, MESSAGE_TYPE_TEXT, message)
}

fn send_ratchet_packet<T: Transport + ?Sized>(
    stream: &mut T,
    ratchet: &Arc<Mutex<Ratchet>>,
    session_id: &[u8; 16],
    message_type: u8,
    message: &[u8],
) -> io::Result<()> {
    let mut rng = SystemRng;

    let mut ratchet = ratchet
        .lock()
        .map_err(|_| io::Error::other("Ratchet mutex poisoned"))?;

    let padded_message = pad_message(message)?;
    let associated_data = packet_associated_data_for_type(session_id, message_type);

    let (header, ciphertext) = ratchet.ratchet_encrypt(&padded_message, &associated_data, &mut rng);

    let mut packet = Vec::with_capacity(PACKET_SIZE);

    packet.extend_from_slice(&[PROTOCOL_VERSION]);
    packet.extend_from_slice(&[message_type]);
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

fn receive_ratchet_packet<T: Transport + ?Sized>(
    stream: &mut T,
    ratchet: &Arc<Mutex<Ratchet>>,
    session_id: &[u8; 16],
    allowed_types: &[u8],
) -> io::Result<(u8, Vec<u8>)> {
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
        || !allowed_types.contains(&packet[1])
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
        .ratchet_decrypt(
            &header,
            ciphertext,
            &packet_associated_data_for_type(session_id, packet[1]),
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Ratchet decrypt failed: {:?}", error),
            )
        })?;

    Ok((packet[1], unpad_message(&padded_message)?))
}

#[cfg(test)]
fn receive_ratchet_message<T: Transport + ?Sized>(
    stream: &mut T,
    ratchet: &Arc<Mutex<Ratchet>>,
    session_id: &[u8; 16],
) -> io::Result<Vec<u8>> {
    let (message_type, payload) =
        receive_ratchet_packet(stream, ratchet, session_id, &[MESSAGE_TYPE_TEXT])?;

    debug_assert_eq!(message_type, MESSAGE_TYPE_TEXT);

    Ok(payload)
}

fn chat<T: Transport + 'static>(
    stream: T,
    ratchet: Ratchet,
    session_id: [u8; 16],
) -> io::Result<()> {
    let ratchet = Arc::new(Mutex::new(ratchet));
    let connected = Arc::new(AtomicBool::new(true));

    let send_stream: Arc<Mutex<Box<dyn Transport>>> =
        Arc::new(Mutex::new(stream.try_clone_transport()?));

    let receive_stream = stream.try_clone_transport()?;
    receive_stream.set_read_timeout(Some(Duration::from_secs(KEEPALIVE_SILENCE_SECS)))?;

    let receive_ratchet = Arc::clone(&ratchet);
    let ping_ratchet = Arc::clone(&ratchet);
    let ping_stream = Arc::clone(&send_stream);
    let receive_connected = Arc::clone(&connected);

    thread::spawn(move || {
        let mut stream = receive_stream;
        let mut ping_sent = false;

        loop {
            match receive_ratchet_packet(
                &mut *stream,
                &receive_ratchet,
                &session_id,
                &[MESSAGE_TYPE_TEXT, MESSAGE_TYPE_PING, MESSAGE_TYPE_PONG],
            ) {
                Ok((message_type, message)) => {
                    ping_sent = false;

                    if let Err(error) =
                        stream.set_read_timeout(Some(Duration::from_secs(KEEPALIVE_SILENCE_SECS)))
                    {
                        println!();
                        println!("Connection closed: {}", error);
                        break;
                    }

                    match message_type {
                        MESSAGE_TYPE_TEXT => {
                            println!();
                            println!("Friend: {}", String::from_utf8_lossy(&message));

                            print!("You: ");
                            io::stdout().flush().ok();
                        }

                        MESSAGE_TYPE_PING => {
                            let mut ping_stream = match ping_stream.lock() {
                                Ok(ping_stream) => ping_stream,
                                Err(_) => {
                                    println!();
                                    println!("Connection closed: transport mutex poisoned");
                                    break;
                                }
                            };

                            if let Err(error) = send_ratchet_packet(
                                &mut *ping_stream,
                                &ping_ratchet,
                                &session_id,
                                MESSAGE_TYPE_PONG,
                                &[],
                            ) {
                                println!();
                                println!("Connection closed: {}", error);
                                break;
                            }
                        }

                        _ => {}
                    }
                }

                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    if ping_sent {
                        println!();
                        println!("Connection closed: keepalive timeout");
                        break;
                    }

                    let mut ping_stream = match ping_stream.lock() {
                        Ok(ping_stream) => ping_stream,
                        Err(_) => {
                            println!();
                            println!("Connection closed: transport mutex poisoned");
                            break;
                        }
                    };

                    if let Err(error) = send_ratchet_packet(
                        &mut *ping_stream,
                        &ping_ratchet,
                        &session_id,
                        MESSAGE_TYPE_PING,
                        &[],
                    ) {
                        println!();
                        println!("Connection closed: {}", error);
                        break;
                    }

                    drop(ping_stream);

                    if let Err(error) =
                        stream.set_read_timeout(Some(Duration::from_secs(KEEPALIVE_PONG_WAIT_SECS)))
                    {
                        println!();
                        println!("Connection closed: {}", error);
                        break;
                    }

                    ping_sent = true;
                }

                Err(error) => {
                    println!();
                    println!("Connection closed: {}", error);
                    break;
                }
            }
        }

        receive_connected.store(false, Ordering::SeqCst);
    });

    println!();
    println!("Double Ratchet chat started");
    println!("Per-message keys enabled");
    println!(
        "Keepalive enabled ({}s silence, {}s pong wait)",
        KEEPALIVE_SILENCE_SECS, KEEPALIVE_PONG_WAIT_SECS
    );
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

        if !connected.load(Ordering::SeqCst) {
            println!("Connection closed by peer");
            break;
        }

        let mut send_stream = send_stream
            .lock()
            .map_err(|_| io::Error::other("Transport mutex poisoned"))?;

        if let Err(error) =
            send_ratchet_message(&mut *send_stream, &ratchet, &session_id, message.as_bytes())
        {
            drop(send_stream);
            println!("Failed to send message: {}", error);
            break;
        }

        drop(send_stream);

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

fn serve_connection(
    mut stream: Box<dyn Transport>,
    address: &str,
    signing_key: &SigningKey,
) -> io::Result<()> {
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
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Identity not trusted",
        ));
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

fn start_server_on(bind_address: &str, label: &str, signing_key: &SigningKey) -> io::Result<()> {
    let listener = transport::listen(bind_address)?;

    println!("Listening on {bind_address} ({label})...");

    loop {
        println!("Waiting for connection...");

        let (stream, address) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("Accept failed: {error}");
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };

        match serve_connection(stream, &address, signing_key) {
            Ok(()) => return Ok(()),
            Err(error) => eprintln!("Connection failed: {error}"),
        }
    }
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

fn with_default_port(address: &str, default_port: u16) -> String {
    if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:{default_port}")
    }
}

fn start_client(address: &str, signing_key: &SigningKey) -> io::Result<()> {
    println!("Connecting to {}...", address);

    let mut stream = if let Some(i2p_address) = address.strip_prefix("i2p://") {
        println!("Routing connection through I2P...");
        transport::connect_i2p(i2p_address)?
    } else if let Some(tor_address) = address.strip_prefix("tor://") {
        println!("Routing connection through Tor...");
        transport::connect_tor(&with_default_port(tor_address, 9000))?
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
            let (destination, private_key) = yosemite::RouterApi::default()
                .generate_destination()
                .await
                .map_err(|error| io::Error::other(format!("I2P destination: {error}")))?;

            let mut session = I2pSession::<I2pStream>::new(yosemite::SessionOptions {
                destination: yosemite::DestinationKind::Persistent { private_key },
                silent_forward: true,
                ..Default::default()
            })
            .await
            .map_err(|error| io::Error::other(format!("I2P session: {error}")))?;

            #[cfg(debug_assertions)]
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

fn encrypt_and_store_device_key(
    path: &str,
    signing_key: &SigningKey,
    password: &[u8],
) -> io::Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    getrandom::fill(&mut nonce_bytes).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let mut encryption_key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password, &salt, &mut *encryption_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Key derivation failed"))?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*encryption_key));
    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| io::Error::other("Invalid nonce"))?;
    let encrypted_key = cipher
        .encrypt(&nonce, signing_key.to_bytes().as_ref())
        .map_err(|_| io::Error::other("Failed to encrypt device key"))?;
    let mut data = Vec::with_capacity(16 + 12 + encrypted_key.len());
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce_bytes);
    data.extend_from_slice(&encrypted_key);
    let tmp_path = format!("{path}.tmp");
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn create_device() -> io::Result<SigningKey> {
    let password = Zeroizing::new(
        prompt_password("Choose a device password: ")
            .map_err(|e| io::Error::other(format!("Could not read password: {e}")))?,
    );
    let confirm = Zeroizing::new(
        prompt_password("Confirm device password: ")
            .map_err(|e| io::Error::other(format!("Could not read password: {e}")))?,
    );
    if password.as_bytes() != confirm.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ));
    }
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty",
        ));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret).map_err(|e| io::Error::other(format!("RNG failed: {e}")))?;
    let signing_key = SigningKey::from_bytes(&secret);
    encrypt_and_store_device_key("device.key", &signing_key, password.as_bytes())?;

    set_contacts_key(password.as_bytes())?;
    println!("New device created");
    println!(
        "Identity fingerprint: {}",
        fingerprint(&signing_key.verifying_key())
    );
    Ok(signing_key)
}

fn unlock_device() -> io::Result<SigningKey> {
    if !Path::new("device.key").exists() {
        println!("No device found");
        return create_device();
    }

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

    set_contacts_key(password.as_bytes())?;

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

    encrypt_and_store_device_key("device.key", signing_key, new_password.as_bytes())?;

    let fingerprints = load_trusted_fingerprints(CONTACTS_FILE)?;
    set_contacts_key(new_password.as_bytes())?;
    if !fingerprints.is_empty() {
        encrypt_contacts_file(CONTACTS_FILE, &fingerprints)?;
    }

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
    println!("5 = list contacts");

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

        "5" => {
            list_contacts();
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
    fn device_key_round_trip_and_wrong_password_rejected() {
        let path = "test_device_roundtrip.key";
        let _ = fs::remove_file(path);
        let signing_key = SigningKey::from_bytes(&[99u8; 32]);
        encrypt_and_store_device_key(path, &signing_key, b"correct horse battery").unwrap();
        let data = fs::read(path).unwrap();
        assert!(data.len() > 28);
        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let encrypted_key = &data[28..];
        let mut encryption_key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"correct horse battery", salt, &mut *encryption_key)
            .unwrap();
        let cipher = ChaCha20Poly1305::new(&Key::from(*encryption_key));
        let nonce = Nonce::try_from(nonce_bytes).unwrap();
        let decrypted = cipher.decrypt(&nonce, encrypted_key).unwrap();
        let key_bytes: [u8; 32] = decrypted.try_into().unwrap();
        assert_eq!(key_bytes, signing_key.to_bytes());
        let mut wrong_key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"wrong password", salt, &mut *wrong_key)
            .unwrap();
        let wrong_cipher = ChaCha20Poly1305::new(&Key::from(*wrong_key));
        assert!(wrong_cipher.decrypt(&nonce, encrypted_key).is_err());
        fs::remove_file(path).ok();
    }

    #[test]
    fn multiple_contacts_are_stored_and_matched() {
        let _ = set_contacts_key(b"contacts-test-password");

        let path = "test_contacts_store.txt";
        let _ = fs::remove_file(path);

        assert!(load_trusted_fingerprints(path).unwrap().is_empty());

        let first = "aa:bb".to_string();
        let second = "cc:dd".to_string();

        add_trusted_fingerprint(path, &first).unwrap();
        add_trusted_fingerprint(path, &second).unwrap();

        let stored = load_trusted_fingerprints(path).unwrap();
        assert_eq!(stored.len(), 2);
        assert!(is_trusted(&stored, &first));
        assert!(is_trusted(&stored, &second));
        assert!(!is_trusted(&stored, "ee:ff"));

        fs::remove_file(path).ok();
    }

    #[test]
    fn contacts_file_round_trip_and_legacy_migration() {
        let _ = set_contacts_key(b"contacts-test-password");

        let path = "test_contacts_encrypted.bin";
        let _ = fs::remove_file(path);

        fs::write(
            path,
            "aa:bb
cc:dd
",
        )
        .unwrap();

        let loaded = load_trusted_fingerprints(path).unwrap();
        assert_eq!(loaded, vec!["aa:bb".to_string(), "cc:dd".to_string()]);

        let data = fs::read(path).unwrap();
        assert!(data.starts_with(b"PMC1"));

        add_trusted_fingerprint(path, "ee:ff").unwrap();
        let loaded = load_trusted_fingerprints(path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(is_trusted(&loaded, "ee:ff"));

        fs::remove_file(path).ok();
    }

    #[test]
    fn ping_pong_round_trip_works() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let bob_ratchet_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret));
        let alice = create_ratchet_alice(&shared_secret, *bob_ratchet_public.as_bytes());
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        send_ratchet_packet(&mut client, &alice, &session_id, MESSAGE_TYPE_PING, b"").unwrap();
        let (message_type, payload) =
            receive_ratchet_packet(&mut server, &bob, &session_id, &[MESSAGE_TYPE_PING]).unwrap();
        assert_eq!(message_type, MESSAGE_TYPE_PING);
        assert!(payload.is_empty());

        send_ratchet_packet(&mut server, &bob, &session_id, MESSAGE_TYPE_PONG, b"").unwrap();
        let (message_type, payload) =
            receive_ratchet_packet(&mut client, &alice, &session_id, &[MESSAGE_TYPE_PONG]).unwrap();
        assert_eq!(message_type, MESSAGE_TYPE_PONG);
        assert!(payload.is_empty());
    }

    #[test]
    fn packet_type_outside_allowed_set_is_rejected_and_state_preserved() {
        let session_id = generate_session_id();
        let shared_secret = [7u8; 32];
        let bob_secret = [8u8; 32];

        let bob_ratchet_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret));
        let alice = create_ratchet_alice(&shared_secret, *bob_ratchet_public.as_bytes());
        let bob = create_ratchet_bob(&shared_secret, bob_secret);

        let alice = Arc::new(Mutex::new(alice));
        let bob = Arc::new(Mutex::new(bob));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        send_ratchet_message(&mut client, &alice, &session_id, b"hello").unwrap();

        assert!(
            receive_ratchet_packet(&mut server, &bob, &session_id, &[MESSAGE_TYPE_PONG]).is_err()
        );

        send_ratchet_message(&mut client, &alice, &session_id, b"world").unwrap();

        let received = receive_ratchet_message(&mut server, &bob, &session_id).unwrap();
        assert_eq!(received, b"world");
    }

    #[test]
    fn tor_address_gets_default_port() {
        assert_eq!(with_default_port("abc123.onion", 9000), "abc123.onion:9000");
        assert_eq!(
            with_default_port("abc123.onion:1234", 9000),
            "abc123.onion:1234"
        );
    }

    #[test]
    fn history_round_trip_and_tamper_detection() {
        let _ = set_contacts_key(b"history-test-password");

        let path = "test_history_roundtrip.bin";
        let _ = fs::remove_file(path);
        let peer = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

        history_append(path, peer, true, b"hello").unwrap();
        history_append(path, peer, false, b"").unwrap();
        history_append(path, peer, true, b"third message").unwrap();

        let entries = history_read(path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].peer, peer);
        assert!(entries[0].outgoing);
        assert_eq!(entries[0].message, b"hello");
        assert!(!entries[1].outgoing);
        assert!(entries[1].message.is_empty());
        assert_eq!(entries[2].message, b"third message");

        let mut data = fs::read(path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 1;
        fs::write(path, &data).unwrap();
        assert!(history_read(path).is_err());

        fs::remove_file(path).ok();
    }

    #[test]
    fn unix_time_formatting_is_sane() {
        assert_eq!(format_unix_time(0), "1970-01-01 00:00:00");
        assert_eq!(format_unix_time(86400), "1970-01-02 00:00:00");
        assert_eq!(format_unix_time(1767225600), "2026-01-01 00:00:00");
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
