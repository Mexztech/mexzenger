# Private Messenger

Status: Work in Progress (WIP)

An experimental Rust privacy messenger with end-to-end encrypted messaging, a double ratchet, and TCP, Tor, and I2P transports.

## Current status

- Authenticated X25519 + Ed25519 handshake with transcript binding and mutual key confirmation
- Double ratchet messaging with per-message keys (ChaCha20Poly1305), out-of-order delivery and replay protection
- Transports: TCP, Tor (onion services via Arti), I2P (via SAM/yosemite)
- Encrypted keepalive with ping/pong (protocol v2)
- Multi-contact identity pinning (TOFU) with encrypted contacts storage
- Encrypted local message history
- File transfer (chunked, integrity-checked)
- Voice notes (Opus) with `/vnote` and `/vplay`
- Offline mailbox: asynchronous text, file and voice-note deposits sealed to the recipient identity key, over TCP, Tor and I2P
- 58 tests passing

## Chat commands

- `/quit` - leave the chat
- `/send <path>` - send a file
- `/vnote <seconds>` - record and send a voice note
- `/vplay [file]` - play a voice note (default: latest received)
- `/mail <message>` - deposit a text message into the peer mailbox
- `/mailfile <path>` - deposit a file into the peer mailbox
- `/mailvnote <seconds>` - record and deposit a voice note

## Security warning

This project is experimental and has not been independently security audited. Do not use it for sensitive or real-world private communications. Passing tests does not prove the implementation is secure.

The cryptographic primitives come from widely used crates (x25519-dalek, ed25519-dalek, chacha20poly1305, hkdf, sha2), but the protocol composition itself is custom and unreviewed.

## Development

Run tests: `cargo test`

Check formatting: `cargo fmt --check`

Run Clippy: `cargo clippy --all-targets --all-features`

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See LICENSE.
