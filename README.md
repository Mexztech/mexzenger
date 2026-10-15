# Private Messenger

**Status: Work in Progress (WIP)**

An experimental Rust messenger exploring encrypted communication, key exchange, a double ratchet, and TCP, Tor, and I2P transports.

## Current status

- TCP handshake and encrypted messaging tests
- Double ratchet tests
- Experimental Tor and I2P transport work
- 37 tests currently passing

## Security warning

This project is experimental and has not been independently security audited. Do not use it for sensitive or real-world private communications. Passing tests does not prove the implementation is secure.

## Development

Run tests: `cargo test`

Check formatting: `cargo fmt --check`

Run Clippy: `cargo clippy --all-targets --all-features`

## License

No license has been selected yet.
