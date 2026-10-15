use snow::Builder;

const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

fn main() {
    let keygen = Builder::new(PARAMS.parse().unwrap());
    let initiator_keys = keygen.generate_keypair().unwrap();
    let responder_keys = keygen.generate_keypair().unwrap();

    let mut initiator = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&initiator_keys.private)
        .unwrap()
        .prologue(b"private-messenger v3")
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&responder_keys.private)
        .unwrap()
        .prologue(b"private-messenger v3")
        .unwrap()
        .build_responder()
        .unwrap();

    let mut message = [0u8; 65535];
    let mut payload = [0u8; 65535];

    let length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..length], &mut payload)
        .unwrap();

    let length = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..length], &mut payload)
        .unwrap();

    let length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..length], &mut payload)
        .unwrap();

    assert!(initiator.is_handshake_finished() && responder.is_handshake_finished());
    assert_eq!(
        initiator.get_handshake_hash(),
        responder.get_handshake_hash()
    );
    assert_eq!(
        initiator.get_remote_static().unwrap(),
        responder_keys.public.as_slice()
    );
    assert_eq!(
        responder.get_remote_static().unwrap(),
        initiator_keys.public.as_slice()
    );

    let mut initiator = initiator.into_transport_mode().unwrap();
    let mut responder = responder.into_transport_mode().unwrap();

    let length = initiator.write_message(b"hallo", &mut message).unwrap();
    let plain = responder
        .read_message(&message[..length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..plain], b"hallo");

    println!("XX handshake ok");
}
