use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use yosemite::{style::Stream, Session, SessionOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Session::<Stream>::new(SessionOptions {
        silent_forward: true,
        ..Default::default()
    }).await?;

    let destination = server.destination().to_owned();

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9100").await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();

        let mut buffer = vec![0u8; 33];
        stream.read_exact(&mut buffer).await.unwrap();
        eprintln!("SERVER GOT: {:?}", buffer);

        stream.write_all(&buffer).await.unwrap();
        stream.flush().await.unwrap();
        eprintln!("SERVER SENT: {:?}", buffer);
    });

    server.forward(9100).await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut client = Session::<Stream>::new(Default::default()).await?;
    let mut stream = client.connect(&destination).await?;

    let data = b"private-messenger-i2p-test-123456";
    stream.write_all(data).await?;
    stream.flush().await?;

    let mut response = vec![0u8; data.len()];
    stream.read_exact(&mut response).await?;

    if response != data {
        return Err(format!(
            "I2P forwarded bytes changed
expected: {:?}
actual:   {:?}",
            data, response
        ).into());
    }

    println!("I2P FORWARD END TO END SUCCESS");
    Ok(())
}
