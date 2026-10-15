use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Arti...");
    let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    println!("Arti bootstrapped");

    println!("Connecting through Tor...");
    let mut stream = client.connect(("example.com", 80)).await?;
    println!("Tor connection established");

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("Received {} bytes", buf.len());

    Ok(())
}
