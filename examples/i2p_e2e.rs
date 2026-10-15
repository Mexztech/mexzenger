use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yosemite::{Session, style::Stream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting I2P server session...");
    let mut server = Session::<Stream>::new(Default::default()).await?;
    let destination = server.destination().to_string();

    println!("I2P destination:");
    println!("{destination}");

    let server_task = tokio::spawn(async move {
        let mut stream = server.accept().await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
        Ok::<_, yosemite::Error>(())
    });

    println!("Connecting through I2P...");
    let mut client = Session::<Stream>::new(Default::default()).await?;
    let mut stream = client.connect(&destination).await?;
    println!("I2P connection established");

    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if &response != b"ping" {
        return Err("wrong response".into());
    }

    server_task.await??;

    println!("I2P END TO END SUCCESS");
    Ok(())
}
