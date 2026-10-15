use yosemite::{Session, style::Stream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting I2P SAM session...");
    let session = Session::<Stream>::new(Default::default()).await?;
    println!("I2P session created");
    println!("Local destination: {}", session.destination());
    Ok(())
}
