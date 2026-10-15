use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use safelog::DisplayRedacted;
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Arti...");
    let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    println!("Arti bootstrapped");

    let mut builder = OnionServiceConfigBuilder::default();
    builder.nickname("private-messenger-test".parse()?);
    let config = builder.build()?;

    let Some((running, _requests)) = client.launch_onion_service(config)? else {
        return Err("onion service disabled".into());
    };

    let address = running.onion_address().ok_or("onion address unavailable")?;

    println!("Onion service:");
    println!("{}", address.display_unredacted());
    println!("Keeping service alive for 60 seconds...");

    sleep(Duration::from_secs(60)).await;

    Ok(())
}
