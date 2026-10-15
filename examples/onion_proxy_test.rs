use arti_client::{TorClient, TorClientConfig};
use safelog::DisplayRedacted;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsrproxy::config::{
    Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsservice::HsNickname;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_rtcompat::SpawnExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Arti...");
    let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    println!("Arti bootstrapped");

    let listener = TcpListener::bind("127.0.0.1:9000").await?;

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };

        let mut buf = [0u8; 4];
        if stream.read_exact(&mut buf).await.is_ok() {
            let _ = stream.write_all(&buf).await;
            let _ = stream.flush().await;
        }
    });

    let nickname = HsNickname::new("private-messenger-test".to_string())?;

    let config = OnionServiceConfigBuilder::default()
        .nickname(nickname.clone())
        .build()?;

    let Some((running, requests)) = client.launch_onion_service(config)? else {
        return Err("onion service disabled".into());
    };

    let rule = ProxyRule::new(
        ProxyPattern::one_port(9000)?,
        ProxyAction::Forward(
            Encapsulation::Simple,
            TargetAddr::Inet("127.0.0.1:9000".parse::<SocketAddr>()?),
        ),
    );

    let mut proxy_config = ProxyConfigBuilder::default();
    proxy_config.set_proxy_ports(vec![rule]);

    let proxy = OnionServiceReverseProxy::new(proxy_config.build()?);

    let runtime = client.runtime().clone();
    let proxy_clone = proxy.clone();

    client.runtime().spawn(async move {
        if let Err(error) = proxy_clone
            .handle_requests(runtime, nickname, requests)
            .await
        {
            eprintln!("Proxy error: {error}");
        }
    })?;

    let address = running.onion_address().ok_or("onion address unavailable")?;

    tokio::time::sleep(Duration::from_secs(30)).await;
    println!("Waiting for onion service publication...");
    let host = address.display_unredacted().to_string();

    println!("Onion service:");
    println!("{host}");
    println!("Testing onion -> proxy -> 127.0.0.1:9000...");

    let mut stream = timeout(
        Duration::from_secs(120),
        client.connect((host.as_str(), 9000)),
    )
    .await??;

    stream.write_all(b"ping").await?;
    stream.flush().await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if &response != b"ping" {
        return Err("wrong response".into());
    }

    println!("END TO END SUCCESS");
    println!("Tor onion connection reached the local TCP service");

    proxy.shutdown();

    Ok(())
}
