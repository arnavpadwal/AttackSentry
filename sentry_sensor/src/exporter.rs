use crate::schema::FlowRecord;
use tokio::sync::mpsc::Receiver;

async fn connect(
    nats_url: &str,
    username: &str,
    password: Option<&str>,
) -> Result<async_nats::Client, String> {
    let options = if !username.is_empty() {
        async_nats::ConnectOptions::with_user_and_password(
            username.to_string(),
            password.unwrap_or_default().to_string(),
        )
    } else {
        async_nats::ConnectOptions::new()
    };
    // Never leave the UI stuck on "Connecting" because a host is unreachable.
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(6),
        options.connect(nats_url),
    )
    .await
    {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("connection to {nats_url} timed out")),
    }
}

pub async fn test_connection(
    nats_url: &str,
    username: &str,
    password: Option<&str>,
) -> Result<(), String> {
    let client = connect(nats_url, username, password).await?;
    client.flush().await.map_err(|e| e.to_string())
}

pub async fn start_exporter(
    mut rx: Receiver<FlowRecord>,
    nats_url: String,
    subject: String,
    username: String,
    password: Option<String>,
) {
    // Connect to NATS (retry until available).
    let client = loop {
        match connect(&nats_url, &username, password.as_deref()).await {
            Ok(c) => {
                println!("Exporter connected to NATS at {}", nats_url);
                break c;
            }
            Err(e) => {
                eprintln!("Exporter: NATS connect failed ({e}) — retrying in 2s");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    };

    while let Some(record) = rx.recv().await {
        match serde_json::to_string(&record) {
            Ok(payload) => {
                if let Err(e) = client.publish(subject.clone(), payload.into()).await {
                    eprintln!("Exporter: publish failed: {e}");
                }
            }
            Err(e) => eprintln!("Exporter: serialize failed: {e}"),
        }
    }
}
