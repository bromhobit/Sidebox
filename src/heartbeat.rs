//! Keep iOS network services alive for the entire device operation.

use std::{future::Future, time::Duration};

use idevice::{
    IdeviceError, IdeviceService, heartbeat::HeartbeatClient, provider::IdeviceProvider,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const FIRST_MARCO_TIMEOUT_SECS: u64 = 20;

struct HeartbeatTask(tokio::task::JoinHandle<Result<(), String>>);

impl Drop for HeartbeatTask {
    fn drop(&mut self) {
        // Dropping the outer operation must never detach a heartbeat task.
        self.0.abort();
    }
}

pub(crate) fn device_error_detail(err: &IdeviceError) -> String {
    match err {
        // `IdeviceError`'s Display implementation hides the underlying OS error.
        IdeviceError::Socket(source) => format!("ошибка сокета: {source}"),
        _ => err.to_string(),
    }
}

fn next_timeout_secs(interval: u64) -> u64 {
    interval.saturating_add(10).clamp(15, 120)
}

/// A separate authenticated heartbeat connection must stay open while the
/// operation uses misagent, installation_proxy or AFC over a network provider.
pub(crate) async fn with_heartbeat<T, F>(
    provider: &dyn IdeviceProvider,
    operation: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    let client = tokio::time::timeout(CONNECT_TIMEOUT, HeartbeatClient::connect(provider))
        .await
        .map_err(|_| "Таймаут запуска службы поддержания связи с iPhone.".to_string())?
        .map_err(|e| {
            format!(
                "Не удалось запустить службу поддержания связи с iPhone: {}",
                device_error_detail(&e)
            )
        })?;
    with_heartbeat_client(client, operation).await
}

async fn with_heartbeat_client<T, F>(mut client: HeartbeatClient, operation: F) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    // Wait for the initial Marco/Polo exchange before using other services.
    let mut interval = client
        .get_marco(FIRST_MARCO_TIMEOUT_SECS)
        .await
        .map_err(|e| {
            format!(
                "iPhone не подтвердил поддержание связи: {}",
                device_error_detail(&e)
            )
        })?;
    tokio::time::timeout(CONNECT_TIMEOUT, client.send_polo())
        .await
        .map_err(|_| "Таймаут ответа службе поддержания связи.".to_string())?
        .map_err(|e| format!("Ошибка поддержания связи: {}", device_error_detail(&e)))?;

    let mut task = HeartbeatTask(tokio::spawn(async move {
        loop {
            interval = client
                .get_marco(next_timeout_secs(interval))
                .await
                .map_err(|e| device_error_detail(&e))?;
            tokio::time::timeout(CONNECT_TIMEOUT, client.send_polo())
                .await
                .map_err(|_| "таймаут ответа iPhone".to_string())?
                .map_err(|e| device_error_detail(&e))?;
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    }));

    tokio::select! {
        result = operation => {
            // Wait for cancellation so the next operation cannot overlap the
            // old heartbeat connection after the engine lock is released.
            task.0.abort();
            let _ = (&mut task.0).await;
            result
        }
        heartbeat_result = &mut task.0 => {
            let reason = match heartbeat_result {
                Ok(Err(reason)) => reason,
                Ok(Ok(())) => "соединение закрыто".to_string(),
                Err(_) => "задача поддержания связи завершилась".to_string(),
            };
            Err(format!("Связь с iPhone прервалась: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idevice::Idevice;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    async fn send_marco(stream: &mut DuplexStream) {
        let mut message = plist::Dictionary::new();
        message.insert("Command".into(), "Marco".into());
        message.insert("Interval".into(), 10_u64.into());
        let mut data = Vec::new();
        plist::to_writer_xml(&mut data, &message).unwrap();
        stream.write_u32(data.len() as u32).await.unwrap();
        stream.write_all(&data).await.unwrap();
    }

    async fn receive_polo(stream: &mut DuplexStream) {
        let size = stream.read_u32().await.unwrap() as usize;
        let mut data = vec![0; size];
        stream.read_exact(&mut data).await.unwrap();
        let reply: plist::Dictionary = plist::from_bytes(&data).unwrap();
        assert_eq!(
            reply.get("Command").and_then(|v| v.as_string()),
            Some("Polo")
        );
    }

    #[test]
    fn heartbeat_timeout_is_bounded() {
        assert_eq!(next_timeout_secs(0), 15);
        assert_eq!(next_timeout_secs(10), 20);
        assert_eq!(next_timeout_secs(u64::MAX), 120);
    }

    #[tokio::test]
    async fn heartbeat_answers_marco_until_operation_finishes() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let client = HeartbeatClient::new(Idevice::new(Box::new(client_stream), "test"));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut server = server_stream;
            for _ in 0..2 {
                send_marco(&mut server).await;
                receive_polo(&mut server).await;
            }
            let _ = done_tx.send(());
            // Keep the fake peer alive until the guarded operation finishes.
            let _ = server.read_u8().await;
        });
        let result = with_heartbeat_client(client, async {
            done_rx.await.map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        })
        .await;
        assert_eq!(result, Ok(()));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_loss_fails_the_guarded_operation() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let client = HeartbeatClient::new(Idevice::new(Box::new(client_stream), "test"));
        let server = tokio::spawn(async move {
            let mut server = server_stream;
            send_marco(&mut server).await;
            receive_polo(&mut server).await;
            // Dropping the peer interrupts the operation.
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            with_heartbeat_client(client, std::future::pending::<Result<(), String>>()),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("Связь с iPhone прервалась"));
        server.await.unwrap();
    }
}
