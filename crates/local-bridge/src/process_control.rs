//! Local bridge process control internals.

use super::*;

pub(super) struct BoundedCapture {
    pub(super) bytes: Vec<u8>,
    pub(super) exceeded: bool,
    pub(super) failed: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ReaderEvent {
    Overflow,
    Failed,
}

pub(super) async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    maximum: usize,
    event_tx: mpsc::UnboundedSender<ReaderEvent>,
) -> BoundedCapture {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if output.len().saturating_add(read) > maximum {
                    output.truncate(maximum);
                    let _ = event_tx.send(ReaderEvent::Overflow);
                    return BoundedCapture {
                        bytes: output,
                        exceeded: true,
                        failed: false,
                    };
                }
                output.extend_from_slice(&buffer[..read]);
            }
            Err(_) => {
                // Do not collapse a reader error into a clean EOF.  The bridge
                // cannot safely claim that the child completed when output
                // collection failed.
                let _ = event_tx.send(ReaderEvent::Failed);
                return BoundedCapture {
                    bytes: output,
                    exceeded: false,
                    failed: true,
                };
            }
        }
    }
    BoundedCapture {
        bytes: output,
        exceeded: false,
        failed: false,
    }
}

pub(super) async fn join_capture(
    task: Option<tokio::task::JoinHandle<BoundedCapture>>,
) -> BoundedCapture {
    match task {
        Some(task) => task.await.unwrap_or(BoundedCapture {
            bytes: Vec::new(),
            exceeded: false,
            failed: true,
        }),
        None => BoundedCapture {
            bytes: Vec::new(),
            exceeded: false,
            failed: false,
        },
    }
}

pub(super) async fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(super) async fn terminate_execution(
    child: &mut Child,
    control: &mut Option<tokio::process::ChildStdin>,
    independently_supervised: bool,
) {
    if independently_supervised {
        terminate_supervised_child(child, control).await;
    } else {
        terminate_child(child).await;
    }
}

async fn terminate_supervised_child(
    child: &mut Child,
    control: &mut Option<tokio::process::ChildStdin>,
) {
    // Closing the control pipe asks the independent supervisor to kill and
    // reap its runtime process group. Keep a hard fallback for a wedged peer.
    drop(control.take());
    if tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .is_ok()
    {
        return;
    }
    terminate_child(child).await;
}
