//! Wake delivery is checked against a long fallback, not a sub-10ms latency.
//! Thread-ready handshakes keep the watchdog separate from thread startup.
use super::*;

const FALLBACK: Duration = Duration::from_secs(60);
const WATCHDOG: Duration = Duration::from_secs(10);

fn receive_payload<T>(rx: &Receiver<T>) -> T {
    loop {
        match receive_dispatch_job(rx, FALLBACK) {
            Ok(value) => return value,
            Err(mpsc::RecvTimeoutError::Timeout) => continue, // park may wake spuriously
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("fixture sender disconnected"),
        }
    }
}

#[test]
fn completion_token_before_wait_is_not_lost() -> Result<(), String> {
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        let (_tx, rx) = mpsc::channel::<()>();
        ready.send(()).map_err(|error| error.to_string())?;
        std::thread::current().unpark();
        assert!(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Timeout)));
        done.send(()).map_err(|error| error.to_string())?;
        Ok(())
    });
    started.recv_timeout(WATCHDOG).map_err(|error| format!("receiver thread not ready: {error}"))?;
    finished.recv_timeout(WATCHDOG).map_err(|error| format!("completion unpark token was lost: {error}"))?;
    thread.join().map_err(|_| "fixture receiver thread panicked".to_owned())??;
    Ok(())
}

#[test]
fn request_arrival_wakes_wait_and_keeps_payload() -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        ready.send(std::thread::current()).map_err(|error| error.to_string())?;
        done.send(receive_payload(&rx)).map_err(|error| error.to_string())?;
        Ok(())
    });
    let handle = started.recv_timeout(WATCHDOG).map_err(|error| format!("receiver thread not ready: {error}"))?;
    tx.send(37).map_err(|error| error.to_string())?;
    handle.unpark();
    assert_eq!(finished.recv_timeout(WATCHDOG).map_err(|error| error.to_string())?, 37);
    thread.join().map_err(|_| "fixture receiver thread panicked".to_owned())??;
    Ok(())
}

#[test]
fn shutdown_wake_does_not_fabricate_job() -> Result<(), String> {
    let (_tx, rx) = mpsc::channel::<()>();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        ready.send(std::thread::current()).map_err(|error| error.to_string())?;
        done.send(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Timeout))).map_err(|error| error.to_string())?;
        Ok(())
    });
    started.recv_timeout(WATCHDOG).map_err(|error| format!("receiver thread not ready: {error}"))?.unpark();
    assert!(finished.recv_timeout(WATCHDOG).map_err(|error| error.to_string())?);
    thread.join().map_err(|_| "fixture receiver thread panicked".to_owned())??;
    Ok(())
}

#[test]
fn channel_disconnect_keeps_terminal_semantics() {
    let (tx, rx) = mpsc::channel::<()>();
    drop(tx);
    assert!(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Disconnected)));
}

#[test]
fn job_queued_before_dispatcher_registration_needs_no_wake() -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    tx.send(91).map_err(|error| error.to_string())?;
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || -> Result<(), String> {
        ready.send(()).map_err(|error| error.to_string())?;
        done.send(receive_payload(&rx)).map_err(|error| error.to_string())?;
        Ok(())
    });
    started.recv_timeout(WATCHDOG).map_err(|error| format!("receiver thread not ready: {error}"))?;
    assert_eq!(finished.recv_timeout(WATCHDOG).map_err(|error| error.to_string())?, 91);
    thread.join().map_err(|_| "fixture receiver thread panicked".to_owned())??;
    Ok(())
}
