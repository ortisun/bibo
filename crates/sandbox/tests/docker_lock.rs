//! The lock that keeps the real-Docker tests from using the daemon's network address pool at the
//! same time, and its two companions: a hard limit on how long a test may hold it, and the retry
//! of the one error that a full address pool gives.
//!
//! These tests need no Docker. They use a lock file of their own, so they never wait for (or hold
//! up) a real-Docker test that is running next to them.

// This target uses only part of the helper, which the Docker targets use in full.
#[allow(dead_code)]
#[path = "support/docker_lock.rs"]
mod docker_lock;

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use docker_lock::{
    DockerLock, WaitedTooLong, is_network_pool_exhausted, retry_while_pool_exhausted,
};

/// A lock file that no other test uses.
fn own_lock_path(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "factory-docker-lock-test-{}-{name}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

#[test]
fn a_second_taker_waits_for_the_first_and_then_gets_the_lock() {
    let path = own_lock_path("handover");
    let first = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("the first taker");
    let second = {
        let path = path.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let lock = DockerLock::acquire_at(&path, Duration::from_secs(10)).expect("handover");
            (started.elapsed(), lock)
        })
    };
    std::thread::sleep(Duration::from_millis(400));
    assert!(!second.is_finished(), "the second taker must be waiting");
    drop(first);
    let (waited, _lock) = second.join().expect("the second taker");
    assert!(
        waited >= Duration::from_millis(300),
        "it waited only {waited:?}"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn giving_up_says_blocked_and_names_the_lock_and_its_holder() {
    let path = own_lock_path("giving-up");
    let _held = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("the holder");
    let started = Instant::now();
    // Another thread asks: the thread that holds the lock would be told off at once instead.
    let refused: WaitedTooLong = {
        let path = path.clone();
        std::thread::spawn(move || DockerLock::acquire_at(&path, Duration::from_millis(300)))
            .join()
            .expect("the waiting thread")
            .expect_err("it must give up")
    };
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "it must not hang: {:?}",
        started.elapsed()
    );
    let text = refused.to_string();
    assert!(text.starts_with("BLOCKED:"), "{text}");
    assert!(text.contains(&path.display().to_string()), "{text}");
    assert!(
        text.contains(&format!("pid {}", std::process::id())),
        "the holder is named: {text}"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_thread_that_asks_for_the_lock_it_already_holds_is_told_at_once() {
    // Two labs in one test would wait for each other for ever. The second asker is refused on
    // the spot, with the reason, instead of after the whole wait limit.
    let path = own_lock_path("same-thread");
    let _first = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("the first lock");
    let started = Instant::now();
    let refused = DockerLock::acquire_at(&path, Duration::from_secs(60))
        .expect_err("the same thread cannot hold it twice");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "it waited {:?}",
        started.elapsed()
    );
    let text = refused.to_string();
    assert!(text.starts_with("BLOCKED:"), "{text}");
    assert!(text.contains("already holds"), "{text}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_lock_held_by_another_process_blocks_a_taker_in_this_one() {
    // A second open file description on the same file is what another process has. The lock is
    // taken on it directly, so only the file layer can refuse the taker.
    let path = own_lock_path("other-process");
    let other = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .expect("open");
    other.lock().expect("another process holds the lock");
    let refused = DockerLock::acquire_at(&path, Duration::from_millis(300));
    assert!(refused.is_err(), "the file lock must refuse a second taker");
    drop(other);
    DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("free after the other let go");
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_lock_is_released_when_its_holder_panics() {
    let path = own_lock_path("panic");
    let for_thread = path.clone();
    let holder = std::thread::spawn(move || {
        let _lock = DockerLock::acquire_at(&for_thread, Duration::from_secs(5)).expect("holder");
        panic!("a test failed while it held the lock");
    });
    assert!(holder.join().is_err());
    DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("free after the panic");
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_hold_limit_fires_for_a_test_that_runs_too_long() {
    let path = own_lock_path("hold-limit");
    let fired = Arc::new(AtomicBool::new(false));
    let lock = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("holder");
    lock.start_watchdog(Duration::from_millis(200), {
        let fired = Arc::clone(&fired);
        move |_label| fired.store(true, Ordering::SeqCst)
    });
    std::thread::sleep(Duration::from_millis(900));
    assert!(fired.load(Ordering::SeqCst), "the hard limit never fired");
    drop(lock);
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_hold_limit_stays_quiet_for_a_test_that_ends_in_time() {
    let path = own_lock_path("hold-quiet");
    let fired = Arc::new(AtomicBool::new(false));
    let lock = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("holder");
    lock.start_watchdog(Duration::from_millis(500), {
        let fired = Arc::clone(&fired);
        move |_label| fired.store(true, Ordering::SeqCst)
    });
    drop(lock);
    std::thread::sleep(Duration::from_millis(900));
    assert!(
        !fired.load(Ordering::SeqCst),
        "the limit fired after the test had ended"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn the_hard_stop_is_given_the_label_of_the_lab_so_it_removes_only_that() {
    let path = own_lock_path("hold-label");
    let seen: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
    let lock = DockerLock::acquire_at(&path, Duration::from_secs(5)).expect("holder");
    lock.register_label("1234-abcd0123");
    lock.start_watchdog(Duration::from_millis(100), {
        let seen = Arc::clone(&seen);
        move |label| *seen.lock().expect("lock") = Some(label)
    });
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        seen.lock().expect("lock").clone(),
        Some(Some("1234-abcd0123".to_owned()))
    );
    drop(lock);
    let _ = std::fs::remove_file(path);
}

#[test]
fn only_the_full_address_pool_message_counts_as_exhaustion() {
    for text in [
        "Error response from daemon: all predefined address pools have been fully subnetted",
        "Error response from daemon: could not find an available, non-overlapping IPv4 address pool among the defaults to assign to the network",
        "ERROR RESPONSE FROM DAEMON: ALL PREDEFINED ADDRESS POOLS HAVE BEEN FULLY SUBNETTED",
    ] {
        assert!(is_network_pool_exhausted(text), "{text}");
    }
    for text in [
        "",
        "Error response from daemon: network with name sf-net-x already exists",
        "Error response from daemon: invalid pool request: Pool overlaps with other one on this address space",
        "Error response from daemon: conflict: unable to remove repository reference",
        "permission denied while trying to connect to the Docker daemon socket",
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        "Error response from daemon: Conflict. The container name \"/sf-x\" is already in use",
    ] {
        assert!(!is_network_pool_exhausted(text), "{text}");
    }
}

#[test]
fn a_full_pool_is_retried_with_a_growing_wait_and_then_succeeds() {
    let calls = AtomicU32::new(0);
    let mut waits = Vec::new();
    let outcome = retry_while_pool_exhausted(
        || {
            if calls.fetch_add(1, Ordering::SeqCst) < 3 {
                Err("all predefined address pools have been fully subnetted".to_owned())
            } else {
                Ok("created")
            }
        },
        |result: &Result<&str, String>| matches!(result, Err(text) if is_network_pool_exhausted(text)),
        |wait| waits.push(wait),
    );
    assert_eq!(outcome, Ok("created"));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(waits.len(), 3);
    assert!(
        waits.windows(2).all(|pair| pair[0] < pair[1]),
        "the wait grows: {waits:?}"
    );
}

#[test]
fn any_other_error_is_returned_at_once_without_a_retry() {
    for text in [
        "network with name sf-net-x already exists",
        "permission denied",
        "Pool overlaps with other one on this address space",
    ] {
        let calls = AtomicU32::new(0);
        let mut waits = Vec::new();
        let outcome: Result<(), String> = retry_while_pool_exhausted(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(text.to_owned())
            },
            |result: &Result<(), String>| matches!(result, Err(t) if is_network_pool_exhausted(t)),
            |wait| waits.push(wait),
        );
        assert_eq!(outcome, Err(text.to_owned()));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{text}");
        assert!(waits.is_empty(), "{text}: {waits:?}");
    }
}

#[test]
fn a_pool_that_stays_full_gives_up_and_returns_the_last_error() {
    let calls = AtomicU32::new(0);
    let mut waits = Vec::new();
    let outcome: Result<(), String> = retry_while_pool_exhausted(
        || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Err(format!(
                "attempt {n}: all predefined address pools have been fully subnetted"
            ))
        },
        |result: &Result<(), String>| matches!(result, Err(t) if is_network_pool_exhausted(t)),
        |wait| waits.push(wait),
    );
    let attempts = calls.load(Ordering::SeqCst);
    assert_eq!(attempts as usize, docker_lock::BACKOFF.len() + 1);
    assert_eq!(waits.len(), docker_lock::BACKOFF.len());
    assert_eq!(
        outcome,
        Err(format!(
            "attempt {}: all predefined address pools have been fully subnetted",
            attempts - 1
        ))
    );
    let total: Duration = waits.iter().sum();
    assert!(
        total < Duration::from_secs(60),
        "the wait is bounded: {total:?}"
    );
}
