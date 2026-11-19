#![cfg(any(target_os = "macos", target_os = "linux"))]
use omd_isolation::{Error, Policy, Session};
use std::{collections::BTreeMap, time::Duration};
use tokio_util::sync::CancellationToken;

fn session(work: &std::path::Path) -> Session {
    Session::start(
        &Policy {
            executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
            readable: vec![],
            executables: vec![],
            work: work.into(),
            broker_port: None,
            broker_upstream_port: None,
            interactive: false,
        },
        &["--protocol".into()],
        &BTreeMap::new(),
        false,
    )
    .unwrap()
}
#[tokio::test]
async fn ordered_exchanges_and_explicit_close() {
    let work = tempfile::tempdir().unwrap();
    let mut session = session(work.path());
    for n in 0..40 {
        let input = format!("request-{n}");
        assert_eq!(
            session
                .exchange(
                    input.as_bytes(),
                    1024,
                    Duration::from_secs(3),
                    &CancellationToken::new()
                )
                .await
                .unwrap(),
            input.as_bytes()
        );
    }
    session.close().await;
    session.close().await;
    assert!(matches!(
        session
            .exchange(
                b"late",
                1024,
                Duration::from_secs(3),
                &CancellationToken::new()
            )
            .await,
        Err(Error::Failed)
    ));
}
#[tokio::test]
async fn timeouts_and_output_budgets_poison_the_channel() {
    for request in ["stall", "stdout-budget", "stderr-budget"] {
        let work = tempfile::tempdir().unwrap();
        let mut session = session(work.path());
        assert!(
            matches!(
                session
                    .exchange(
                        request.as_bytes(),
                        1024,
                        Duration::from_millis(500),
                        &CancellationToken::new()
                    )
                    .await,
                Err(Error::Budget)
            ),
            "{request}"
        );
        assert!(matches!(
            session
                .exchange(
                    b"must-not-consume-old-response",
                    1024,
                    Duration::from_secs(3),
                    &CancellationToken::new()
                )
                .await,
            Err(Error::Failed)
        ));
    }
}
#[tokio::test]
async fn cancellation_closes_the_process_before_returning() {
    let work = tempfile::tempdir().unwrap();
    let mut session = session(work.path());
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        signal.cancel();
    });
    assert!(matches!(
        session
            .exchange(b"stall", 1024, Duration::from_secs(3), &cancel)
            .await,
        Err(Error::Canceled)
    ));
    assert!(matches!(
        session
            .exchange(
                b"late",
                1024,
                Duration::from_secs(3),
                &CancellationToken::new()
            )
            .await,
        Err(Error::Failed)
    ));
}
#[tokio::test]
async fn invalid_requests_do_not_enter_adapter() {
    let work = tempfile::tempdir().unwrap();
    let mut session = session(work.path());
    assert!(matches!(
        session
            .exchange(
                b"one\ntwo",
                1024,
                Duration::from_secs(3),
                &CancellationToken::new()
            )
            .await,
        Err(Error::Invalid)
    ));
    assert_eq!(
        session
            .exchange(
                b"valid",
                1024,
                Duration::from_secs(3),
                &CancellationToken::new()
            )
            .await
            .unwrap(),
        b"valid"
    );
}
