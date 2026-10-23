use ldap3::{
    CodecLimits, DriverLimits, LdapConnAsync,
    asn1::{PL, StructureTag, TagClass},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn limits() -> DriverLimits {
    DriverLimits {
        codec: CodecLimits::default(),
        maximum_outstanding: 2,
        maximum_request_bytes: 1024 * 1024,
        maximum_response_bytes: 1024 * 1024,
        maximum_response_items: 2,
    }
}
fn delete() -> StructureTag {
    StructureTag {
        class: TagClass::Application,
        id: 10,
        payload: PL::P(b"dc=test".to_vec()),
    }
}
fn abandon(id: u8) -> StructureTag {
    StructureTag {
        class: TagClass::Application,
        id: 16,
        payload: PL::P(vec![id]),
    }
}
async fn reply(peer: &mut tokio::io::DuplexStream, id: u8, operation: u8) {
    peer.write_all(&[0x30, 12, 2, 1, id, operation, 7, 10, 1, 0, 4, 0, 4, 0])
        .await
        .unwrap();
}
async fn request(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut header = [0; 2];
    peer.read_exact(&mut header).await.unwrap();
    assert!(header[1] < 128);
    let mut body = vec![0; usize::from(header[1])];
    peer.read_exact(&mut body).await.unwrap();
    body
}
#[tokio::test]
async fn shared_capacity_survives_dropped_receipts_and_reverse_order_responses() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
    let mut clone = handle.clone();
    let first = handle.submit(delete(), vec![]).unwrap();
    let first_id = first.id;
    drop(first);
    let mut second = clone.submit(delete(), vec![]).unwrap();
    let full = handle.submit(delete(), vec![]).err().unwrap();
    assert_eq!(full.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        full.get_ref()
            .unwrap()
            .downcast_ref::<ldap3::OutstandingLimit>()
            .unwrap()
            .maximum,
        2
    );
    let driver = tokio::spawn(conn.drive());
    request(&mut peer).await;
    request(&mut peer).await;
    second.written().await.unwrap();
    reply(&mut peer, second.id as u8, 0x6b).await;
    let mut event = events.recv().await.unwrap();
    assert!(event.complete);
    assert_eq!(event.response.id, second.id);
    event.confirm();
    let third = handle.submit(delete(), vec![]).unwrap();
    assert!(third.id > second.id);
    reply(&mut peer, first_id as u8, 0x6b).await;
    assert_eq!(events.recv().await.unwrap().response.id, first_id);
    driver.abort();
    let _ = driver.await;
}
#[tokio::test]
async fn abandon_keeps_late_response_identity_and_invalid_abandon_does_not_dispatch() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
    let driver = tokio::spawn(conn.drive());
    let mut bad = handle.submit(abandon(123), vec![]).unwrap();
    assert!(bad.written().await.is_err());
    assert!(!bad.was_dispatched());
    let operation = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    let mut abandoned = handle.submit(abandon(operation.id as u8), vec![]).unwrap();
    request(&mut peer).await;
    abandoned.written().await.unwrap();
    reply(&mut peer, operation.id as u8, 0x6b).await;
    let event = events.recv().await.unwrap();
    assert!(event.complete);
    assert!(event.abandon_requested);
    assert_eq!(event.response.id, operation.id);
    driver.abort();
    let _ = driver.await;
}
fn search() -> StructureTag {
    StructureTag {
        class: TagClass::Application,
        id: 3,
        payload: PL::C(vec![]),
    }
}
#[tokio::test]
async fn forgetting_a_search_frees_its_slot_and_discards_what_still_arrives() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let limits = DriverLimits {
        maximum_outstanding: 3,
        ..limits()
    };
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let driver = tokio::spawn(conn.drive());
    let search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    // Only a search is forgotten: an update's outcome would be lost.
    let update = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    let mut refused = handle.forget(update.id).unwrap();
    assert!(refused.written().await.is_err());
    reply(&mut peer, update.id as u8, 0x6b).await;
    let mut updated = events.recv().await.unwrap();
    assert_eq!(updated.response.id, update.id);
    updated.confirm();
    let mut forgotten = handle.forget(search.id).unwrap();
    request(&mut peer).await;
    forgotten.written().await.unwrap();
    // Every slot of three is free again.
    let first = handle.submit(delete(), vec![]).unwrap();
    let second = handle.submit(delete(), vec![]).unwrap();
    let third = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    request(&mut peer).await;
    request(&mut peer).await;
    // What the server still sends for the search reaches no one.
    reply(&mut peer, search.id as u8, 0x65).await;
    reply(&mut peer, first.id as u8, 0x6b).await;
    let event = events.recv().await.unwrap();
    assert_eq!(event.response.id, first.id);
    for operation in [&second, &third] {
        reply(&mut peer, operation.id as u8, 0x6b).await;
        assert_eq!(events.recv().await.unwrap().response.id, operation.id);
    }
    // An identifier never issued still ends the driver.
    reply(&mut peer, 99, 0x6b).await;
    assert!(driver.await.unwrap().is_err());
}
#[tokio::test]
async fn mismatched_operation_closes_driver_without_delivering_a_false_result() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
    let driver = tokio::spawn(conn.drive());
    let operation = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    reply(&mut peer, operation.id as u8, 0x67).await;
    assert!(driver.await.unwrap().is_err());
    assert!(events.recv().await.is_none());
}
#[tokio::test]
async fn full_delivery_queue_backpressures_reads_but_keeps_abandon_writes_live() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let mut limits = limits();
    limits.maximum_response_items = 1;
    limits.maximum_outstanding = 3;
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let driver = tokio::spawn(conn.drive());
    let first = handle.submit(delete(), vec![]).unwrap();
    let second = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    request(&mut peer).await;
    reply(&mut peer, first.id as u8, 0x6b).await;
    reply(&mut peer, second.id as u8, 0x6b).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!driver.is_finished());
    let third = handle.submit(delete(), vec![]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), request(&mut peer))
        .await
        .unwrap();
    let mut cancel = handle.submit(abandon(third.id as u8), vec![]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), request(&mut peer))
        .await
        .unwrap();
    cancel.written().await.unwrap();
    reply(&mut peer, third.id as u8, 0x6b).await;
    assert_eq!(events.recv().await.unwrap().response.id, first.id);
    assert_eq!(events.recv().await.unwrap().response.id, second.id);
    let event = events.recv().await.unwrap();
    assert_eq!(event.response.id, third.id);
    assert!(event.abandon_requested);
    driver.abort();
    let _ = driver.await;
}
#[tokio::test]
async fn request_byte_limit_is_shared_and_precedes_queue_and_id_allocation() {
    let (stream, _peer) = tokio::io::duplex(32);
    let mut limits = limits();
    limits.maximum_request_bytes = 1100;
    let (_conn, mut handle, _) = LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let first = handle.submit(delete(), vec![]).unwrap();
    assert_eq!(first.id, 1);
    drop(first);
    assert!(handle.submit(delete(), vec![]).is_err());
}

#[tokio::test]
async fn delivered_but_retained_responses_keep_their_byte_permits() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let mut limits = limits();
    limits.maximum_response_bytes = 500;
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let driver = tokio::spawn(conn.drive());
    let first = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    reply(&mut peer, first.id as u8, 0x6b).await;
    let retained = events.recv().await.unwrap();
    let second = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    reply(&mut peer, second.id as u8, 0x6b).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), events.recv())
            .await
            .is_err()
    );
    assert!(!driver.is_finished());
    drop(retained);
    assert_eq!(events.recv().await.unwrap().response.id, second.id);
    driver.abort();
    let _ = driver.await;
}
#[tokio::test]
async fn explicit_upgrade_recovers_only_an_idle_transport_without_buffered_plaintext() {
    use ldap3::asn1::ASNTag;
    for trailing in [false, true] {
        let (stream, mut peer) = tokio::io::duplex(1024);
        let (conn, mut handle, mut events) =
            LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
        let mut dispatch = handle
            .submit(
                ldap3::requests::extended(ldap3::exop::Exop {
                    name: Some("1.3.6.1.4.1.1466.20037".into()),
                    val: None,
                })
                .into_structure(),
                vec![],
            )
            .unwrap();
        let exchange = tokio::spawn(conn.drive_one());
        request(&mut peer).await;
        let mut response = vec![
            0x30,
            12,
            2,
            1,
            dispatch.id as u8,
            0x78,
            7,
            10,
            1,
            0,
            4,
            0,
            4,
            0,
        ];
        if trailing {
            response.push(0x30);
        }
        peer.write_all(&response).await.unwrap();
        let conn = exchange.await.unwrap().unwrap();
        dispatch.written().await.unwrap();
        let mut event = events.recv().await.unwrap();
        assert!(event.complete);
        event.confirm();
        drop(event);
        let stream = conn.into_stream();
        assert_eq!(stream.is_err(), trailing);
    }
}

#[tokio::test]
async fn sasl_handoff_preserves_coalesced_security_frames_without_ber_decoding() {
    use ldap3::asn1::ASNTag;
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
    let mut dispatch = handle
        .submit(
            ldap3::requests::sasl_bind("GSSAPI", Some(vec![])).into_structure(),
            vec![],
        )
        .unwrap();
    let exchange = tokio::spawn(conn.drive_one());
    request(&mut peer).await;
    let mut bytes = vec![
        0x30,
        12,
        2,
        1,
        dispatch.id as u8,
        0x61,
        7,
        10,
        1,
        0,
        4,
        0,
        4,
        0,
    ];
    let protected = b"\x00\x00\x00\x06opaque";
    bytes.extend_from_slice(protected);
    peer.write_all(&bytes).await.unwrap();
    let conn = exchange.await.unwrap().unwrap();
    dispatch.written().await.unwrap();
    let mut event = events.recv().await.unwrap();
    assert!(event.complete);
    event.confirm();
    drop(event);
    let (mut stream, buffered) = conn.into_security_stream().unwrap();
    assert_eq!(buffered, protected);
    stream.write_all(b"wrapped-next-request").await.unwrap();
    let mut output = [0; 20];
    peer.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, b"wrapped-next-request");
}

#[tokio::test]
async fn cancellation_drops_a_capacity_blocked_driver_and_its_transport() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let mut limits = limits();
    limits.maximum_response_items = 1;
    let (conn, mut handle, _events) = LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let driver = tokio::spawn(conn.drive());
    let first = handle.submit(delete(), vec![]).unwrap();
    let second = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    request(&mut peer).await;
    reply(&mut peer, first.id as u8, 0x6b).await;
    reply(&mut peer, second.id as u8, 0x6b).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn no_response_controls_work_with_every_outstanding_slot_occupied() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, _events) = LdapConnAsync::from_stream_bounded(
        stream,
        DriverLimits {
            maximum_outstanding: 1,
            ..limits()
        },
    )
    .unwrap();
    let driver = tokio::spawn(conn.drive());
    let search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    assert!(handle.submit(delete(), vec![]).is_err());
    let mut abandoned = handle.submit(abandon(search.id as u8), vec![]).unwrap();
    abandoned.written().await.unwrap();
    assert_eq!(request(&mut peer).await[3], 0x50);
    let mut forgotten = handle.forget(search.id).unwrap();
    assert_eq!(forgotten.written().await.unwrap(), ldap3::RawWrite::NoSend);
    assert!(!forgotten.was_dispatched());
    let mut next = handle.submit(delete(), vec![]).unwrap();
    next.written().await.unwrap();
    assert_eq!(
        request(&mut peer).await[3],
        0x4a,
        "forget must not send Abandon twice"
    );
    let mut unbind = handle
        .submit(
            StructureTag {
                class: TagClass::Application,
                id: 2,
                payload: PL::P(vec![]),
            },
            vec![],
        )
        .unwrap();
    unbind.written().await.unwrap();
    assert_eq!(request(&mut peer).await[3], 0x42);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn forgetting_an_already_abandoned_search_only_releases_its_slot() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, _events) = LdapConnAsync::from_stream_bounded(stream, limits()).unwrap();
    let driver = tokio::spawn(conn.drive());
    let search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    let mut abandoned = handle.submit(abandon(search.id as u8), vec![]).unwrap();
    abandoned.written().await.unwrap();
    assert_eq!(request(&mut peer).await[3], 0x50);
    let mut forgotten = handle.forget(search.id).unwrap();
    assert_eq!(forgotten.written().await.unwrap(), ldap3::RawWrite::NoSend);
    assert!(!forgotten.was_dispatched());
    let mut next = handle.submit(delete(), vec![]).unwrap();
    next.written().await.unwrap();
    assert_eq!(
        request(&mut peer).await[3],
        0x4a,
        "duplicate Abandon on the wire"
    );
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn a_decoded_completion_suppresses_abandon_without_claiming_confirmation() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) = LdapConnAsync::from_stream_bounded(
        stream,
        DriverLimits {
            maximum_outstanding: 1,
            ..limits()
        },
    )
    .unwrap();
    let driver = tokio::spawn(conn.drive());
    let search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    reply(&mut peer, search.id as u8, 0x65).await;
    let mut final_result = events.recv().await.unwrap();
    assert_eq!(
        handle.submit(delete(), vec![]).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut abandoned = handle.submit(abandon(search.id as u8), vec![]).unwrap();
    assert_eq!(abandoned.written().await.unwrap(), ldap3::RawWrite::NoSend);
    assert!(!abandoned.was_dispatched());
    assert_eq!(
        handle.submit(delete(), vec![]).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock,
        "wire decoding is not semantic confirmation"
    );
    final_result.confirm();
    drop(final_result);
    let mut next = handle.submit(delete(), vec![]).unwrap();
    next.written().await.unwrap();
    assert_eq!(request(&mut peer).await[3], 0x4a);
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn forgetting_a_decoded_search_releases_its_slot_while_the_event_is_retained() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let (conn, mut handle, mut events) = LdapConnAsync::from_stream_bounded(
        stream,
        DriverLimits {
            maximum_outstanding: 1,
            ..limits()
        },
    )
    .unwrap();
    let driver = tokio::spawn(conn.drive());
    let search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    reply(&mut peer, search.id as u8, 0x65).await;
    let final_result = events.recv().await.unwrap();
    assert!(handle.submit(delete(), vec![]).is_err());
    let mut forgotten = handle.forget(search.id).unwrap();
    assert_eq!(forgotten.written().await.unwrap(), ldap3::RawWrite::NoSend);
    let mut next = handle.submit(delete(), vec![]).unwrap();
    next.written().await.unwrap();
    assert_eq!(request(&mut peer).await[3], 0x4a, "no redundant Abandon");
    assert_eq!(final_result.response.id, search.id);
    assert!(final_result.complete);
    drop(final_result);
    driver.abort();
    let _ = driver.await;
}

#[tokio::test]
async fn controls_still_obey_the_shared_request_byte_budget() {
    let (stream, _peer) = tokio::io::duplex(1024);
    let (conn, mut handle, _events) = LdapConnAsync::from_stream_bounded(
        stream,
        DriverLimits {
            maximum_outstanding: 1,
            maximum_request_bytes: 65536,
            ..limits()
        },
    )
    .unwrap();
    let search = handle.submit(search(), vec![]).unwrap();
    let mut held = Vec::new();
    loop {
        match handle.forget(search.id) {
            Ok(dispatch) => held.push(dispatch),
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                break;
            }
        }
        assert!(held.len() < 1024, "control allocation must be bounded");
    }
    assert!(
        !held.is_empty(),
        "controls do not use ordinary outstanding slots"
    );
    drop(conn);
    assert_eq!(
        handle.forget(search.id).err().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn a_failed_cleanup_write_keeps_its_cause_and_outstanding_search() {
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };
    struct FailingWriter {
        stream: tokio::io::DuplexStream,
        fail: Arc<AtomicBool>,
    }
    impl tokio::io::AsyncRead for FailingWriter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
    impl tokio::io::AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail.load(Ordering::Acquire) {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "cleanup write fixture",
                )))
            } else {
                Pin::new(&mut self.stream).poll_write(cx, bytes)
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }
    let (stream, mut peer) = tokio::io::duplex(1024);
    let fail = Arc::new(AtomicBool::new(false));
    let (conn, mut handle, _events) = LdapConnAsync::from_stream_bounded(
        FailingWriter {
            stream,
            fail: fail.clone(),
        },
        limits(),
    )
    .unwrap();
    let driver = tokio::spawn(conn.drive());
    let mut search = handle.submit(search(), vec![]).unwrap();
    request(&mut peer).await;
    search.written().await.unwrap();
    fail.store(true, Ordering::Release);
    let mut forget = handle.forget(search.id).unwrap();
    let error = forget.written().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "cleanup write fixture");
    assert!(forget.was_dispatched());
    assert!(search.was_dispatched());
    assert!(
        driver
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cleanup write fixture")
    );
}
