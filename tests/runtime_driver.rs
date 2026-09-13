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
    assert!(handle.submit(delete(), vec![]).is_err());
    let driver = tokio::spawn(conn.drive());
    request(&mut peer).await;
    request(&mut peer).await;
    second.written().await.unwrap();
    reply(&mut peer, second.id as u8, 0x6b).await;
    let event = events.recv().await.unwrap();
    assert!(event.complete);
    assert_eq!(event.response.id, second.id);
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
async fn full_delivery_queue_fails_explicitly_and_does_not_stall_transport() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let mut limits = limits();
    limits.maximum_response_items = 1;
    let (conn, mut handle, mut events) =
        LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
    let driver = tokio::spawn(conn.drive());
    let first = handle.submit(delete(), vec![]).unwrap();
    let second = handle.submit(delete(), vec![]).unwrap();
    request(&mut peer).await;
    request(&mut peer).await;
    reply(&mut peer, first.id as u8, 0x6b).await;
    reply(&mut peer, second.id as u8, 0x6b).await;
    assert!(driver.await.unwrap().is_err());
    assert_eq!(events.recv().await.unwrap().response.id, first.id);
    assert!(events.recv().await.is_none());
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
    assert!(driver.await.unwrap().is_err());
    assert!(handle.outcome_unknown());
    drop(retained);
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
        assert!(events.recv().await.unwrap().complete);
        let stream = conn.into_stream();
        assert_eq!(stream.is_err(), trailing);
    }
}
