use bytes::BytesMut;
use ldap3::{CodecLimits, LdapCodec, LdapConnAsync};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::Decoder;
#[test]
fn exact_wire_and_unknown_numeric_results_survive_the_single_decoder() {
    // message ID 1, BindResponse with unassigned numeric result 1234.
    let wire = [0x30, 13, 2, 1, 1, 0x61, 8, 10, 2, 4, 0xd2, 4, 0, 4, 0];
    let mut input = BytesMut::from(&wire[..]);
    input.extend_from_slice(&wire);
    let mut codec = LdapCodec::new(CodecLimits::default()).unwrap();
    let reply = codec.decode(&mut input).unwrap().unwrap();
    assert_eq!(reply.id, 1);
    assert_eq!(reply.raw.as_ref(), wire);
    assert_eq!(input.as_ref(), wire);
    assert_eq!(reply.operation.id, 1);
    let children = reply.operation.expect_constructed().unwrap();
    assert_eq!(children[0].clone().expect_primitive().unwrap(), [4, 0xd2]);
}
#[test]
fn malformed_peer_envelopes_and_controls_fail_without_panicking_or_consuming() {
    for wire in [
        &[0x30, 0][..],
        &[0x30, 3, 2, 1, 1],
        &[0x30, 5, 2, 1, 0xff, 0x61, 0],
        &[0x30, 7, 2, 1, 1, 0x61, 0, 4, 0],
        // Empty BOOLEAN inside a response control.
        &[
            0x30, 16, 2, 1, 1, 0x61, 0, 0xa0, 9, 0x30, 7, 4, 3, b'1', b'.', b'2', 1, 0,
        ],
        &[0x30, 0x80],
        &[0x30, 0x89],
        // Outer message complete; inner operation length escapes it.
        &[0x30, 5, 2, 1, 1, 0x61, 8],
    ] {
        let mut codec = LdapCodec::new(CodecLimits::default()).unwrap();
        let mut input = BytesMut::from(wire);
        assert!(codec.decode(&mut input).is_err(), "{wire:?}");
        assert_eq!(input.as_ref(), wire);
    }
    let mut codec = LdapCodec::new(CodecLimits {
        maximum_frame: 8,
        ..Default::default()
    })
    .unwrap();
    assert!(
        codec
            .decode(&mut BytesMut::from(&[0x30, 0x82, 1, 0][..]))
            .is_err()
    );
}
#[tokio::test]
async fn supplied_transport_uses_library_bind_and_correlation_without_opening_a_socket() {
    let (stream, mut peer) = tokio::io::duplex(128);
    let (conn, mut ldap) = LdapConnAsync::from_stream(stream, CodecLimits::default()).unwrap();
    let driver = tokio::spawn(conn.drive());
    let server = tokio::spawn(async move {
        // Empty LDAPv3 simple BindRequest, packet identifier 1.
        let mut request = [0; 14];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(
            request,
            [0x30, 12, 2, 1, 1, 0x60, 7, 2, 1, 3, 4, 0, 0x80, 0]
        );
        peer.write_all(&[0x30, 12, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0])
            .await
            .unwrap();
        let mut unbind = [0; 7];
        peer.read_exact(&mut unbind).await.unwrap();
        assert_eq!(unbind, [0x30, 5, 2, 1, 2, 0x42, 0]);
    });
    let result = ldap.simple_bind("", "").await.unwrap();
    assert_eq!(result.rc, 0);
    ldap.unbind().await.unwrap();
    drop(ldap);
    driver.await.unwrap().unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn blocked_large_write_does_not_stop_an_earlier_response() {
    let (stream, mut peer) = tokio::io::duplex(32);
    let (conn, mut first) = LdapConnAsync::from_stream(stream, CodecLimits::default()).unwrap();
    let mut second = first.clone();
    let driver = tokio::spawn(conn.drive());
    let bind = tokio::spawn(async move { first.simple_bind("", "").await });
    let mut request = [0; 14];
    peer.read_exact(&mut request).await.unwrap();
    let blocked = tokio::spawn(async move {
        second
            .extended(ldap3::exop::Exop {
                name: Some("1.2.3".into()),
                val: Some(vec![1; 65536]),
            })
            .await
    });
    // Confirm that the second frame has begun, then deliberately stop draining it.
    let mut header = [0; 2];
    peer.read_exact(&mut header).await.unwrap();
    peer.write_all(&[0x30, 12, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0])
        .await
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), bind).await;
    driver.abort();
    let _ = driver.await;
    drop(peer);
    let _ = blocked.await;
    assert_eq!(
        result
            .expect("response stalled behind writer")
            .unwrap()
            .unwrap()
            .rc,
        0
    );
}
