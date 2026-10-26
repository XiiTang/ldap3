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

fn assert_request_limit(
    operation: ldap3::asn1::StructureTag,
    limits: CodecLimits,
    expected: ldap3::RequestLimit,
) {
    let error = LdapCodec::new(limits)
        .unwrap()
        .validate_request(&operation, &[])
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<ldap3::RequestLimit>(),
        Some(&expected),
    );
}

#[test]
fn request_depth_refusal_stops_before_counting_the_tree() {
    use ldap3::asn1::ASNTag;
    let mut operation = ldap3::requests::unbind().into_structure();
    operation.payload = ldap3::asn1::PL::C(vec![operation.clone()]);
    assert_request_limit(
        operation,
        CodecLimits {
            maximum_depth: 1,
            maximum_nodes: 1,
            ..Default::default()
        },
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::Depth,
            maximum: 1,
            observed: None,
        },
    );
}

#[test]
fn request_tag_refusal_names_the_encoder_tag_bound() {
    use ldap3::asn1::ASNTag;
    let mut operation = ldap3::requests::unbind().into_structure();
    operation.id = 31;
    assert_request_limit(
        operation,
        CodecLimits::default(),
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::Tag,
            maximum: 30,
            observed: Some(31),
        },
    );
}

#[test]
fn request_node_refusal_has_no_complete_observed_count() {
    use ldap3::asn1::ASNTag;
    let mut operation = ldap3::requests::unbind().into_structure();
    operation.payload = ldap3::asn1::PL::C(vec![operation.clone(), operation.clone()]);
    assert_request_limit(
        operation,
        CodecLimits {
            maximum_nodes: 1,
            ..Default::default()
        },
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::Nodes,
            maximum: 1,
            observed: None,
        },
    );
}

#[test]
fn request_retained_allocation_refusal_measures_capacity_before_frame() {
    use ldap3::asn1::ASNTag;
    let mut operation = ldap3::requests::unbind().into_structure();
    let mut bytes = Vec::with_capacity(4096);
    bytes.push(0);
    let retained = bytes.capacity();
    operation.payload = ldap3::asn1::PL::P(bytes);
    assert_request_limit(
        operation,
        CodecLimits {
            maximum_allocation: retained - 1,
            maximum_frame: 2,
            ..Default::default()
        },
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::RetainedAllocation,
            maximum: retained - 1,
            observed: Some(retained),
        },
    );
}

#[test]
fn request_frame_refusal_precedes_total_allocation_and_keeps_its_measurement() {
    use ldap3::asn1::ASNTag;
    assert_request_limit(
        ldap3::requests::unbind().into_structure(),
        CodecLimits {
            maximum_frame: 2,
            maximum_allocation: 100,
            ..Default::default()
        },
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::Frame,
            maximum: 2,
            observed: Some(10),
        },
    );
    let at_frame = LdapCodec::new(CodecLimits {
        maximum_frame: 10,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        at_frame
            .validate_request(&ldap3::requests::unbind().into_structure(), &[])
            .unwrap(),
        1064
    );
}

#[test]
fn request_total_allocation_refusal_includes_encoder_and_bookkeeping() {
    use ldap3::asn1::ASNTag;
    assert_request_limit(
        ldap3::requests::unbind().into_structure(),
        CodecLimits {
            maximum_allocation: 1063,
            ..Default::default()
        },
        ldap3::RequestLimit {
            kind: ldap3::RequestLimitKind::TotalAllocation,
            maximum: 1063,
            observed: Some(1064),
        },
    );
    let at_allocation = LdapCodec::new(CodecLimits {
        maximum_allocation: 1064,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        at_allocation
            .validate_request(&ldap3::requests::unbind().into_structure(), &[])
            .unwrap(),
        1064
    );
}
