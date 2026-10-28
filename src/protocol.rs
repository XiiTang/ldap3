use std::io;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
#[cfg(feature = "gssapi")]
use std::sync::{Arc, Mutex};

use crate::RequestId;
use crate::controls::{Control, RawControl};
use crate::controls_impl::{build_tag, try_parse_controls};
use crate::search::SearchItem;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Sequence, Tag};
use lber::universal::Types;
use lber::write;

use bytes::{Buf, Bytes, BytesMut};
#[cfg(feature = "gssapi")]
use cross_krb5::{ClientCtx, K5Ctx};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, Encoder};

/// Limits used by the single library BER decoder before allocation.
#[derive(Clone, Copy, Debug)]
pub struct CodecLimits {
    pub maximum_frame: usize,
    pub maximum_allocation: usize,
    pub maximum_nodes: usize,
    pub maximum_depth: usize,
}
impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            maximum_frame: 16 * 1024 * 1024,
            maximum_allocation: 64 * 1024 * 1024,
            maximum_nodes: 65536,
            maximum_depth: 64,
        }
    }
}
/// The codec check that first refused an outgoing request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestLimitKind {
    Depth,
    Tag,
    Nodes,
    RetainedAllocation,
    Frame,
    TotalAllocation,
}

/// A request validation refusal, carried as an `InvalidInput` I/O error source.
/// `observed` is absent when traversal stopped at its budget or arithmetic
/// overflow prevented a complete measurement. Validation never resumes to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("LDAP request {kind:?} limit exceeded (maximum {maximum}, observed {observed:?})")]
pub struct RequestLimit {
    pub kind: RequestLimitKind,
    pub maximum: usize,
    pub observed: Option<usize>,
}
impl RequestLimit {
    fn error(self, observed: Option<usize>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, Self { observed, ..self })
    }
    fn add(self, a: usize, b: usize) -> io::Result<usize> {
        a.checked_add(b).ok_or_else(|| self.error(None))
    }
    fn mul(self, a: usize, b: usize) -> io::Result<usize> {
        a.checked_mul(b).ok_or_else(|| self.error(None))
    }
    fn tlv(self, payload: usize) -> io::Result<usize> {
        self.add(
            payload,
            if payload < 128 {
                2
            } else {
                2 + (usize::BITS - payload.leading_zeros()).div_ceil(8) as usize
            },
        )
    }
}
fn request_limit(kind: RequestLimitKind, maximum: usize) -> RequestLimit {
    RequestLimit {
        kind,
        maximum,
        observed: None,
    }
}

/// Exact envelope evidence and the parsed operation. No numeric result code is
/// converted to a closed enum or interpreted as business success here.
pub struct RawResponse {
    pub id: RequestId,
    pub operation: StructureTag,
    pub controls: Vec<Control>,
    pub raw: Bytes,
}

#[derive(Clone)]
pub struct LdapCodec {
    limits: CodecLimits,
    #[cfg(feature = "gssapi")]
    pub(crate) has_decoded_data: bool,
    #[cfg(feature = "gssapi")]
    pub(crate) sasl_param: Arc<RwLock<(bool, u32)>>, // sasl_wrap, sasl_max_send
    #[cfg(feature = "gssapi")]
    pub(crate) client_ctx: Arc<Mutex<Option<ClientCtx>>>,
}

pub(crate) type MaybeControls = Option<Vec<RawControl>>;
pub(crate) type ItemSender = mpsc::UnboundedSender<(SearchItem, Vec<Control>)>;
pub(crate) type ResultSender = oneshot::Sender<(Tag, Vec<Control>)>;

#[derive(Debug)]
pub enum MiscSender {
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    Cert(oneshot::Sender<Option<Vec<u8>>>),
}

#[derive(Debug)]
pub enum LdapOp {
    #[allow(private_interfaces)]
    // Keep queued requests and their recoverable send errors small.
    Raw(Box<crate::raw::RawOperation>),
    Single,
    Search(ItemSender),
    Abandon(RequestId),
    Unbind,
}

impl LdapCodec {
    pub fn validate_request(
        &self,
        operation: &StructureTag,
        controls: &[RawControl],
    ) -> io::Result<usize> {
        request_allocation(operation, controls, self.limits)
    }
    pub fn new(limits: CodecLimits) -> io::Result<Self> {
        if limits.maximum_frame < 2
            || limits.maximum_allocation == 0
            || limits.maximum_nodes == 0
            || limits.maximum_depth == 0
            || limits.maximum_depth > 128
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LDAP codec limits",
            ));
        }
        Ok(Self {
            limits,
            #[cfg(feature = "gssapi")]
            has_decoded_data: false,
            #[cfg(feature = "gssapi")]
            sasl_param: Arc::new(RwLock::new((false, 0))),
            #[cfg(feature = "gssapi")]
            client_ctx: Arc::new(Mutex::new(None)),
        })
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid LDAP envelope")
}
fn decode_inner(buf: &mut BytesMut, limits: CodecLimits) -> io::Result<Option<RawResponse>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[0] != 0x30 {
        return Err(invalid());
    }
    let (header, payload) = if buf[1] < 128 {
        (2, buf[1] as usize)
    } else {
        let n = (buf[1] & 127) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return Err(invalid());
        }
        if buf.len() < 2 + n {
            return Ok(None);
        }
        let mut len = 0usize;
        for byte in &buf[2..2 + n] {
            len = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(*byte as usize))
                .ok_or_else(invalid)?;
        }
        (2 + n, len)
    };
    let length = header.checked_add(payload).ok_or_else(invalid)?;
    if length > limits.maximum_frame {
        return Err(invalid());
    }
    if buf.len() < length {
        return Ok(None);
    }
    let (tail, tag) = lber::parse::parse_tag_limited(
        &buf[..length],
        limits.maximum_depth,
        limits.maximum_nodes,
        limits.maximum_allocation,
    )
    .map_err(|_| invalid())?;
    if !tail.is_empty() {
        return Err(invalid());
    }
    let mut tags = tag.expect_constructed().ok_or_else(invalid)?.into_iter();
    let id = tags.next().ok_or_else(invalid)?;
    if id.class != TagClass::Universal || id.id != Types::Integer as u64 {
        return Err(invalid());
    }
    let id = id.expect_primitive().ok_or_else(invalid)?;
    if id.is_empty() || id.len() > 4 || id[0] & 128 != 0 {
        return Err(invalid());
    }
    let id = parse_uint(&id).map_err(|_| invalid())?.1;
    if id > i32::MAX as u64 {
        return Err(invalid());
    }
    let mut operation = tags.next().ok_or_else(invalid)?;
    if operation.class != TagClass::Application {
        return Err(invalid());
    }
    let mut trailing = tags.next();
    // Upstream accepts AD's responseName outside ExtendedResponse. Move the
    // known Notice field into its semantic position; keep the wire bytes below.
    if id == 0
        && operation.id == 24
        && trailing.as_ref().is_some_and(|field| {
            field.class == TagClass::Context
                && field.id == 10
                && matches!(&field.payload, PL::P(name) if name == b"1.3.6.1.4.1.1466.20036")
        })
    {
        let PL::C(fields) = &mut operation.payload else {
            return Err(invalid());
        };
        if fields
            .iter()
            .any(|field| field.class == TagClass::Context && field.id == 10)
        {
            return Err(invalid());
        }
        fields.push(trailing.take().expect("checked AD responseName"));
        trailing = tags.next();
    }
    let controls = trailing
        .map(try_parse_controls)
        .transpose()?
        .unwrap_or_default();
    if tags.next().is_some() {
        return Err(invalid());
    }
    let raw = Bytes::copy_from_slice(&buf[..length]);
    buf.advance(length);
    Ok(Some(RawResponse {
        id: id as i32,
        operation,
        controls,
        raw,
    }))
}

impl Decoder for LdapCodec {
    type Item = RawResponse;
    type Error = io::Error;

    #[cfg(not(feature = "gssapi"))]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_inner(buf, self.limits)
    }

    #[cfg(feature = "gssapi")]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();

        let sasl_wrap = { self.sasl_param.read().expect("sasl param").0 };
        if !sasl_wrap || buf.is_empty() {
            return decode_inner(buf, self.limits);
        }
        if self.has_decoded_data {
            let res = decode_inner(buf, self.limits);
            if res.is_ok() && buf.is_empty() {
                self.has_decoded_data = false;
            }
            return res;
        }
        if buf.len() < U32_SIZE {
            return Ok(None);
        }
        let sasl_len = u32::from_be_bytes(buf[0..U32_SIZE].try_into().unwrap());
        if sasl_len as usize > self.limits.maximum_frame {
            return Err(invalid());
        }
        if buf.len() - U32_SIZE < sasl_len as usize {
            return Ok(None);
        }
        buf.advance(U32_SIZE);
        let client_opt = &mut *self.client_ctx.lock().expect("client ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        let mut decoded = client_ctx.unwrap_iov(sasl_len as usize, buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("gss_unwrap error: {:#}", e))
        })?;
        let res = decode_inner(&mut decoded, self.limits);
        if res.is_ok() && !decoded.is_empty() && buf.is_empty() {
            buf.extend(decoded);
            self.has_decoded_data = true;
        }
        res
    }
}

#[cfg(not(feature = "gssapi"))]
#[inline]
fn maybe_wrap(
    _codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    write::encode_into(into, outstruct)?;
    Ok(())
}

#[cfg(feature = "gssapi")]
fn maybe_wrap(
    codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    let mut out_buf = BytesMut::new();
    write::encode_into(&mut out_buf, outstruct)?;
    let (sasl_wrap, sasl_send_max) = {
        let sasl_param = codec.sasl_param.read().expect("sasl param");
        (sasl_param.0, sasl_param.1)
    };
    if sasl_wrap {
        let client_opt = &mut *codec.client_ctx.lock().expect("client_ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        if sasl_send_max > 0 && out_buf.len() > sasl_send_max as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "buffer too large for GSSAPI: {} > {}",
                    out_buf.len(),
                    sasl_send_max
                ),
            ));
        }
        let sasl_buf = client_ctx.wrap(true, &out_buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("gss_wrap error: {:#}", e))
        })?;
        let sasl_len = (sasl_buf.len() as u32).to_be_bytes();
        into.extend(&sasl_len);
        into.extend(&*sasl_buf);
    } else {
        into.extend(&out_buf);
    }
    Ok(())
}

impl Encoder<(RequestId, Tag, MaybeControls)> for LdapCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: (RequestId, Tag, MaybeControls),
        into: &mut BytesMut,
    ) -> io::Result<()> {
        let (id, tag, controls) = msg;
        let outstruct = {
            let mut msg = vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                tag,
            ];
            if let Some(controls) = controls {
                msg.push(Tag::StructureTag(StructureTag {
                    id: 0,
                    class: TagClass::Context,
                    payload: PL::C(controls.into_iter().map(build_tag).collect()),
                }));
            }
            Tag::Sequence(Sequence {
                inner: msg,
                ..Default::default()
            })
            .into_structure()
        };
        maybe_wrap(self, outstruct, into)?;
        Ok(())
    }
}

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "LDAP allocation or frame limit exceeded",
    )
}
fn add(a: usize, b: usize) -> io::Result<usize> {
    a.checked_add(b).ok_or_else(too_large)
}
fn footprint(
    tag: &StructureTag,
    depth: usize,
    nodes: &mut usize,
    limits: CodecLimits,
) -> io::Result<(usize, usize)> {
    if depth > limits.maximum_depth {
        return Err(request_limit(RequestLimitKind::Depth, limits.maximum_depth).error(None));
    }
    if tag.id >= 31 {
        return Err(request_limit(RequestLimitKind::Tag, 30).error(usize::try_from(tag.id).ok()));
    }
    *nodes = nodes
        .checked_sub(1)
        .ok_or_else(|| request_limit(RequestLimitKind::Nodes, limits.maximum_nodes).error(None))?;
    let retained = request_limit(
        RequestLimitKind::RetainedAllocation,
        limits.maximum_allocation,
    );
    let frame = request_limit(RequestLimitKind::Frame, limits.maximum_frame);
    let (payload, memory) = match &tag.payload {
        PL::P(bytes) => (bytes.len(), bytes.capacity()),
        PL::C(children) => {
            let mut payload = 0;
            let mut memory =
                retained.mul(children.capacity(), std::mem::size_of::<StructureTag>())?;
            for child in children {
                let (wire, heap) = footprint(child, depth + 1, nodes, limits)?;
                payload = frame.add(payload, wire)?;
                memory = retained.add(memory, heap)?;
            }
            (payload, memory)
        }
    };
    if memory > limits.maximum_allocation {
        return Err(retained.error(Some(memory)));
    }
    Ok((frame.tlv(payload)?, memory))
}
pub(crate) fn request_allocation(
    operation: &StructureTag,
    controls: &[RawControl],
    limits: CodecLimits,
) -> io::Result<usize> {
    let mut nodes = limits.maximum_nodes;
    let (operation_wire, mut memory) = footprint(operation, 1, &mut nodes, limits)?;
    let allocation = request_limit(RequestLimitKind::TotalAllocation, limits.maximum_allocation);
    let frame = request_limit(RequestLimitKind::Frame, limits.maximum_frame);
    // Include the operation, envelope, request bookkeeping and temporary encoder nodes.
    memory = allocation.add(memory, 1024)?;
    let mut controls_wire = 0;
    for control in controls {
        let wire = frame.add(frame.tlv(control.ctype.len())?, 3)?;
        let wire = frame.add(
            wire,
            control.val.as_ref().map_or(Ok(0), |v| frame.tlv(v.len()))?,
        )?;
        controls_wire = frame.add(controls_wire, frame.tlv(wire)?)?;
        memory = allocation.add(
            memory,
            allocation.add(
                512,
                allocation.add(
                    control.ctype.capacity(),
                    control.val.as_ref().map_or(0, Vec::capacity),
                )?,
            )?,
        )?;
    }
    let wire = frame.tlv(frame.add(
        frame.add(6, operation_wire)?,
        if controls.is_empty() {
            0
        } else {
            frame.tlv(controls_wire)?
        },
    )?)?;
    if wire > limits.maximum_frame {
        return Err(frame.error(Some(wire)));
    }
    // BytesMut may grow geometrically, and framing/tree conversion coexist.
    memory = allocation.add(memory, allocation.mul(wire, 4)?)?;
    if memory > limits.maximum_allocation {
        return Err(allocation.error(Some(memory)));
    }
    Ok(memory)
}
impl RawResponse {
    pub(crate) fn allocation_bytes(&self) -> io::Result<usize> {
        let mut nodes = usize::MAX;
        let (_, heap) = footprint(
            &self.operation,
            1,
            &mut nodes,
            CodecLimits {
                maximum_allocation: usize::MAX,
                maximum_depth: 128,
                ..Default::default()
            },
        )
        // Response accounting retains its original allocation error; typed
        // request refusals belong to request admission only.
        .map_err(|_| too_large())?;
        let mut size = add(add(heap, self.raw.len())?, std::mem::size_of::<Self>())?;
        size = add(
            size,
            self.controls
                .capacity()
                .checked_mul(std::mem::size_of::<Control>())
                .ok_or_else(too_large)?,
        )?;
        for control in &self.controls {
            size = add(
                size,
                add(
                    control.1.ctype.capacity(),
                    control.1.val.as_ref().map_or(0, Vec::capacity),
                )?,
            )?;
        }
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_footprint_refusals_keep_the_allocation_error_and_cause() {
        let mut unsupported = crate::requests::unbind().into_structure();
        unsupported.id = 31;
        let mut deep = crate::requests::unbind().into_structure();
        for _ in 0..128 {
            deep = StructureTag {
                payload: PL::C(vec![deep]),
                ..crate::requests::unbind().into_structure()
            };
        }
        for operation in [unsupported, deep] {
            let response = RawResponse {
                id: 1,
                operation,
                controls: vec![],
                raw: Bytes::new(),
            };
            let error = response.allocation_bytes().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), "LDAP allocation or frame limit exceeded");
            assert_eq!(
                error.get_ref().unwrap().to_string(),
                "LDAP allocation or frame limit exceeded",
            );
        }
    }
}
