//! Bounded raw operations on the same connection driver used by `Ldap`.
//! The caller owns transport security, authentication, deadlines and task lifetime.
use crate::{CodecLimits, Ldap, RawResponse, RequestId, protocol::LdapOp};
use lber::{
    common::TagClass,
    structure::{PL, StructureTag},
    structures::Tag,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

#[derive(Clone, Copy, Debug)]
pub struct DriverLimits {
    pub codec: CodecLimits,
    pub maximum_outstanding: usize,
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_response_items: usize,
}
impl DriverLimits {
    pub fn validate(self) -> io::Result<Self> {
        crate::LdapCodec::new(self.codec)?;
        for n in [
            self.maximum_outstanding,
            self.maximum_request_bytes,
            self.maximum_response_bytes,
            self.maximum_response_items,
        ] {
            if n == 0 || n > u32::MAX as usize || n > Semaphore::MAX_PERMITS {
                return Err(input("invalid LDAP driver limits"));
            }
        }
        Ok(self)
    }
}
fn input(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text)
}
fn full() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "LDAP capacity exhausted")
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "LDAP driver closed")
}

/// A command accepted into the bounded library queue. A dropped receipt does
/// not undo or cancel dispatch. `written()` establishes physical flush only.
#[derive(Clone)]
pub struct DispatchStatus(Arc<AtomicBool>);
impl DispatchStatus {
    pub fn was_dispatched(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
pub struct RawDispatch {
    pub id: RequestId,
    written: oneshot::Receiver<io::Result<()>>,
    dispatched: Arc<AtomicBool>,
}
impl RawDispatch {
    pub async fn written(&mut self) -> io::Result<()> {
        (&mut self.written).await.map_err(|_| closed())?
    }
    pub fn was_dispatched(&self) -> bool {
        self.dispatched.load(Ordering::Acquire)
    }
    pub fn status(&self) -> DispatchStatus {
        DispatchStatus(self.dispatched.clone())
    }
}
/// Response capacity remains charged until this event is dropped, even after
/// receiving it from the queue. No response or operation is silently discarded.
pub struct RawEvent {
    pub response: RawResponse,
    pub complete: bool,
    pub abandon_requested: bool,
    _memory: OwnedSemaphorePermit,
}
pub struct RawResponses(mpsc::Receiver<RawEvent>);
impl RawResponses {
    pub async fn recv(&mut self) -> Option<RawEvent> {
        self.0.recv().await
    }
}

pub struct RawHandle {
    ldap: Ldap,
    limits: DriverLimits,
    outstanding: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    responses: Arc<Semaphore>,
    storage: Arc<AtomicUsize>,
    uncertain: Arc<AtomicBool>,
}
impl Clone for RawHandle {
    fn clone(&self) -> Self {
        Self {
            ldap: self.ldap.clone(),
            limits: self.limits,
            outstanding: self.outstanding.clone(),
            requests: self.requests.clone(),
            responses: self.responses.clone(),
            storage: self.storage.clone(),
            uncertain: self.uncertain.clone(),
        }
    }
}
// No Debug output includes request trees, credentials or response data.
pub(crate) struct Lease {
    id: RequestId,
    ids: Arc<Mutex<(RequestId, HashSet<RequestId>)>>,
    _slot: OwnedSemaphorePermit,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut ids) = self.ids.lock() {
            ids.1.remove(&self.id);
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Reply(u64),
    Search,
    Abandon(RequestId),
    Unbind,
}
impl Kind {
    fn from_tag(tag: &StructureTag) -> io::Result<Self> {
        if tag.class != TagClass::Application {
            return Err(input("LDAP operation must be application-tagged"));
        }
        Ok(match tag.id {
            0 => Self::Reply(1),
            3 => Self::Search,
            6 => Self::Reply(7),
            8 => Self::Reply(9),
            10 => Self::Reply(11),
            12 => Self::Reply(13),
            14 => Self::Reply(15),
            23 => Self::Reply(24),
            2 => {
                if !matches!(&tag.payload,PL::P(v) if v.is_empty()) {
                    return Err(input("invalid LDAP Unbind"));
                }
                Self::Unbind
            }
            16 => {
                let PL::P(v) = &tag.payload else {
                    return Err(input("invalid LDAP Abandon"));
                };
                if v.is_empty() || v.len() > 4 || v[0] & 128 != 0 {
                    return Err(input("invalid LDAP Abandon identifier"));
                }
                let id = v.iter().fold(0i32, |n, b| (n << 8) | i32::from(*b));
                if id <= 0 {
                    return Err(input("invalid LDAP Abandon identifier"));
                }
                Self::Abandon(id)
            }
            _ => return Err(input("unsupported LDAP request operation")),
        })
    }
    fn response(self, tag: u64) -> io::Result<bool> {
        if tag == 25 {
            return Ok(false);
        }
        match self {
            Self::Reply(expected) if expected == tag => Ok(true),
            Self::Search if matches!(tag, 4 | 5 | 19) => Ok(tag == 5),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LDAP response does not match its request",
            )),
        }
    }
}
pub(crate) struct RawOperation {
    pub kind: Kind,
    lease: Arc<Lease>,
    _memory: OwnedSemaphorePermit,
    written: Option<oneshot::Sender<io::Result<()>>>,
    dispatched: Arc<AtomicBool>,
}
impl std::fmt::Debug for RawOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawOperation")
    }
}
struct Pending {
    kind: Kind,
    abandoned: bool,
    _lease: Arc<Lease>,
}
pub(crate) struct Driver {
    pending: HashMap<RequestId, Pending>,
    storage: Arc<AtomicUsize>,
    output: mpsc::Sender<RawEvent>,
    responses: Arc<Semaphore>,
    uncertain: Arc<AtomicBool>,
}
impl Driver {
    pub fn new(ldap: Ldap, limits: DriverLimits) -> (Self, RawHandle, RawResponses) {
        let (output, receiver) = mpsc::channel(limits.maximum_response_items);
        let uncertain = Arc::new(AtomicBool::new(false));
        let responses = Arc::new(Semaphore::new(limits.maximum_response_bytes));
        let storage = Arc::new(AtomicUsize::new(0));
        (
            Self {
                pending: HashMap::new(),
                output,
                responses: responses.clone(),
                storage: storage.clone(),
                uncertain: uncertain.clone(),
            },
            RawHandle {
                ldap,
                limits,
                outstanding: Arc::new(Semaphore::new(limits.maximum_outstanding)),
                requests: Arc::new(Semaphore::new(limits.maximum_request_bytes)),
                responses,
                storage,
                uncertain,
            },
            RawResponses(receiver),
        )
    }
    pub fn observe_buffers(&self, bytes: usize) {
        self.storage.store(
            bytes.saturating_add(
                self.pending
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(RequestId, Pending)>() + 32),
            ),
            Ordering::Release,
        );
    }
    pub fn register(&mut self, id: RequestId, op: &RawOperation) -> io::Result<()> {
        match op.kind {
            Kind::Abandon(target) => {
                let pending = self
                    .pending
                    .get_mut(&target)
                    .ok_or_else(|| input("LDAP abandon target is not outstanding"))?;
                pending.abandoned = true;
            }
            Kind::Unbind => {}
            kind => {
                self.pending.insert(
                    id,
                    Pending {
                        kind,
                        abandoned: false,
                        _lease: op.lease.clone(),
                    },
                );
            }
        }
        Ok(())
    }
    pub fn rejected(op: &mut RawOperation, error: io::Error) {
        if let Some(reply) = op.written.take() {
            let _ = reply.send(Err(error));
        }
    }
    pub fn started(op: &RawOperation) {
        op.dispatched.store(true, Ordering::Release);
    }
    pub fn completed(op: &mut RawOperation) {
        if let Some(reply) = op.written.take() {
            let _ = reply.send(Ok(()));
        }
    }
    pub fn response(&mut self, response: RawResponse) -> io::Result<bool> {
        let (complete, abandon_requested) = if response.id == 0 {
            if response.operation.id != 24 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid LDAP unsolicited response",
                ));
            }
            (false, false)
        } else {
            let pending = self.pending.get(&response.id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LDAP response has no outstanding message ID",
                )
            })?;
            (
                pending.kind.response(response.operation.id)?,
                pending.abandoned,
            )
        };
        let size = response.allocation_bytes()?;
        let memory = self
            .responses
            .clone()
            .try_acquire_many_owned(u32::try_from(size).map_err(|_| full())?)
            .map_err(|_| full())?;
        if complete {
            self.pending.remove(&response.id);
        }
        self.output
            .try_send(RawEvent {
                response,
                complete,
                abandon_requested,
                _memory: memory,
            })
            .map_err(|_| full())?;
        Ok(complete)
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            self.uncertain.store(true, Ordering::Release);
        }
    }
}
impl RawHandle {
    /// Resident buffers and reserved request/response allocation, including all clones.
    pub fn memory_bytes(&self) -> usize {
        let ids = self
            .ldap
            .msgmap
            .lock()
            .map_or(0, |ids| ids.1.capacity().saturating_mul(16));
        self.limits
            .maximum_request_bytes
            .saturating_sub(self.requests.available_permits())
            .saturating_add(
                self.limits
                    .maximum_response_bytes
                    .saturating_sub(self.responses.available_permits()),
            )
            .saturating_add(self.storage.load(Ordering::Acquire))
            .saturating_add(ids)
    }
    /// A driver ended while a dispatched operation lacked a terminal response.
    pub fn outcome_unknown(&self) -> bool {
        self.uncertain.load(Ordering::Acquire)
    }
    /// Queue one operation without waiting for a response. All in-flight and
    /// queued operations share limits, including calls made through clones.
    /// Caller cancellation after acceptance does not assert remote rollback.
    pub fn submit(
        &mut self,
        operation: StructureTag,
        controls: Vec<crate::controls::RawControl>,
    ) -> io::Result<RawDispatch> {
        if self.ldap.tx.is_closed() {
            return Err(closed());
        }
        let kind = Kind::from_tag(&operation)?;
        let size = crate::protocol::request_allocation(&operation, &controls, self.limits.codec)?;
        let memory = self
            .requests
            .clone()
            .try_acquire_many_owned(u32::try_from(size).map_err(|_| full())?)
            .map_err(|_| full())?;
        let slot = self
            .outstanding
            .clone()
            .try_acquire_owned()
            .map_err(|_| full())?;
        let id = self.ldap.next_msgid()?;
        let lease = Arc::new(Lease {
            id,
            ids: self.ldap.msgmap.clone(),
            _slot: slot,
        });
        let (written, receipt) = oneshot::channel();
        let dispatched = Arc::new(AtomicBool::new(false));
        let raw = RawOperation {
            kind,
            lease,
            _memory: memory,
            written: Some(written),
            dispatched: dispatched.clone(),
        };
        let (reply, _) = oneshot::channel();
        self.ldap
            .tx
            .send((
                id,
                LdapOp::Raw(raw),
                Tag::StructureTag(operation),
                Some(controls),
                reply,
            ))
            .map_err(|_| closed())?;
        Ok(RawDispatch {
            id,
            written: receipt,
            dispatched,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn message_ids_never_alias_an_old_dispatch_after_exhaustion() {
        use crate::asn1::ASNTag;
        let (stream, _peer) = tokio::io::duplex(128);
        let limits = DriverLimits {
            codec: CodecLimits::default(),
            maximum_outstanding: 2,
            maximum_request_bytes: 65536,
            maximum_response_bytes: 65536,
            maximum_response_items: 2,
        };
        let (_conn, mut handle, _events) =
            crate::LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
        handle.ldap.msgmap.lock().unwrap().0 = i32::MAX - 1;
        assert_eq!(
            handle
                .submit(
                    crate::requests::delete(b"dc=x".to_vec()).into_structure(),
                    vec![]
                )
                .unwrap()
                .id,
            i32::MAX
        );
        assert!(
            handle
                .submit(
                    crate::requests::delete(b"dc=x".to_vec()).into_structure(),
                    vec![]
                )
                .is_err()
        );
    }
}
