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
/// The peer has not completed enough requests to admit another response owner.
/// Shared by every clone of a bounded raw handle; no-response controls use no slot.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("LDAP outstanding request capacity exhausted (maximum {maximum})")]
pub struct OutstandingLimit {
    pub maximum: usize,
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "LDAP driver closed")
}

/// Whether admission to the physical writer still required a packet.
/// `NoSend` is not a write or a peer acknowledgement. A completion may still
/// await the caller's semantic validation through `RawEvent::confirm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawWrite {
    Written,
    NoSend,
}

/// A command accepted into the bounded library queue. A dropped receipt does
/// not undo or cancel dispatch. Only `RawWrite::Written` establishes a physical
/// flush; `RawWrite::NoSend` reports admission without transmission.
#[derive(Clone)]
pub struct DispatchStatus(Arc<AtomicBool>);
impl DispatchStatus {
    pub fn was_dispatched(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
pub struct RawDispatch {
    pub id: RequestId,
    written: oneshot::Receiver<io::Result<RawWrite>>,
    dispatched: Arc<AtomicBool>,
}
impl RawDispatch {
    pub async fn written(&mut self) -> io::Result<RawWrite> {
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
struct Unconfirmed {
    kind: Kind,
    _lease: Arc<Lease>,
}
type Completion = (RequestId, Arc<Mutex<Tracking>>, Arc<Lease>);
pub struct RawEvent {
    pub response: RawResponse,
    pub complete: bool,
    pub abandon_requested: bool,
    _memory: OwnedSemaphorePermit,
    completion: Option<Completion>,
}
impl RawEvent {
    /// Confirm a fully validated terminal result. Dropping an unconfirmed
    /// terminal event retains uncertainty and the message identifier lease.
    pub fn confirm(&mut self) {
        if let Some((id, tracking, _lease)) = self.completion.take() {
            tracking
                .lock()
                .expect("LDAP tracking")
                .unconfirmed
                .remove(&id);
        }
    }
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
    tracking: Arc<Mutex<Tracking>>,
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
            tracking: self.tracking.clone(),
        }
    }
}
// No Debug output includes request trees, credentials or response data.
pub(crate) struct Lease {
    id: RequestId,
    ids: Arc<Mutex<(RequestId, HashSet<RequestId>)>>,
    slot: Mutex<Option<OwnedSemaphorePermit>>,
}
impl Lease {
    fn release_slot(&self) {
        self.slot.lock().expect("LDAP outstanding slot").take();
    }
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
    /// An Abandon after which the search it names is forgotten.
    Forget(RequestId),
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
    written: Option<oneshot::Sender<io::Result<RawWrite>>>,
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
    complete: bool,
    registered: bool,
    _lease: Arc<Lease>,
}
#[derive(Default)]
struct Tracking {
    pending: HashMap<RequestId, Pending>,
    unconfirmed: HashMap<RequestId, Unconfirmed>,
}
impl Tracking {
    // Every local retirement releases both the route and its ordinary slot.
    // A retained event or queued writer may still hold the identifier lease.
    fn forget(&mut self, target: RequestId) {
        if let Some(pending) = self.pending.remove(&target) {
            pending._lease.release_slot();
        }
        if let Some(unconfirmed) = self.unconfirmed.remove(&target) {
            unconfirmed._lease.release_slot();
        }
    }
}
/// A response the caller no longer routes: one for a search it forgot locally
/// or after that search's Abandon was written. RFC 4511 section 4.11 has the server
/// send nothing more for an abandoned operation, but one already on its way
/// still arrives; ldapts and the upstream driver discard it too.
fn discarded() -> (bool, usize, Delivery) {
    (false, 0, Box::pin(async { Ok(None) }))
}
pub(crate) type Delivery =
    std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Option<RequestId>>> + Send>>;

pub(crate) struct Driver {
    maximum_response_bytes: usize,
    storage: Arc<AtomicUsize>,
    output: mpsc::Sender<RawEvent>,
    responses: Arc<Semaphore>,
    uncertain: Arc<AtomicBool>,
    tracking: Arc<Mutex<Tracking>>,
    /// The identifiers issued so far, the highest first.
    ids: Arc<Mutex<(RequestId, HashSet<RequestId>)>>,
}
impl Driver {
    pub fn new(ldap: Ldap, limits: DriverLimits) -> (Self, RawHandle, RawResponses) {
        let (output, receiver) = mpsc::channel(limits.maximum_response_items);
        let uncertain = Arc::new(AtomicBool::new(false));
        let tracking = Arc::new(Mutex::new(Tracking::default()));
        let responses = Arc::new(Semaphore::new(limits.maximum_response_bytes));
        let storage = Arc::new(AtomicUsize::new(0));
        (
            Self {
                maximum_response_bytes: limits.maximum_response_bytes,
                output,
                responses: responses.clone(),
                storage: storage.clone(),
                uncertain: uncertain.clone(),
                tracking: tracking.clone(),
                ids: ldap.msgmap.clone(),
            },
            RawHandle {
                ldap,
                limits,
                outstanding: Arc::new(Semaphore::new(limits.maximum_outstanding)),
                requests: Arc::new(Semaphore::new(limits.maximum_request_bytes)),
                responses,
                storage,
                uncertain,
                tracking,
            },
            RawResponses(receiver),
        )
    }
    pub fn observe_buffers(&self, bytes: usize) {
        self.storage.store(bytes, Ordering::Release);
    }
    /// One admission point for every raw write, after earlier writes finished.
    /// Replies already decoded and Abandons already flushed need no packet.
    pub fn register(&mut self, id: RequestId, op: &mut RawOperation) -> io::Result<bool> {
        let no_send = {
            let mut tracking = self.tracking.lock().expect("LDAP tracking");
            match op.kind {
                Kind::Abandon(target) | Kind::Forget(target) => {
                    let forget = matches!(op.kind, Kind::Forget(_));
                    let pending = tracking.pending.get(&target);
                    if let Some(pending) = pending {
                        if forget && !matches!(pending.kind, Kind::Search) {
                            return Err(input("only a search is forgotten"));
                        }
                    } else if target > self.ids.lock().expect("LDAP identifiers").0 {
                        return Err(input("LDAP abandon target is not outstanding"));
                    }
                    if pending.is_none_or(|pending| pending.abandoned || pending.complete) {
                        if forget {
                            tracking.forget(target);
                        }
                        true
                    } else {
                        false
                    }
                }
                Kind::Unbind => false,
                kind => {
                    // Submission installed the route before queue acceptance.
                    // A local forget may already have removed it. Dispatch is
                    // still owned, but must never recreate forgotten tracking.
                    if let Some(pending) = tracking.pending.get_mut(&id) {
                        pending.registered = true;
                        tracking.unconfirmed.insert(
                            id,
                            Unconfirmed {
                                kind,
                                _lease: op.lease.clone(),
                            },
                        );
                    }
                    false
                }
            }
        };
        // The callback may call the handle again; never hold tracking here.
        if no_send && let Some(reply) = op.written.take() {
            let _ = reply.send(Ok(RawWrite::NoSend));
        }
        Ok(!no_send)
    }
    pub fn rejected(op: &mut RawOperation, error: io::Error) {
        if let Some(reply) = op.written.take() {
            let _ = reply.send(Err(error));
        }
    }
    pub fn started(op: &RawOperation) {
        op.dispatched.store(true, Ordering::Release);
    }
    /// `op` was written. A forgotten search's Abandon frees its tracking.
    pub fn completed(&mut self, op: &mut RawOperation) {
        {
            let mut tracking = self.tracking.lock().expect("LDAP tracking");
            match op.kind {
                Kind::Forget(target) => tracking.forget(target),
                Kind::Abandon(target) => {
                    if let Some(pending) = tracking.pending.get_mut(&target) {
                        pending.abandoned = true;
                    }
                }
                _ => {}
            }
        }
        if let Some(reply) = op.written.take() {
            let _ = reply.send(Ok(RawWrite::Written));
        }
    }
    pub fn response_delivered(&mut self, id: RequestId) {
        self.tracking
            .lock()
            .expect("LDAP tracking")
            .pending
            .remove(&id);
    }
    pub fn response(&mut self, response: RawResponse) -> io::Result<(bool, usize, Delivery)> {
        let mut tracking = self.tracking.lock().expect("LDAP tracking");
        let (complete, abandon_requested) = if response.id == 0 {
            if response.operation.id != 24 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid LDAP unsolicited response",
                ));
            }
            (false, false)
        } else {
            let Some(pending) = tracking.pending.get_mut(&response.id) else {
                // An identifier issued and no longer outstanding is a
                // forgotten search's; one never issued is the server's error.
                let issued = self.ids.lock().map_or(0, |ids| ids.0);
                if response.id > 0 && response.id <= issued {
                    return Ok(discarded());
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LDAP response has no outstanding message ID",
                ));
            };
            if !pending.registered {
                // As before, an issued id has no response route until the
                // writer admits it. Queued tracking is only for local forget.
                return Ok(discarded());
            }
            let complete = pending.kind.response(response.operation.id)?;
            pending.complete = complete;
            (complete, pending.abandoned)
        };
        let size = response.allocation_bytes()?;
        if size > self.maximum_response_bytes {
            return Err(full());
        }
        let bytes = u32::try_from(size).map_err(|_| full())?;
        let responses = self.responses.clone();
        let output = self.output.clone();
        let id = response.id;
        let completion = if complete {
            tracking
                .pending
                .get(&id)
                .map(|pending| (id, self.tracking.clone(), pending._lease.clone()))
        } else {
            None
        };
        drop(tracking);
        // One decoded response waits outside the queue. The connection driver
        // stops reading further BER frames while this future waits, but keeps
        // its independent writer (including Abandon and Unbind) running.
        let delivery = Box::pin(async move {
            let slot = output.reserve().await.map_err(|_| closed())?;
            let memory = responses
                .acquire_many_owned(bytes)
                .await
                .map_err(|_| closed())?;
            slot.send(RawEvent {
                response,
                complete,
                abandon_requested,
                _memory: memory,
                completion,
            });
            Ok(complete.then_some(id))
        });
        Ok((complete, size, delivery))
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        let mut tracking = self.tracking.lock().expect("LDAP tracking");
        if tracking.pending.values().any(|pending| pending.registered) {
            self.uncertain.store(true, Ordering::Release);
        }
        tracking.pending.clear();
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
        let tracking = self.tracking.lock().expect("LDAP tracking");
        let structural = tracking
            .unconfirmed
            .capacity()
            .saturating_mul(std::mem::size_of::<(RequestId, Unconfirmed)>() + 32)
            .saturating_add(
                tracking
                    .pending
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(RequestId, Pending)>() + 32),
            );
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
            .saturating_add(structural)
    }
    /// Queue one operation without waiting for a response. All in-flight and
    /// queued operations share limits, including calls made through clones.
    /// Caller cancellation after acceptance does not assert remote rollback.
    pub fn submit(
        &mut self,
        operation: StructureTag,
        controls: Vec<crate::controls::RawControl>,
    ) -> io::Result<RawDispatch> {
        let kind = Kind::from_tag(&operation)?;
        self.dispatch(kind, operation, controls)
    }
    /// Forget a search's local correlation and outstanding slot immediately.
    /// This sends no packet and reserves no request bytes. It does not undo a
    /// queued or in-flight write. Existing response events keep their bytes and
    /// identifier leases; subsequent responses for the search are discarded.
    ///
    /// When notifying the peer, use `forget()` and await its write first, then
    /// call this even if notification admission or the write failed. Calling
    /// this first makes a later `forget()` a no-send. An already retired search
    /// is a no-op; an unissued id or a tracked non-search is rejected.
    pub fn forget_local(&mut self, search: RequestId) -> io::Result<()> {
        let mut tracking = self.tracking.lock().expect("LDAP tracking");
        let issued = self.ldap.msgmap.lock().expect("LDAP identifiers").0;
        if search <= 0 || search > issued {
            return Err(input("LDAP forget target was not issued"));
        }
        let kind = tracking
            .pending
            .get(&search)
            .map(|pending| pending.kind)
            .or_else(|| {
                tracking
                    .unconfirmed
                    .get(&search)
                    .map(|pending| pending.kind)
            });
        if kind.is_some_and(|kind| !matches!(kind, Kind::Search)) {
            return Err(input("only a search is forgotten"));
        }
        tracking.forget(search);
        Ok(())
    }
    /// Abandons the outstanding search `search` and forgets it once the
    /// Abandon is written, as ldapts forgets an abandoned message: its
    /// identifier and outstanding slot are free again, and a response for it
    /// that still arrives is discarded. An Abandon through `submit` instead
    /// keeps the operation, so a late reply still reaches its caller.
    pub fn forget(&mut self, search: RequestId) -> io::Result<RawDispatch> {
        let operation = crate::asn1::ASNTag::into_structure(crate::requests::abandon(search));
        Kind::from_tag(&operation)?;
        self.dispatch(Kind::Forget(search), operation, vec![])
    }
    fn dispatch(
        &mut self,
        kind: Kind,
        operation: StructureTag,
        controls: Vec<crate::controls::RawControl>,
    ) -> io::Result<RawDispatch> {
        if self.ldap.tx.is_closed() {
            return Err(closed());
        }
        let size = crate::protocol::request_allocation(&operation, &controls, self.limits.codec)?;
        let memory = self
            .requests
            .clone()
            .try_acquire_many_owned(u32::try_from(size).map_err(|_| full())?)
            .map_err(|_| full())?;
        // Controls expect no response and must work even at the ordinary
        // outstanding limit. Their allocations still share the byte budget.
        let slot = if matches!(kind, Kind::Reply(_) | Kind::Search) {
            Some(self.outstanding.clone().try_acquire_owned().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    OutstandingLimit {
                        maximum: self.limits.maximum_outstanding,
                    },
                )
            })?)
        } else {
            None
        };
        let id = self.ldap.next_msgid()?;
        let lease = Arc::new(Lease {
            id,
            ids: self.ldap.msgmap.clone(),
            slot: Mutex::new(slot),
        });
        if matches!(kind, Kind::Reply(_) | Kind::Search) {
            self.tracking.lock().expect("LDAP tracking").pending.insert(
                id,
                Pending {
                    kind,
                    abandoned: false,
                    complete: false,
                    registered: false,
                    _lease: lease.clone(),
                },
            );
        }
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
        if self
            .ldap
            .tx
            .send((
                id,
                LdapOp::Raw(Box::new(raw)),
                Tag::StructureTag(operation),
                Some(controls),
                reply,
            ))
            .is_err()
        {
            self.tracking.lock().expect("LDAP tracking").forget(id);
            return Err(closed());
        }
        Ok(RawDispatch { id, written: receipt, dispatched })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_forget_needs_no_request_bytes_or_driver_progress() {
        let (stream, _peer) = tokio::io::duplex(128);
        let limits = DriverLimits {
            codec: CodecLimits::default(),
            maximum_outstanding: 1,
            maximum_request_bytes: 65536,
            maximum_response_bytes: 65536,
            maximum_response_items: 1,
        };
        let (_conn, mut handle, _events) =
            crate::LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
        let search = handle
            .submit(
                StructureTag {
                    class: TagClass::Application,
                    id: 3,
                    payload: PL::C(vec![]),
                },
                vec![],
            )
            .unwrap();
        let held = handle
            .requests
            .clone()
            .try_acquire_many_owned(handle.requests.available_permits() as u32)
            .unwrap();
        assert_eq!(
            handle.forget(search.id).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        handle.forget_local(search.id).unwrap();
        assert_eq!(handle.outstanding.available_permits(), 1);
        assert_eq!(handle.requests.available_permits(), 0);
        drop(held);
        handle
            .submit(
                StructureTag {
                    class: TagClass::Application,
                    id: 10,
                    payload: PL::P(b"dc=x".to_vec()),
                },
                vec![],
            )
            .unwrap();
    }


    #[tokio::test]
    async fn dropping_a_queued_operation_keeps_its_receipt_error_and_releases_capacity() {
        use crate::asn1::ASNTag;
        let (stream, _peer) = tokio::io::duplex(128);
        let limits = DriverLimits {
            codec: CodecLimits::default(),
            maximum_outstanding: 2,
            maximum_request_bytes: 65536,
            maximum_response_bytes: 65536,
            maximum_response_items: 2,
        };
        let (conn, mut handle, _events) =
            crate::LdapConnAsync::from_stream_bounded(stream, limits).unwrap();
        let mut dispatch = handle
            .submit(
                crate::requests::delete(b"dc=x".to_vec()).into_structure(),
                vec![],
            )
            .unwrap();
        assert_eq!(handle.outstanding.available_permits(), 1);
        assert!(handle.requests.available_permits() < limits.maximum_request_bytes);
        drop(conn);
        let error = dispatch.written().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "LDAP driver closed");
        assert!(!dispatch.was_dispatched());
        assert_eq!(
            handle.outstanding.available_permits(),
            limits.maximum_outstanding
        );
        assert_eq!(
            handle.requests.available_permits(),
            limits.maximum_request_bytes
        );
        assert!(handle.ldap.msgmap.lock().unwrap().1.is_empty());
    }

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
        let error = handle
            .submit(
                crate::requests::delete(b"dc=x".to_vec()).into_structure(),
                vec![],
            )
            .err()
            .expect("exhausted message identifiers");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "LDAP message ID space exhausted");
    }
}
