# Runtime-supplied transport and bounded LDAP driver

Base: upstream `inejge/ldap3` tag `v0.12.1`, commit
`1107b192bb12783d8727025a77aeec079612afad` (full upstream history retained). Branch: `codex/runtime-driver`.

The bounded raw handle uses the existing `LdapConnAsync` driver, codec and
identifier allocator. Runtime supplies an already authorized transport and owns
DNS, proxy policy, TLS, credentials, cancellation and task joining. Library
features used by Runtime disable all default socket/TLS selection features.
There is no reconnect, referral traversal, replay or implicit Unbind in this path.

Changes:

- Supplied asynchronous streams and explicit idle-stream recovery for STARTTLS.
  Buffered plaintext, queued requests and outstanding operations prevent recovery.
- Independent physical reads and writes in the existing connection driver.
  Blocked outgoing data cannot pause response parsing. Closing drops both halves.
- Raw response evidence with unknown numeric results, binary controls and exact
  frame bytes. Unknown controls are not discarded. Response kind and ID are
  correlated by the library; explicit Abandon preserves late replies.
- Shared limits for outstanding/queued requests, retained request allocations,
  response items and retained response bytes, across handle clones. Dropping a
  dispatch receipt does not cancel or release a queued operation. A retained
  delivered response continues to consume its byte permit. Overflow terminates
  explicitly rather than blocking or silently losing delivery.
- Physical write receipts, dispatch-status observation, uncertain-outcome state
  after driver termination and memory reservation observations.
- The existing lber parser checks frame, depth, node and allocation limits before
  allocation and validates envelope/controls without panic. Incomplete inner BER
  inside a complete frame fails immediately. The same encoder writes directly to
  its destination instead of making a nested copy for every enclosing sequence;
  outgoing primitive buffers and driver write buffers are erased on release.
- `RawHandle::forget` abandons an outstanding search and, once its Abandon is
  written, frees the search's identifier and outstanding slot, as ldapts
  forgets an abandoned message. RFC 4511 section 4.11 has the server send
  nothing more for it, so an Abandon through `submit`, which keeps the
  operation for a late reply, held its slot for the connection's life. A
  response for an identifier issued and no longer outstanding is discarded; one
  never issued still ends the driver. Only a search is forgotten, since an
  update's outcome would be lost. Regression:
  `forgetting_a_search_frees_its_slot_and_discards_what_still_arrives`.
- Shared operation/filter constructors used by both the upstream high-level
  methods and Runtime's binary DTO conversion. No second operation encoder or
  response-routing implementation is maintained by Runtime.

Verification covers the upstream library tests, the existing lber tests,
`runtime_codec` and `runtime_driver`, with default features and Runtime's
`--no-default-features` selection. IMAPipe separately exercises real isolated
OpenLDAP plus frozen-authentication, cancellation and public interpreter routes.
This patch does not establish complete LDAP authentication, OS TLS/mTLS or all
native-platform acceptance; those remain in IMAPipe's acceptance matrix.

## No-response control admission and search cleanup

`Driver::register` is the sole write-admission point: a completed request or an
already flushed Abandon suppresses another packet. `RawWrite` distinguishes a
physical write from no send; decoding a final response still does not confirm its
semantic result. Only the caller's `RawEvent::confirm` does that. Explicit Abandon
retains late replies and the original outstanding slot. Forget removes the route
and slot after the first successful Abandon, or immediately if it was already
written. Abandon, Forget and Unbind use the shared request-byte budget but no
ordinary response slot. Failed writes preserve their cause in the receipt.

Regression evidence on macOS arm64: the full-capacity and explicit-Abandon/Forget
wire-count cases fail on the preceding pin and pass here. `runtime_driver` also
checks no-send receipts after decoded completion, retained uncertainty until
confirmation, control-byte exhaustion, cleanup-write failure, late replies and
sibling progress. Three older fixture callers now explicitly confirm their
validated terminal result before expecting capacity or an idle transport, as the
raw API already requires. Library, codec and driver tests pass with
`--no-default-features`; the caller's adapter suite covers the 1024-slot contract.
