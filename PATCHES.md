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
- Shared operation/filter constructors used by both the upstream high-level
  methods and Runtime's binary DTO conversion. No second operation encoder or
  response-routing implementation is maintained by Runtime.

Verification covers the upstream library tests, the existing lber tests,
`runtime_codec` and `runtime_driver`, with default features and Runtime's
`--no-default-features` selection. IMAPipe separately exercises real isolated
OpenLDAP plus frozen-authentication, cancellation and public interpreter routes.
This patch does not establish complete LDAP authentication, OS TLS/mTLS or all
native-platform acceptance; those remain in IMAPipe's acceptance matrix.
