# Runtime-supplied transport and bounded LDAP driver

Base: upstream `inejge/ldap3` tag `v0.12.1`, commit
`1107b192bb12783d8727025a77aeec079612afad` (full upstream history retained). Branch: `boundless`.

The bounded raw handle uses the existing `LdapConnAsync` driver, codec and
identifier allocator. Runtime supplies an already authorized transport and owns
DNS, proxy policy, TLS, credentials, cancellation and task joining. Library
features used by Runtime disable all default socket/TLS selection features.
There is no reconnect, referral traversal, replay or implicit Unbind in this path.

Changes:

- `RawHandle::dispatch` reports exhausted ordinary response slots with a typed
  `OutstandingLimit` carrying `maximum_outstanding`, inside its `WouldBlock`
  error. A peer withholding final responses can otherwise retain unbounded
  correlation state. Request-byte exhaustion retains its separate byte-budget
  path; no-response controls still need no ordinary slot. Regression:
  `shared_capacity_survives_dropped_receipts_and_reverse_order_responses`
  checks the shared-clone refusal and admission after a confirmed result.
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
- Physical write receipts, per-dispatch status and memory reservation
  observations. The unused aggregate `RawHandle::outcome_unknown` observation
  and its otherwise unused completion-map status field were removed: only fork
  tests used it. `was_dispatched`, write receipts, `RawEvent::confirm`, identifier
  leases and permit accounting remain. Tests assert confirmation/admission via
  outstanding capacity, no-send receipts and per-dispatch status instead.
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
written or the final response was decoded. A retained terminal event still owns
its response bytes and identifier lease, but cannot keep an explicitly forgotten
search's outstanding slot. `Driver::forget` releases that slot independently of
the event's lifetime. Abandon, Forget and Unbind use the shared request-byte budget but no
ordinary response slot. Failed writes preserve their cause in the receipt.

Regression evidence on macOS arm64: the full-capacity and explicit-Abandon/Forget
wire-count cases fail on the preceding pin and pass here. `runtime_driver` also
checks no-send receipts after decoded completion, outstanding capacity retained
until confirmation, control-byte exhaustion, cleanup-write failure, late replies and
sibling progress. Three older fixture callers now explicitly confirm their
validated terminal result before expecting capacity or an idle transport, as the
raw API already requires. Library, codec and driver tests pass with
`--no-default-features`; the caller's adapter suite covers the 1024-slot contract.
`forgetting_a_decoded_search_releases_its_slot_while_the_event_is_retained`
fails with capacity exhaustion on the preceding pin and passes here, without a
second Abandon or a fabricated semantic confirmation.

After removing the aggregate observation, `cargo +1.97.0 test
--no-default-features --lib raw::tests` (1 test) and `cargo +1.97.0 test
--no-default-features --test runtime_driver` (16 tests) pass on macOS arm64.

## Rust 1.97 strict Clippy (Boundless #316)

The pinned `97a3f20adf4670e2d4ee7ff8ca5da9913aaa1d14` and the issue's
`cd34abf57bab8d1025f26cd6c25429dde95c356f` baseline both reproduce 20 errors
with Rust 1.97.0. Upstream HEAD is still the base release, `1107b192`; its
error conversion, unescaper and transaction iterator retain the same forms,
so there is no newer upstream lint repair to adopt.

- Fourteen `result_large_err` findings come from the 152-byte `OpSend`
  payload. Box only the fork's internal `LdapOp::Raw` payload at its sole
  construction point, `RawHandle::dispatch`. The public `LdapError` variants,
  `From<SendError<...>>`, failed request payload and error source stay intact.
  Raw Unbind still shuts down the writer and terminates after the write.
- Name the raw event's existing completion tuple with a private alias for
  `type_complexity`; its ownership and confirmation behavior stay the same.
- Use `io::Error::other` at the two `io_other_error` sites. Preserve the kind,
  display text and existing I/O cause rather than wrapping the original
  `LdapError` as a new cause. No mutex or poison handling changes.
- Replace the checked `Option` unwrap with `if let`, preserving borrowed
  unescaped strings and the `DecodingUTF8` result for invalid escapes.
- Iterate transaction tags with `for ... in tags.by_ref()`, keeping the
  post-loop rejection of trailing elements after the controls.
- Indent the TLS feature's documentation continuation under its list item.

No lint suppression is added. Preservation tests cover the closed-driver
send error and its retained request/source, queued-operation receipt and
permit release, I/O error kind/cause/display, message-ID exhaustion's kind
and text, unescape failures, and transaction responses with trailing elements.
Existing runtime driver tests exercise physical Unbind and cancellation.

All Cargo checks use the build-slot wrapper with `CARGO_INCREMENTAL=0`.
The fork's ignored lockfile is copied unchanged from the pinned clone for
both baseline worktrees. Verification on macOS arm64, Rust 1.97.0:

| Command | Before | After |
| --- | --- | --- |
| `cargo clippy --no-default-features --lib --tests --locked -- -D warnings` | Exit 101, 20 errors on both pins | Exit 0 |

`cargo test --workspace --no-default-features --lib --tests --locked` also
exits 0, including the preservation tests and the complete runtime codec/driver
and lber library suites. Formatting checks exit 0.

## Typed request validation (Boundless #374)

`protocol::request_allocation` is the shared admission check for
`LdapCodec::validate_request` and `RawHandle::dispatch`, before identifier or
permit acquisition. Its private `footprint` walk detects depth, unsupported tag,
node and retained-allocation limits; `request_allocation` detects frame and total
allocation limits. `RawResponse::allocation_bytes` shares the footprint count but
maps its refusals to the original allocation error and cause, so response
accounting preserves its error contract. Request admission returns `RequestLimit`
as the source of an ordinary `InvalidInput` I/O error, following `OutstandingLimit` and Tokio's codec error
source pattern. Checked arithmetic reports the corresponding limit with no
complete measurement on overflow. The check order and traversal stop points
are unchanged; validation never retries with relaxed limits or traverses again
to obtain a complete count.

Runtime maps this source once instead of reconstructing the codec's decision.
Stopped node/depth traversal has no complete `observed` count. When frame and
total allocation both exceed their limits, frame is reported because it is
checked first. These follow the owner's 2026-10-27 decision: both refusals ask
the caller to shrink the request, without changing the failure contract.

`runtime_codec` regressions `request_depth_refusal_stops_before_counting_the_tree`,
`request_tag_refusal_names_the_encoder_tag_bound`,
`request_node_refusal_has_no_complete_observed_count`,
`request_retained_allocation_refusal_measures_capacity_before_frame`,
`request_frame_refusal_precedes_total_allocation_and_keeps_its_measurement` and
`request_total_allocation_refusal_includes_encoder_and_bookkeeping` cover each
kind, its measurements, precedence and accepted frame/allocation thresholds.

Initial validation on macOS arm64, Rust 1.97.0, with `CARGO_INCREMENTAL=0` and
the machine's build-slot wrapper: `cargo test --no-default-features --test
runtime_codec --test runtime_driver --locked` exits 0 (10 codec and 16 driver
tests); `cargo clippy --no-default-features --lib --tests --locked -- -D
warnings` exits 0. The caller's LDAP module tests retain the pre-dispatch refusal
and unaffected outstanding-search coverage.

Review follow-up: `protocol::tests::response_footprint_refusals_keep_the_allocation_error_and_cause`
checks the response's ordinary `InvalidInput` allocation error and its cause for
unsupported tags and excessive depth. Request regressions continue to assert the
typed codec refusals; only the response accounting boundary restores its previous
error after the shared count stops.

Review validation on macOS arm64, Rust 1.97.0, through the build-slot wrapper:
`cargo test --no-default-features --lib --locked -- protocol::tests::` (1 test),
`cargo test --no-default-features --test runtime_codec --locked` (10 tests),
`cargo clippy --no-default-features --lib --tests --locked -- -D warnings` and
`cargo fmt --all --check` all exit 0.


## Restore upstream handle-drop, Unbind and AD Notice behavior (F2/F4/F12a)

Upstream 1107b192 `src/conn.rs:759-802` lets closed handle channels end its
unbiased loop and logs Unbind shutdown errors after the packet was flushed.
The bounded split-I/O loop retains its necessary write/delivery priority, but
now ends when the scrub channel closes instead of starving its other closed
channels. Unbind publishes its ordinary raw/high-level write completion after
flush, then performs upstream's best-effort shutdown with a logged error.
No new teardown error changes an already written receipt.

Upstream `src/protocol.rs:81-90` tolerates AD's misplaced responseName sibling
by ignoring it. The bounded decoder ports that workaround only for message ID
zero's known Notice-of-Disconnection OID, moving the existing parsed tag into
the ExtendedResponse so the caller can recognize the peer end. This minimal
difference preserves exact raw bytes and the fork's required strict controls
and allocation limits; ordinary trailing fields still use try_parse_controls.
Message-ID allocation/reuse is unchanged (F12b is design-only).

Regressions: `dropping_the_last_handle_ends_the_driver_and_transport`,
`an_unbind_flushed_before_shutdown_failure_is_written`, and
`ad_notice_response_name_is_normalized_without_changing_received_bytes`.
The existing malformed-controls tests continue to exercise strict decoding.

Validation on macOS arm64, Rust 1.97.0: workspace default tests and
`--lib --tests --no-default-features` pass; strict Clippy for library/test
workspace targets passes with default and no-default features; fmt passes.
The wider no-default example build cannot import the feature-gated LdapConn,
and strict all-targets Clippy also reports unchanged needless-question-mark
examples. Those existing example configurations were not repaired or suppressed.
