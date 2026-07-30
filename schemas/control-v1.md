# quicperf endpoint control protocol v1

The endpoint control channel is an inherited bidirectional Unix
`SOCK_SEQPACKET` socket. Coordinator and endpoint state, capabilities, timing,
progress, and results are authoritative only on this channel. Stdout and stderr
are bounded human diagnostics and are never parsed.

The normative machine-readable registry is
[`control-v1-fields.json`](control-v1-fields.json). Python and C++ constants are
checked against it and share byte-exact golden vectors.

## Packet encoding

All integers use network byte order. Every packet begins with this 24-byte
header:

```text
u32 magic          = 0x51504332
u16 version        = 1
u16 message_type
u32 payload_length
u32 flags
u64 sequence
```

The complete datagram is at most 65,536 bytes. Each sender's sequence starts at
one and increments exactly once per packet. Zero, a gap, a duplicate, or a
reordered sequence is a protocol error. `payload_length` must exactly equal the
remaining packet bytes; truncation and trailing data are rejected.

Payload fields are TLVs:

```text
u16 field_id
u8  wire_type
u8  reserved = 0
u32 byte_length
u8  value[byte_length]
```

Wire types are `1=u64`, `2=i64`, `3=UTF-8`, `4=bytes`, and `5=boolean`.
Integers are exactly eight bytes. A boolean is exactly one byte, zero or one.
UTF-8 values are nonempty, strictly encoded, and NUL-free. Floating point is
forbidden; scaled integers and raw numerators/denominators carry measurements.

Unknown field IDs below `0x8000`, duplicate fields, missing required fields,
wrong wire types, invalid encodings, a nonzero reserved byte, malformed lengths,
and unexpected fields reject the packet. Unknown optional IDs at or above
`0x8000` may be skipped after validating their envelope. `trial_id` and
`cell_id` are exactly 32 bytes. Packets carrying a trial identity are rejected
unless it matches the active trial.

## Messages

| ID | Message | Purpose |
|---:|---|---|
| 1 | `HELLO` | Attest endpoint role, build identity, and control version. |
| 2 | `CAPABILITIES` | Attest library, build, roles, backends, scenarios, protocol and effective features. |
| 3 | `CONFIG` | Select the frozen trial/cell and complete canonical configuration. |
| 4 | `BOUND` | Server reports the supervisor-reserved UDP port. |
| 5 | `READY` | Endpoint reports PID, effective backend, and raw-clock readiness. |
| 6 | `ARM` | Carry common warmup, measurement, end, and trace raw-clock epochs. |
| 7 | `ARMED` | Acknowledge the common barrier before warmup. |
| 8 | `MEASUREMENT_STARTED` | Report the observed raw start. |
| 9 | `PROGRESS` | Report indexed validated units or an explicit causal block. |
| 10 | `MEASUREMENT_STOPPED` | Report the observed raw stop. |
| 11 | `COMPLETION_ACK` | Carry reconciled peer counters outside the numerator. |
| 12 | `RESULT` | Carry the complete strict result object. |
| 13 | `UNSUPPORTED` | Report a declared capability gap for this planned trial. |
| 14 | `ERROR` | Report a structured protocol/adapter fatal error. |
| 15 | `RESET` | Request zero-state reattestation from a reuse-qualified worker. |
| 16 | `RESET_ACK` | Confirm reset and trial identity. |
| 17 | `SHUTDOWN` | Request endpoint termination. |
| 18 | `SHUTDOWN_ACK` | Confirm clean endpoint termination. |
| 19 | `EXERCISE` | Start a bounded untimed minimal-work reset-contract cycle. |
| 20 | `EXERCISED` | Attest nonzero live connection/work state before reset. |
| 21 | `ARM_REJECTED` | Reject a stale ARM while retaining the control channel. |

Required field IDs and wire types are defined only by the JSON registry. The
single optional registry field is `diagnostic` (`0x8001`, UTF-8); it cannot
change state or validity.

## State machines

`describe --control-fd=<fd>` completes exactly:

```text
HELLO -> CAPABILITIES -> SHUTDOWN -> SHUTDOWN_ACK
```

A worker starts once with `HELLO -> CAPABILITIES`. A server trial completes
`CONFIG -> BOUND -> READY`; the coordinator then includes the bound address and
port in the client's `CONFIG`, after which the client reports `READY`. Both
endpoints proceed through:

```text
ARM -> ARMED -> MEASUREMENT_STARTED -> PROGRESS* ->
MEASUREMENT_STOPPED -> COMPLETION_ACK -> RESULT
```

An ARM whose warmup boundary is no longer in the future produces
`ARM_REJECTED`; the endpoint remains at the same trial boundary and may receive
another ARM or SHUTDOWN. `UNSUPPORTED` or `ERROR` is terminal for the attempt. A fresh-process worker
then completes `SHUTDOWN -> SHUTDOWN_ACK`. A reuse-qualified worker instead
completes `RESET -> RESET_ACK`, reattests zero transport/application state, and
returns to `CONFIG`; it receives `SHUTDOWN` only after its last assigned trial.
An out-of-order or duplicate message is fatal even when its fields are otherwise
valid.

Worker-reuse reset screening uses a separate untimed branch after `READY`:

```text
EXERCISE -> EXERCISED -> RESET -> RESET_ACK
```

`EXERCISE` carries an absolute monotonic-raw deadline no more than five seconds
ahead. Both endpoints keep their native event loops active until they can attest
nonzero live connections and work inventory. Only then may the coordinator send
`RESET`; `RESET_ACK` must report exact zero connection, stream, ticket, and work
inventories before the persistent worker can accept another `CONFIG`.

The exact state timeouts are five seconds for `HELLO`, `CAPABILITIES`, `CONFIG`,
`BOUND`, and `READY`; five seconds for `EXERCISED`; two seconds for `ARMED` and
`RESET_ACK`; the scenario-
specific completion bound for `COMPLETION_ACK`; and one second for
`SHUTDOWN_ACK`. The absolute ARM-to-terminal watchdog is warmup plus measurement
window plus completion bound plus two seconds. Timeout cleanup is TERM for two
seconds followed by KILL for one second.

## Trust boundary

The inherited descriptor is supplied by the supervisor and is not configurable
through the environment. Endpoint PIDs, open network descriptors, threads,
loaded executable mappings, effective settings, and counters are independently
audited at readiness and result. A syntactically valid packet never overrides
the frozen campaign identity or schedule.
