# quicperf V2.3 schemas

quicperf exchanges and persists strict canonical JSON. JSON Schema describes
the format; Python loaders additionally reject duplicate keys, invalid numeric
bounds, unsafe paths, wrong identities, and impossible cross-field
cardinalities.

| Document | Purpose |
|---|---|
| [`experiment-v2.3.schema.json`](experiment-v2.3.schema.json) | Immutable V2.3 treatment, schedule, retry, validity, qualification, analysis, and runtime policy. |
| [`analysis-v2.3.schema.json`](analysis-v2.3.schema.json) | Deterministic V2.3 analysis and three-hour session-ceiling evidence. |
| [`suite-v10.schema.json`](suite-v10.schema.json) | Crash-resumable V2.3 primary-only suite identity and deadline plan. |
| [`manifest-v2.schema.json`](manifest-v2.schema.json) | Source, dependency, binary, loaded-library, toolchain, protocol, path, and stable host-policy identity. |
| [`event-v2.schema.json`](event-v2.schema.json) | Append-only journal event/export envelope. |
| [`result-v2.schema.json`](result-v2.schema.json) | Endpoint treatment, workload, timing, metric, telemetry, negotiated settings, and validity evidence. |
| [`control-v1-fields.json`](control-v1-fields.json) | Machine-readable Unix control-protocol field registry. |
| [`control-v1.md`](control-v1.md) | Control wire encoding, state machines, timeouts, and trust boundary. |

The retained `v2` names on manifest, event, result, and control schemas are
wire/artifact format versions still used by V2.3; they are not executable
V2.0 publication profiles.

Canonical JSON is UTF-8 with sorted object keys, minimal separators, no
insignificant whitespace, and finite integer numbers. Decimal policy values are
canonical strings. Hashes use separated domains and length-prefixed variable
fields.

Schema acceptance is not publication qualification. Finalization also requires
exact frozen identities, complete cardinality, paired microblocks, valid
workloads, two independent sessions, simultaneous inference, and every
required physical gate. `NOT_RUN` is never a pass.
