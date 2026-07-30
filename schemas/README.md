# Harness v2 schemas

Harness v2 exchanges and persists strict canonical JSON. The schemas in this
directory are normative format contracts; the Python loaders additionally
enforce duplicate-key rejection, numeric bounds, path normalization, identity
hashes, exact publication cardinality, and cross-field rules that JSON Schema
cannot express.

| Document | Purpose |
|---|---|
| [`experiment-v2.schema.json`](experiment-v2.schema.json) | Immutable experiment, treatment, schedule, retry, analysis, manifest, validity, and qualification policy. |
| [`experiment-v2.1.schema.json`](experiment-v2.1.schema.json) | Additive V2.1 publication contract for observed monitor intervals, localized retries, and operational runtime reporting. |
| [`analysis-v2.1.schema.json`](analysis-v2.1.schema.json) | V2.1 deterministic analysis status plus prominently reported runtime-efficiency metrics. |
| [`experiment-v2.2.schema.json`](experiment-v2.2.schema.json) | V2.2 iouring-only primary-publication contract with exact 4,320-trial cardinality and frozen session/suite budgets. |
| [`analysis-v2.2.schema.json`](analysis-v2.2.schema.json) | V2.2 deterministic analysis status and session-ceiling evidence. |
| [`experiment-v2.3.schema.json`](experiment-v2.3.schema.json) | V2.3 ceiling-only revision of the iouring-only primary-publication contract. |
| [`analysis-v2.3.schema.json`](analysis-v2.3.schema.json) | V2.3 deterministic analysis status and three-hour session-ceiling evidence. |
| [`manifest-v2.schema.json`](manifest-v2.schema.json) | Source, dependency, binary, loaded-library, toolchain, protocol, path, and stable host-policy identity. |
| [`event-v2.schema.json`](event-v2.schema.json) | Append-only journal event/export envelope with campaign and entity identities. |
| [`result-v2.schema.json`](result-v2.schema.json) | Endpoint treatment, timing, raw metric, completion, cap/progress, telemetry, negotiated settings, and validity facts. |
| [`control-v1-fields.json`](control-v1-fields.json) | Machine-readable message/field registry for the Unix control protocol. |
| [`control-v1.md`](control-v1.md) | Wire encoding, state machines, timeouts, and trust boundary for that protocol. |
| [`suite-v1.schema.json`](suite-v1.schema.json) | Historical five-campaign suite identity. |
| [`suite-v9.schema.json`](suite-v9.schema.json) | Crash-safe V2.2 primary-only freeze identity with an immutable timing plan. |
| [`suite-v10.schema.json`](suite-v10.schema.json) | Crash-safe V2.3 primary-only freeze identity with the revised ceiling plan. |

Unknown properties are rejected. Identifiers and SHA-256 values are complete,
nonempty canonical strings. JSON numbers are finite integers within their
declared range; decimal policy values are canonical strings so parser/runtime
floating-point behavior cannot change identity. Arrays declared unique retain
their canonical order where order is semantically meaningful.

Canonical JSON uses UTF-8, sorted object keys, minimal separators, and no
insignificant whitespace. Hash domains are separated and length-prefix variable
fields. The immutable identity manifest contains stable source/build/host-policy
requirements; runtime PIDs, timestamps, loaded-library observations, health,
frequency, and temperature remain journal evidence and never mutate campaign
identity.

The V2.3 primary-only coordinator stores `suite.json` with schema version
`quicperf.publication-suite.v10`. Its top-level fields include
`schema_version`, `phase`, `suite_seed`, `creation_inputs`, and `campaigns`.
The ordered campaign array freezes the profile path/hash, derived seed, run
directory, campaign ID, schedule hash, planned-trial count, and maximum
preallocated trial-ID count for the fixed-treatment estimand. `phase=frozen`
requires every campaign identity field to be present;
unknown, partial, noncanonical, or profile-mismatched state is rejected.

Schema acceptance never implies publication qualification. `finalize` must also
verify exact frozen hashes, complete journal cardinality, paired microblocks,
validity, inference, two independent sessions, and all required physical gates.
Any gate recorded as `NOT_RUN` is a hard publication failure.
