# v2 publication artifacts

This directory accepts immutable exports only from a campaign whose canonical
v2 `finalize` operation recorded `publication_qualified`.

It intentionally contains no result data. Diagnostic runs,
`implementation_complete` runs, and campaigns with any physical gate recorded
as `NOT_RUN` are not eligible.

No qualified-host evidence is committed, so the required physical publication
gates are currently `NOT_RUN`.
