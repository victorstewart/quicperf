# Public benchmark TLS fixtures

Every certificate and private key in this directory is an intentionally public
quicperf test fixture. The keys are committed so benchmark identities are
reproducible.

They provide no secrecy or production trust. Never install these roots, reuse
these keys, or use these certificates for any real service. Production
deployments must generate and protect independent keys and trust anchors.
