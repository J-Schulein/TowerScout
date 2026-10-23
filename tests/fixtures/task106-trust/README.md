# Public incident certificate fixture

`distrusted-emsign-root.pem` is the public emSign ECC Root CA - G3 certificate,
retained only for offline rejection tests. It contains no private key and must
never be installed as trusted test or application state.

DER SHA-256: `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`.
Checked against the [incident disclosure inventory](https://github.com/galadran/we-have-a-problem.com/blob/main/roots.json).
The [Mozilla disclosure](https://www.openwall.com/lists/oss-security/2026/10/20/1)
provides the SPKI identity used by the runtime rejection policy.
