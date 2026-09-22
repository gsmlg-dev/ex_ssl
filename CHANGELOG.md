# Changelog

## [0.4.0] - 2026-09-22

- Add P-384 ECDHE/ECDSA, Ed25519 and RSA-PSS-PSS with runtime-filtered capabilities.
- Add bounded PEM/DER client identities and initial-handshake mutual TLS.
- Add explicit ordered algorithm policies and a safe TCP option allowlist.
- Add an independent opt-in TLS 1.2 ECDHE/EMS/AES-GCM client engine with four suites.
- Add opt-in TLS 1.3 PSK-DHE resumption with partitioned, bounded in-memory tickets,
  current certificate revalidation, fresh key shares and authenticated HRR binders.
- Add non-secret connection information, peer certificate and address diagnostics.
- Expand interoperability, negative, fragmented-input and lifecycle regressions.

TLS 1.3 remains the library default. Resumption defaults to disabled. Peer
verification remains mandatory. TLS 1.2/mTLS resumption, early data, automatic
backend fallback and request replay are unsupported. This remains an experimental
OTP-compatible client subset; it is not full OTP parity or security certification.
