# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).


## [0.1.0] - 2026-10-12

### Added
- Initial release of `msg_auth`: per-message authentication for ESP-IDF v6.0.x
  between nodes that share an installation key. Pure logic on bytes: no
  network, no tasks, no callbacks, no flash access.
- Handle-based API: `msg_auth_create()`, `msg_auth_delete()`,
  `msg_auth_sign()`, `msg_auth_verify()`, `msg_auth_reset_peer()`,
  `msg_auth_get_peer_stats()` and `msg_auth_err_to_name()`.
- Envelope version 1: a 12-byte big-endian header (version, mode, sender,
  receiver, epoch, counter), the message (0 to 1432 bytes) and a 16-byte
  HMAC-SHA256 tag over both; at most 1460 bytes, one `udp_link` datagram.
- Purpose keys derived with HKDF-SHA256 (salt `"msg_auth v1"`, info = purpose
  label) directly into a volatile, non-exportable PSA HMAC key.
- Replay protection with a strict `(epoch, counter)` high-water mark per
  sender. The tag is checked before freshness state is read or changed.
- Distinct results for malformed, misaddressed, unknown-sender, bad-tag,
  replayed and counter-exhausted cases. Crypto-library failures return
  `ESP_FAIL` and never count as a bad tag.
- Zero-copy verify: the message is returned as a pointer into the caller's
  buffer.
- Thread safety: concurrent sign and verify on one context, with the
  counter reserved under a mutex and the MAC computed outside it.
- Two MAC paths with identical wire format: truncated-MAC key policy
  (default) and full HMAC with constant-time truncated compare
  (`-DMSG_AUTH_MAC_FALLBACK=1`).
- Build-time checks for the ESP-IDF release and the PSA algorithms and
  threading support msg_auth depends on.
- `MSG_AUTH_SPEC.md`: the complete implementation specification.
- `examples/sign_verify`: in-process acceptance test on any board, with an
  NVS boot-counter epoch, PASS/FAIL per scenario, timing and statistics.
- `host_test/`: tests T1–T25 on `msg_auth.c` against the real PSA Crypto
  library from ESP-IDF's Mbed TLS tree, on both MAC paths, with ASan/UBSan,
  fault injection and multi-threaded tests, plus known-answer vectors
  generated independently in Python.

### Changed (specification)
- `MSG_AUTH_SPEC.md` §5.1 step 5: the installation key is imported as a
  volatile PSA derivation key and passed with `psa_key_derivation_input_key()`.
  PSA does not permit `psa_key_derivation_output_key()` when the secret was
  given as raw bytes (`PSA_ERROR_NOT_PERMITTED`). The imported key is destroyed
  as soon as derivation ends, on every path.
