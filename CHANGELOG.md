# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).


## [0.2.0] - 2026-10-14

Additive release: `msg_auth_verify()` and every 0.1.0 behaviour are unchanged.

### Added
- `msg_auth_verify_from()`: verification for callers that know the only
  acceptable sender (e.g. one peer per link). Any other sender is rejected
  with the new `ESP_ERR_MSG_AUTH_WRONG_SENDER` before the tag is checked,
  without touching that sender's freshness state or per-peer statistics.
  Fixes the cross-link case where a genuine envelope relayed onto the wrong
  link advanced its sender's state and caused the real copy to be rejected
  as a replay. An invalid `expected_sender` is `ESP_ERR_INVALID_ARG`
  whatever the envelope contains. Outputs are written only on `ESP_OK`.
- `msg_auth_rx_info_t`: the verified `(epoch, counter)` of an accepted
  envelope, returned by `msg_auth_verify_from()`, for event identity.
- `msg_auth_get_stats()` and `msg_auth_stats_t`: context-wide
  `bad_tag_total` and `wrong_sender` counters.
- `msg_auth_err_to_name()` names `ESP_ERR_MSG_AUTH_WRONG_SENDER`.
- Host tests T26–T33: right and wrong sender, the cross-link scenario,
  check order, argument checks and untouched outputs, bit flips, injected
  crypto failure, context statistics and concurrency through
  `msg_auth_verify_from()`. T1–T25 unchanged.
- `examples/sign_verify`: node C, `verify_from` scenarios including a
  relayed envelope on the wrong link, and `target_checks.c`, which measures
  every `MSG_AUTH_SPEC.md` §9.3 row (MAC path, HMAC driver, concurrency on
  one key ID, `psa_crypto_init`, heap at create and per call, stack per
  call, latency at 0/64/512/1432 bytes) and prints it as one block.

### Changed
- Steps 1–7 of verification are one internal function shared by both
  entry points.
- Per-peer `bad_tag` is documented as tag failures *claiming* that sender
  (the ID is unauthenticated); `bad_tag_total` is the reliable count.

### Documentation
- `MSG_AUTH_SPEC.md`: §1 points to `verify_from`; new §5.4a and §5.8; §5.7
  seven codes; §6.3 event identity from `info.epoch`; §7 concurrency table;
  §7 memory notes PSA's per-call heap use; §9.3 names the HMAC driver
  actually used (ESP's transparent HMAC driver on the SHA accelerator, not
  the eFuse-key HMAC peripheral) and records ESP32 QEMU results; §10 tests
  T26–T33; §11 example; §12 open point 2 resolved.
- README: `verify_from` usage, results table, statistics, chip status.

### Verified
- Host: T1–T33 pass on both MAC paths with ASan/UBSan (TF-PSA-Crypto from
  Mbed TLS 4.0.0).
- ESP-IDF v6.0.3: example builds without warnings for ESP32 (both MAC
  paths) and ESP32-S3, and passes 27/27 in Espressif's QEMU (ESP32) on both
  paths. Hardware latency and the hardware §9.3 record are still to be
  recorded.


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
