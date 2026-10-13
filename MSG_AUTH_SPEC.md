# msg_auth — Core Specification

This file is everything needed to implement the component. If a plausible implementation could get a rule wrong, the rule is written here.

---

## 1. What msg_auth is

- An ESP-IDF component that **authenticates individual messages** between nodes that share a secret key (a pre-shared key, provisioned per installation).
- Sender side: wraps a message in an **envelope** carrying sender/receiver IDs, an epoch, a counter and a 16-byte **tag** (HMAC-SHA256 truncated to 128 bits).
- Receiver side: recomputes the tag and rejects forged, altered, oversized, misaddressed and **replayed** messages, then returns the original message.
- **Pure authentication logic on bytes.** No network, no sockets, no NVS, no tasks, no callbacks. It works the same over UDP, UART, BLE or anything else. Transport, key storage and provisioning belong to the caller.
- Cryptography is used **only to authenticate**: HKDF-SHA256 for key derivation and HMAC-SHA256 for tags, through the **PSA Crypto API** (Mbed TLS 4.x, as shipped with ESP-IDF 6.0).

### Non-goals

- **No encryption.** Messages travel in clear; integrity and authenticity only. The envelope reserves a `mode` value for a future authenticated-encryption mode.
- **No sessions, handshakes, key exchange, peer discovery or transport management.** These belong to a higher-level component (a secure channel), never to msg_auth.
- **No per-node identity proof.** All holders of the installation key are equally trusted. Any of them can sign as any `sender_id`, and can therefore also advance another sender's freshness state and cause that sender's genuine messages to be rejected. `sender_id` is an authenticated claim by a key holder, not proof of which physical node sent the message. Callers that know the expected sender (e.g. from the link the message arrived on) check `sender_id` themselves.
- **No independent trust domains.** Purpose labels separate keys by use (domain separation); they do not isolate a compromised key holder, who can derive every purpose key.
- **No reordering tolerance.** Messages must arrive in increasing order per sender; an older one is rejected as a replay (§6). Suitable for state-type traffic, not for audio or other streams that may be reordered.

## 2. Concepts

| Term | Meaning |
| --- | --- |
| **Installation key** | Secret input key material, 16–64 bytes, identical on all nodes of one installation. Never transmitted. msg_auth does not retain it. |
| **Purpose** | ASCII label selecting an independent derived key (e.g. `"status"`). 1–32 bytes, each in `0x21`–`0x7E` (printable, no space). |
| **Derived key** | HKDF-SHA256 output, 32 bytes, created **directly as a PSA key object** (§5.1). msg_auth never receives or holds it as a byte array; it exists only inside the PSA key store, referenced by a key ID. |
| **Node ID** | `uint8_t`, `0 … max_peer_id`, unique per node, assigned by the caller's configuration. |
| **Epoch** | `uint32_t` supplied by the caller at create. Must be **strictly greater on every boot** of the node (§6.2). |
| **Counter** | `uint32_t`, per context, starting at 0 in each epoch, incremented on every signed message. Valid values `0 … UINT32_MAX − 1`. |
| **Freshness pair** | `(epoch, counter)`, compared lexicographically: epoch first, then counter. |

## 3. Wire format (envelope)

All multi-byte integers are **big-endian**, independent of the CPU's byte order. `n` = message length.

| Offset | Field | Type | Value |
| --- | --- | --- | --- |
| 0 | `version` | u8 | `1` |
| 1 | `mode` | u8 | `1` = AUTH (tag only). `2` = reserved for authenticated encryption; **never accepted by this component**. Any other value is invalid |
| 2 | `sender_id` | u8 | signer's node ID |
| 3 | `receiver_id` | u8 | intended receiver's node ID |
| 4 | `epoch` | u32 | sender's epoch |
| 8 | `counter` | u32 | sender's counter for this message |
| 12 | `message` | n bytes | caller's message, unchanged |
| 12 + n | `tag` | 16 bytes | first 16 bytes of `HMAC-SHA256(derived_key, bytes[0 … 12+n−1])` |

- **Overhead:** `MSG_AUTH_OVERHEAD = 28` bytes (12-byte header + 16-byte tag).
- The tag covers **the whole header and the message**, so IDs, epoch, counter, version and mode cannot be changed without detection.
- **Size limits:** `0 ≤ n ≤ MSG_AUTH_MAX_MESSAGE = 1432`, so an envelope is at most `MSG_AUTH_MAX_ENVELOPE = 1460` bytes. This is a protocol profile chosen so that one envelope fits one `udp_link` datagram; it is not a cryptographic requirement. Both signer and verifier enforce it.

### Key derivation (normative)

```
derived_key = HKDF-SHA256(
    salt = the 11 ASCII bytes "msg_auth v1"      (no terminating NUL)
    ikm  = installation key (key_len bytes)
    info = purpose label bytes                    (no terminating NUL)
    L    = 32 bytes )
```

These choices are frozen by the known-answer fixtures (§10).

## 4. Public header (verbatim)

```c
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSG_AUTH_HEADER_SIZE      12
#define MSG_AUTH_TAG_SIZE         16
#define MSG_AUTH_OVERHEAD         (MSG_AUTH_HEADER_SIZE + MSG_AUTH_TAG_SIZE)
#define MSG_AUTH_MAX_MESSAGE      1432
#define MSG_AUTH_MAX_ENVELOPE     (MSG_AUTH_MAX_MESSAGE + MSG_AUTH_OVERHEAD)   /* 1460 */
#define MSG_AUTH_MAX_PEERS        32          /* node IDs 0..31 */
#define MSG_AUTH_KEY_MIN          16
#define MSG_AUTH_KEY_MAX          64
#define MSG_AUTH_PURPOSE_MAX      32

#define ESP_ERR_MSG_AUTH_BASE        0x71000
#define ESP_ERR_MSG_AUTH_MALFORMED   (ESP_ERR_MSG_AUTH_BASE + 1)  /* too short, bad version or mode  */
#define ESP_ERR_MSG_AUTH_NOT_FOR_ME  (ESP_ERR_MSG_AUTH_BASE + 2)  /* receiver_id != my_id (unauthenticated) */
#define ESP_ERR_MSG_AUTH_UNKNOWN     (ESP_ERR_MSG_AUTH_BASE + 3)  /* sender_id > max_peer_id or == my_id */
#define ESP_ERR_MSG_AUTH_BAD_TAG     (ESP_ERR_MSG_AUTH_BASE + 4)  /* forged, altered or wrong key    */
#define ESP_ERR_MSG_AUTH_REPLAY      (ESP_ERR_MSG_AUTH_BASE + 5)  /* freshness pair not newer        */
#define ESP_ERR_MSG_AUTH_EXHAUSTED   (ESP_ERR_MSG_AUTH_BASE + 6)  /* counter used up: new epoch needed */

typedef struct msg_auth *msg_auth_handle_t;

typedef struct {
    const uint8_t *key;          /* installation key; used during create only, not retained */
    size_t         key_len;      /* MSG_AUTH_KEY_MIN .. MSG_AUTH_KEY_MAX                     */
    const char    *purpose;      /* 1..MSG_AUTH_PURPOSE_MAX bytes in 0x21..0x7E, NUL-terminated */
    uint8_t        my_id;        /* 0 .. max_peer_id                                         */
    uint8_t        max_peer_id;  /* highest node ID in use, < MSG_AUTH_MAX_PEERS             */
    uint32_t       epoch;        /* strictly greater than on any previous boot (see §6.2)    */
} msg_auth_config_t;

typedef struct {
    uint32_t accepted;
    uint32_t bad_tag;
    uint32_t replay;
    uint32_t last_epoch;         /* freshness pair of the last accepted message */
    uint32_t last_counter;
    uint8_t  seen;               /* 0 until the first accepted message          */
} msg_auth_peer_stats_t;

/* Create a context. Derives the purpose key into the PSA key store.
 * The installation key buffer may be wiped by the caller after return. */
esp_err_t msg_auth_create(const msg_auth_config_t *cfg, msg_auth_handle_t *out);

/* Destroy the PSA key and free the context. No call may be in progress. */
esp_err_t msg_auth_delete(msg_auth_handle_t h);

/* Sign msg for receiver_id into out.
 * out must not overlap msg; out_cap >= msg_len + MSG_AUTH_OVERHEAD.
 * On success *out_len = msg_len + MSG_AUTH_OVERHEAD; on any failure *out_len = 0
 * (when out_len is non-null) and the counter is unchanged. */
esp_err_t msg_auth_sign(msg_auth_handle_t h, uint8_t receiver_id,
                        const void *msg, size_t msg_len,
                        void *out, size_t out_cap, size_t *out_len);

/* Verify an envelope. On ESP_OK, *msg points INTO `in` (borrowed, zero copy):
 * valid only while `in` stays valid and unchanged; copy it to keep it.
 * The component never modifies or frees `in`.
 * sender_id, msg and msg_len must be distinct writable objects that do not
 * overlap `in`. Output values on failure: see §5.4. */
esp_err_t msg_auth_verify(msg_auth_handle_t h,
                          const void *in, size_t in_len,
                          uint8_t *sender_id,
                          const void **msg, size_t *msg_len);

/* ADMINISTRATIVE: forget one peer's freshness state (stats kept).
 * Re-opens acceptance of that peer's historical messages; see §6.4.
 * Call only from trusted local recovery logic, never on a network request. */
esp_err_t msg_auth_reset_peer(msg_auth_handle_t h, uint8_t peer_id);

esp_err_t msg_auth_get_peer_stats(msg_auth_handle_t h, uint8_t peer_id,
                                  msg_auth_peer_stats_t *stats);

const char *msg_auth_err_to_name(esp_err_t err);

#ifdef __cplusplus
}
#endif
```

## 5. Functions

### 5.1 `msg_auth_create`

**Argument checks** → `ESP_ERR_INVALID_ARG`:
- null `cfg`, `out`, `key` or `purpose`;
- `key_len` outside 16…64;
- `purpose`: length measured with a **bounded** scan (`strnlen(purpose, MSG_AUTH_PURPOSE_MAX + 1)`); empty, longer than 32, or containing a byte outside `0x21…0x7E`;
- `max_peer_id ≥ MSG_AUTH_MAX_PEERS`; `my_id > max_peer_id`.

All-zero or all-`0xFF` keys are accepted (the component does not judge key quality).

**Steps**, each failure releasing everything acquired before it (single cleanup path):

| # | Step | On failure |
| --- | --- | --- |
| 1 | `*out = NULL` | — |
| 2 | Ensure PSA is initialised: call `psa_crypto_init()` (idempotent; ESP-IDF normally calls it at startup) | `ESP_FAIL` |
| 3 | Allocate the context (internal RAM) | `ESP_ERR_NO_MEM` |
| 4 | Create the mutex **in static storage inside the context** (`xSemaphoreCreateMutexStatic`) | free context; `ESP_FAIL` |
| 5 | HKDF (§3) **directly into a PSA key object**: import the installation key as a volatile `PSA_KEY_TYPE_DERIVE` key (usage `PSA_KEY_USAGE_DERIVE`, algorithm `PSA_ALG_HKDF(PSA_ALG_SHA_256)`); `psa_key_derivation_setup(PSA_ALG_HKDF(PSA_ALG_SHA_256))`; inputs salt (bytes) / secret (`psa_key_derivation_input_key` with the imported key) / info (bytes); then `psa_key_derivation_output_key()` with the attributes below; `psa_key_derivation_abort()` and destruction of the imported key in all cases | abort derivation; destroy imported key; delete mutex; free context; `ESP_FAIL` |
| 6 | `epoch = cfg->epoch`, `counter = 0`, all peers unseen, stats zero | — |
| 7 | `*out = h` | — |

Derived-key attributes:
- type `PSA_KEY_TYPE_HMAC`, 256 bits, **volatile** lifetime;
- usage `PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE` only (**no export, no copy**);
- algorithm: the **MAC algorithm selected per §9** (`PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16)`, or `PSA_ALG_HMAC(PSA_ALG_SHA_256)` on the fallback path).

msg_auth never copies the installation key into its own memory; it is imported into PSA as the derivation secret, that PSA key is destroyed as soon as derivation ends (on every path), and the caller's buffer is not referenced after create returns.

*Why the import (amended in v0.1.0):* PSA permits `psa_key_derivation_output_key()` only when the secret was supplied as a key with `psa_key_derivation_input_key()`; with a secret supplied through `psa_key_derivation_input_bytes()` it returns `PSA_ERROR_NOT_PERMITTED`, so raw bytes cannot be turned into a key with a chosen policy. Found by the first §9.3 check on host (TF-PSA-Crypto 1.0 / Mbed TLS 4.0.0).

### 5.2 `msg_auth_delete`

Null → `ESP_ERR_INVALID_ARG`. Otherwise `psa_destroy_key(key_id)`, delete the mutex, wipe the context (`mbedtls_platform_zeroize` or equivalent), free, `ESP_OK`. Precondition (the caller's): no other call on the handle is in progress or will start.

### 5.3 `msg_auth_sign`

**Checks** (in this order; on any failure `*out_len = 0` when `out_len` is non-null, nothing else changes):
1. Null handle, `out` or `out_len`, or `msg == NULL` with `msg_len > 0` → `ESP_ERR_INVALID_ARG`.
2. `receiver_id > max_peer_id` or `receiver_id == my_id` → `ESP_ERR_INVALID_ARG`.
3. `msg_len > MSG_AUTH_MAX_MESSAGE` → `ESP_ERR_INVALID_SIZE`.
4. `out_cap < msg_len + MSG_AUTH_OVERHEAD` → `ESP_ERR_INVALID_SIZE`.

**Steps:**
1. **Under the mutex:** if `counter == UINT32_MAX` → `ESP_ERR_MSG_AUTH_EXHAUSTED`. Otherwise take `c = counter`, set `counter = c + 1`. (Reserving the counter before computing the tag keeps concurrent signers' counters distinct.)
2. Write the header with `c`, copy the message.
3. Compute the tag (§9) over header + message; write it.
4. Crypto failure in step 3 → `ESP_FAIL`, `*out_len = 0`. The reserved counter value is not reused (gaps are harmless).
5. `*out_len = msg_len + 28`, `ESP_OK`.

The last counter value signed in an epoch is `UINT32_MAX − 1`; the next call returns `EXHAUSTED`.

### 5.4 `msg_auth_verify`

**Steps, in this order.** The first failure decides the result.

| # | Check | Result | Stats | Outputs written |
| --- | --- | --- | --- | --- |
| 0 | Null handle / `in` / `sender_id` / `msg` / `msg_len` | `ESP_ERR_INVALID_ARG` | none | none |
| 1 | `in_len > MSG_AUTH_MAX_ENVELOPE` | `ESP_ERR_INVALID_SIZE` | none | none |
| 2 | `in_len < 28`, or `version != 1`, or `mode != 1` | `ESP_ERR_MSG_AUTH_MALFORMED` | none | none |
| 3 | `receiver_id != my_id` | `ESP_ERR_MSG_AUTH_NOT_FOR_ME` (an unauthenticated routing result) | none | none |
| 4 | `sender_id > max_peer_id` or `sender_id == my_id` | `ESP_ERR_MSG_AUTH_UNKNOWN` | none | none |
| 5 | Verify the tag over `in[0 … in_len−17]` (§9), **outside the mutex** | mismatch: `ESP_ERR_MSG_AUTH_BAD_TAG`; crypto failure: `ESP_FAIL` | mismatch: `bad_tag++` **under the mutex**; crypto failure: none | `*sender_id` |
| 6 | **Under the mutex:** if the peer is seen and `(epoch, counter) ≤ (last_epoch, last_counter)` | `ESP_ERR_MSG_AUTH_REPLAY` | `replay++` | `*sender_id` |
| 7 | **Same critical section:** store the pair, `seen = 1`, `accepted++` | `ESP_OK` | — | `*sender_id`, `*msg = in + 12`, `*msg_len = in_len − 28` |

Rules:
- **The tag is checked before the freshness state is read or changed**, so forged messages cannot advance a peer's state.
- **A crypto-library failure is never an authentication result:** it returns `ESP_FAIL`, does not count as `bad_tag`, does not touch freshness state, and never accepts the message.
- **Every** change to statistics and freshness state happens under the mutex.
- `*msg` and `*msg_len` are written only on `ESP_OK`; `*sender_id` only for steps 5–7.

### 5.5 `msg_auth_reset_peer`

`peer_id > max_peer_id` or `peer_id == my_id` → `ESP_ERR_INVALID_ARG`. Under the mutex: `seen = 0` for that peer; stats kept. See §6.4 for what this means.

### 5.6 `msg_auth_get_peer_stats`

Same ID checks as `reset_peer`; null `stats` → `ESP_ERR_INVALID_ARG`. Copies under the mutex.

### 5.7 `msg_auth_err_to_name`

Returns the names of all six msg_auth codes; `esp_err_to_name()` for any other value.

## 6. Freshness and replay

### 6.1 Rules

- **Sender:** one counter per context, shared by all receivers. Each receiver sees a strictly increasing subsequence; gaps are normal.
- **Receiver:** accepts a message only if its `(epoch, counter)` is **strictly greater** than the last accepted one from that sender.
- **Reordering:** an authentic message older than one already accepted is rejected as `REPLAY`. The same applies to concurrent verification: if two valid messages from one sender are verified in parallel and the newer one reaches the critical section first, the older one is rejected. This is the documented consequence of a strict high-water mark.

### 6.2 Epoch contract (the caller's obligation)

msg_auth cannot enforce these; the caller must:
1. Obtain the epoch from durable storage (e.g. a boot counter in NVS) and **commit the incremented value before creating the context**.
2. If that commit fails, **do not create the context** (fail closed): never sign under an epoch that might be reused.
3. Never wrap: an epoch of `UINT32_MAX` cannot be followed by a greater one. A node that reaches it must be re-provisioned (new installation key, or all peers reset per §6.4).
4. Treat erased, restored or replaced storage as a recovery event (§6.4).

**Repeated epoch** (contract violated, e.g. a commit was lost): a receiver that still holds state accepts only messages whose counter exceeds its last accepted counter for that epoch; a receiver that lost its state accepts the first one regardless.

### 6.3 Scope of the guarantee

Replay protection lasts **as long as the receiver's context**. Freshness state is kept in RAM; after a receiver restarts, the **first** authenticated message from each peer is accepted whatever its freshness pair, so a captured old message could be accepted once at that moment.

This suits **state-type traffic**, where a newer message supersedes an older one (status updates, periodic reports) and harmless events (a doorbell). It does **not** suit one-shot commands that must never execute twice (e.g. door unlock); those need a stronger mechanism at a higher layer (persistent state or a session challenge).

### 6.4 Recovery (`msg_auth_reset_peer`)

When a peer legitimately restarts with a **lower** epoch (its storage was erased or restored), all its messages are rejected as `REPLAY` until the receiver forgets that peer's state. `msg_auth_reset_peer()` does this, and in doing so **deliberately reopens acceptance of that peer's historical messages** until a new message re-establishes its state. Therefore:
- it is an **administrative operation**, started only by trusted local action (e.g. a button held at install time, or a provisioning step), **never** by a network message;
- the recovery procedure should establish the peer's new epoch deliberately and reset all relevant receivers in a controlled way;
- the temporary loss of replay protection is accepted only where §6.3's traffic scope applies.

### 6.5 Counter exhaustion

The valid counter range per epoch is `0 … UINT32_MAX − 1` (2³² − 1 values): 136 years at 1 message/s, about 4 years at 33/s. On exhaustion the caller recreates the context with a new epoch.

## 7. Concurrency and lifetime

| Call | May run concurrently with | Mechanism |
| --- | --- | --- |
| `sign` | `sign`, `verify`, `get_peer_stats` | counter reserved under the mutex; MAC computed outside it |
| `verify` | `sign`, `verify`, `get_peer_stats` | MAC verified outside the mutex; all stats and freshness changes under it |
| `reset_peer` | anything except `delete` | under the mutex |
| `create` / `delete` | nothing on the same handle | caller's precondition |

- Every PSA MAC operation is a **one-shot call on the shared key ID** (`psa_mac_compute` / `psa_mac_verify`); no PSA operation object is shared between calls. Concurrent use of the **same key ID** from several tasks must be confirmed on the target (§9.3).
- The caller keeps the handle alive for the duration of every call, and does not modify or release `in` while `verify` reads it (nor afterwards, while using the borrowed `*msg`).
- Task context only; never from an ISR.

### Memory

msg_auth makes **one allocation of its own** (the context, with the mutex stored inside it) in `create`, and **none** in `sign`, `verify` or the other calls. The PSA implementation may allocate internally (key slot, derivation, MAC operations); this is measured on the target (§9.3) and recorded, not assumed.

## 8. Security requirements

- **No hand-written, early-exit comparison of tags.** On the primary path the comparison is done by `psa_mac_verify()`. On the fallback path (§9.2) it is done by a **verified constant-time comparison primitive available in the selected build**, or, if none is available, by the component's own reviewed fixed-length comparison helper that accumulates differences over all 16 bytes with no early exit.
- The derived key is a non-exportable PSA key used only for signing and verifying; it is destroyed on `delete` and on every `create` failure after derivation.
- The installation key is not copied or retained by msg_auth. Its storage, and protection at rest (NVS encryption, flash encryption for physically accessible devices), are the caller's responsibility.
- Truncating HMAC-SHA256 to 128 bits is standard practice and far beyond forgery range.

## 9. Implementation path (PSA Crypto)

ESP-IDF 6.0 ships Mbed TLS 4.x, where PSA Crypto is the primary interface and most legacy `mbedtls_*` crypto APIs are removed. msg_auth uses PSA only.

### 9.1 Primary path

- Key algorithm: `PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), 16)`.
- Sign: `psa_mac_compute(key, alg, data, len, tag, 16, &tag_len)`.
- Verify: `psa_mac_verify(key, alg, data, len, tag, 16)`:
  `PSA_SUCCESS` → match; `PSA_ERROR_INVALID_SIGNATURE` → `BAD_TAG`; anything else → `ESP_FAIL`.

### 9.2 Fallback path

Used if the target's PSA implementation does not accept the truncated-MAC policy. **Wire format and results are identical.**
- Key algorithm: `PSA_ALG_HMAC(PSA_ALG_SHA_256)`.
- Sign: `psa_mac_compute` → 32-byte MAC → copy the first 16 bytes into the envelope.
- Verify: `psa_mac_compute` → 32-byte MAC → compare its first 16 bytes with the received tag using the comparison required by §8; wipe the computed MAC afterwards. A PSA error → `ESP_FAIL`.

### 9.3 Target checks (done first, results recorded here)

Run on the actual ESP-IDF 6.0 target before the implementation is considered final:

| Check | Result |
| --- | --- |
| HKDF output directly into an HMAC key with the required usage policy | Host, Mbed TLS 4.0.0: works only with the secret as an imported DERIVE key (§5.1 step 5, amended). Target: to record |
| Truncated-MAC policy accepted (selects §9.1 or §9.2) | Host, Mbed TLS 4.0.0 built-in driver: accepted, both paths pass T1–T25. Target (ESP HMAC driver): to record |
| Concurrent sign and verify from ≥ 2 tasks using the **same key ID**: no errors, all results correct | to record |
| `psa_crypto_init()` behaviour when already initialised; failure handling | to record |
| Heap: at `create`, per `sign`/`verify` (should be 0 from msg_auth itself), PSA internals | to record |
| Peak stack use of `sign` / `verify` | to record |
| Latency of `sign` / `verify` at 0, 64, 512 and 1432 bytes | to record |

Each record states the ESP-IDF version, target chip, relevant PSA/Mbed TLS configuration and the implementation path selected.

## 10. Code organisation and tests

```
msg_auth/
  include/msg_auth.h         public API (§4)
  private/msg_auth_priv.h    pure functions, for host tests
  src/msg_auth_pure.c        envelope encode/decode, freshness comparison,
                             purpose validation, fixed-length compare helper
  src/msg_auth.c             context, mutex, PSA calls
  examples/sign_verify/      in-process example, no network (§11)
  host_test/                 Unity / plain C on Linux
    fixtures/                independently generated known-answer vectors
  idf_component.yml          idf >= 6.0, < 6.1; PSA via the built-in mbedtls component
```

Pure functions (no PSA, no RTOS):

```c
void      msg_auth_hdr_encode(uint8_t out[12], uint8_t sender, uint8_t receiver,
                              uint32_t epoch, uint32_t counter);
esp_err_t msg_auth_hdr_decode(const uint8_t *in, size_t in_len, msg_auth_hdr_t *hdr);
bool      msg_auth_is_newer(uint32_t e, uint32_t c, uint32_t last_e, uint32_t last_c);
bool      msg_auth_purpose_valid(const char *purpose);
bool      msg_auth_ct_equal16(const uint8_t a[16], const uint8_t b[16]);
```

### Known-answer fixtures

Generated **independently of the implementation** (e.g. with Python `hmac` / `hashlib` and an RFC 5869 HKDF), checked into `host_test/fixtures/`, never computed at test time by the code under test:
- HKDF: fixed installation key + purpose → derived key bytes (tests §3's salt/info encoding).
- HMAC: fixed derived key + data → full and truncated MAC.
- Envelope: fixed key, purpose, IDs, epoch, counter, message → exact envelope bytes.

### Tests

| # | Test |
| --- | --- |
| T1 | Sign then verify returns the message, length and sender ID unchanged, for lengths 0, 1, 100, 1432 |
| T2 | Every single-bit flip in the envelope gives the result of the **first** check that field reaches: `MALFORMED` (version/mode), `NOT_FOR_ME` (receiver), `UNKNOWN` (sender out of range), else `BAD_TAG` |
| T3 | Different key, or same key with a different purpose → `BAD_TAG` |
| T4 | Same envelope verified twice → second is `REPLAY` |
| T5 | Older counter after a newer one → `REPLAY`; gaps accepted |
| T6 | New epoch with counter 0 after an old epoch with a high counter → accepted |
| T7 | Lower epoch → `REPLAY`; after `reset_peer` → accepted |
| T8 | Envelope for node 1 given to node 2 → `NOT_FOR_ME` |
| T9 | Sender ID equal to own ID, or above max → `UNKNOWN` |
| T10 | A forged message with a high counter (bad tag) does not advance freshness: the next genuine message is accepted |
| T11 | Shorter than 28 bytes, wrong version, mode 2 → `MALFORMED` |
| T12 | Envelope of exactly 1460 bytes accepted; 1461 → `ESP_ERR_INVALID_SIZE` (before any MAC) |
| T13 | Counter boundary: sign with counter `UINT32_MAX − 1` succeeds; the next sign → `EXHAUSTED`; `*out_len == 0` |
| T14 | Repeated epoch: with receiver state retained, only higher counters accepted; after receiver state is lost, the first message accepted |
| T15 | Argument checks for every function; `out_len` zero and outputs untouched on every failure path as specified |
| T16 | Purpose validation: lengths 0, 1, 32, 33; bytes `0x20`, `0x7F`, `0x80`; unterminated buffer scanned only up to the bound |
| T17 | Key edge cases: all-zero and all-`0xFF` keys at 16 and 64 bytes |
| T18 | `reset_peer` / `get_peer_stats` with own ID, ID above max, highest valid ID |
| T19 | Known-answer fixtures: HKDF, HMAC and envelope bytes match |
| T20 | Injected crypto failure in sign and in verify → `ESP_FAIL`; no `bad_tag` increment, no freshness change, outputs per contract |
| T21 | `create` failure at each step (allocation, mutex, derivation) leaves nothing allocated and no PSA key alive |
| T22 | Two tasks verifying bad tags from the **same sender** simultaneously: `bad_tag` increases by exactly the number of failures |
| T23 | Two tasks signing concurrently: all counters distinct |
| T24 | Two tasks verifying **consecutive counters from the same sender** concurrently: outcomes consistent with §6.1 (either both accepted in order, or the older rejected as `REPLAY`); stats consistent |
| T25 | After a receiver restart, a previously accepted envelope is accepted once (documents §6.3) |

## 11. Example: `examples/sign_verify`

Runs on any ESP32 board, **no Wi-Fi and no network**: msg_auth needs nothing but bytes.

- Creates three contexts from a test key (menuconfig `EXAMPLE_PSK_HEX`, labelled insecure): node A (id 0), node B (id 1), and an "outsider" with a **different** key. The epoch comes from a boot counter in NVS, committed before create, showing how a real caller meets §6.2.
- A "channel" is a buffer passed from one context to another in the same task.
- Runs one scenario per row, logs result and expectation, prints PASS/FAIL:

| Scenario | Expected |
| --- | --- |
| A signs, B verifies | `ESP_OK`, message and sender ID intact |
| One bit flipped in message / header / tag | per T2 |
| Outsider signs, B verifies | `BAD_TAG` |
| Same envelope verified twice | second is `REPLAY` |
| Envelope for node 2 given to B | `NOT_FOR_ME` |
| Oversized, truncated, unsigned | `INVALID_SIZE` / `MALFORMED` |
| Newer epoch (second A context with epoch + 1) | accepted |
| Older epoch | `REPLAY`; after `msg_auth_reset_peer` accepted |
| Timing | µs per sign/verify at 64 B and 1432 B |

- Ends with per-peer stats from `msg_auth_get_peer_stats`.

A networked example (nodes over `udp_link`) belongs to a separate component that depends on both msg_auth and udp_link. msg_auth, including its examples, never depends on a transport.

## 12. Open points

1. Component name for publishing: `msg_auth`.
2. Whether `verify` should take an `expected_sender` argument (currently the caller checks `sender_id`).
3. Shape of the authenticated-encryption mode (`mode = 2`) for a future version, and the sliding replay window it would need for reorderable streams.
4. Accepting the installation key as a persistent PSA key ID (stored via PSA Internal Trusted Storage) instead of raw bytes, so the secret never passes through application memory.
