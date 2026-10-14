# msg_auth

![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v6.0.x-blue)
![Espressif Component Registry](https://img.shields.io/badge/Espressif-Component%20Registry-orange)
![License](https://img.shields.io/badge/license-MIT-green)

Message authentication for ESP-IDF nodes that share a secret key. The
sender wraps each message in a 28-byte envelope: sender and receiver IDs,
an epoch, a counter and a 128-bit HMAC-SHA256 tag. The receiver checks the
envelope and gets the original message back only if it was signed with the
installation key, is unaltered, is addressed to it and is newer than
anything already accepted from that sender. Forged, altered, misaddressed
and replayed messages each get their own result code.

msg_auth works on bytes only. It opens no sockets, starts no tasks and
stores nothing in flash, so the same envelope travels over UDP, UART, BLE,
ESP-NOW or anything else. It authenticates; it does not encrypt.

---

## Features

* **One key per installation, one key per purpose** — every node holds the
  same 16–64-byte installation key. HKDF-SHA256 derives an independent key
  for each purpose label (`"status"`, `"doorbell"`, …), so tags made for
  one use never verify in another.
* **Key that cannot be read back** — the derived key lives only in the PSA
  key store, as a volatile key that can sign and verify but not be
  exported or copied. msg_auth never holds it as bytes.
* **Replay protection** — each sender's `(epoch, counter)` must increase.
  A captured envelope sent again is rejected, and so is any message older
  than one already accepted.
* **Tag first, state second** — the tag is checked before any freshness
  state is read or changed, so a forged message can never block a
  genuine sender.
* **Per-link sender check** — `msg_auth_verify_from()` takes the one sender
  a link may carry and rejects anything else before the tag is checked, so
  one node's envelopes relayed onto another node's link cannot disturb
  either node's replay state.
* **Distinct results** — malformed, misaddressed, unknown sender, wrong
  sender, bad tag, replay and exhausted counter each have their own code; a
  crypto-library failure is `ESP_FAIL`, never mistaken for a bad tag.
* **Zero copy on receive** — `msg_auth_verify()` returns a pointer into
  your receive buffer; nothing is copied or allocated.
* **Thread-safe** — any number of tasks may sign and verify on one
  context at once; counters stay distinct and statistics exact.
* **No hidden execution** — no tasks, timers or callbacks; one heap
  allocation per context, made in `msg_auth_create()`.

---

## Chip Support

msg_auth uses only the PSA Crypto API, so it runs on any ESP-IDF 6.0
target. Chips with a SHA accelerator use it through ESP-IDF's PSA driver.

| Chip | Status |
|---|---|
| ESP32 | **Verified** on hardware, ESP-IDF v6.0.3: example 27/27, §9.3 record complete |
| ESP32-S2 | Expected to work |
| ESP32-S3 | **Verified** on hardware, ESP-IDF v6.0.3: example 27/27, §9.3 record complete |
| ESP32-C3 | Expected to work |
| ESP32-C6 | Expected to work |

Update this table as hardware runs are recorded: `examples/sign_verify` is
the acceptance test, and prints the `MSG_AUTH_SPEC.md` §9.3 record.

**MAC path and driver.** The default (primary) path keeps a truncated-MAC
policy on the key; it is accepted on ESP32 and ESP32-S3 (ESP-IDF v6.0.3), so
the fallback is not needed there. HMAC runs
in ESP-IDF's transparent HMAC driver on the SHA accelerator
(`CONFIG_MBEDTLS_HARDWARE_SHA=y`, the default), not on the HMAC peripheral,
which works only with eFuse keys. On an ESP32-S3 at 160 MHz a sign or
verify takes about 160–220 µs from 0 to 1432 bytes, and 310–540 µs on an
ESP32 (`MSG_AUTH_SPEC.md` §9.3).

---

## Installation

```bash
idf.py add-dependency "embedblocks/msg_auth^0.2.0"
```

Or in `idf_component.yml`:

```yaml
dependencies:
  embedblocks/msg_auth: "^0.2.0"
```

ESP-IDF's defaults already enable everything msg_auth needs (SHA-256,
HMAC, HKDF, Mbed TLS threading). The build fails with a clear message if a
configuration has turned one of them off.

---

## Usage

Every node creates a context with the same key and purpose, its own node
ID, and an epoch that is higher than on any previous boot.

```c
#include "msg_auth.h"

static msg_auth_handle_t s_auth;

/* Your transport: udp_link, UART, BLE, ... */
extern void   transport_send(const void *buf, size_t len);
extern size_t transport_recv(void *buf, size_t cap);

static void rx_task(void *arg)
{
    static uint8_t buf[MSG_AUTH_MAX_ENVELOPE];
    for (;;) {
        size_t len = transport_recv(buf, sizeof buf);

        uint8_t     sender;
        const void *msg;
        size_t      msg_len;
        esp_err_t err = msg_auth_verify(s_auth, buf, len, &sender, &msg, &msg_len);
        if (err == ESP_ERR_MSG_AUTH_NOT_FOR_ME) {
            continue;                           // addressed to another node
        }
        if (err != ESP_OK) {
            ESP_LOGW("app", "rejected: %s", msg_auth_err_to_name(err));
            continue;
        }
        // msg_len bytes at msg, from node `sender`; msg points into buf
    }
}

void app_main(void)
{
    uint8_t key[32];
    load_installation_key(key);                 // your provisioning
    uint32_t epoch = next_boot_epoch();         // read, increment, COMMIT to NVS first

    const msg_auth_config_t cfg = {
        .key         = key,
        .key_len     = sizeof key,
        .purpose     = "status",
        .my_id       = 1,                       // this node
        .max_peer_id = 3,                       // nodes 0..3
        .epoch       = epoch,
    };
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_auth));
    memset(key, 0, sizeof key);                 // msg_auth kept no copy
    xTaskCreate(rx_task, "rx", 4096, NULL, 5, NULL);

    uint8_t env[64 + MSG_AUTH_OVERHEAD];
    for (;;) {
        const char report[] = "temp=21.5";
        size_t len;
        esp_err_t err = msg_auth_sign(s_auth, 0, report, sizeof report,
                                      env, sizeof env, &len);
        if (err == ESP_ERR_MSG_AUTH_EXHAUSTED) {
            // counter used up: recreate the context with a new epoch
        } else if (err == ESP_OK) {
            transport_send(env, len);
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

`examples/sign_verify` shows a complete `next_boot_epoch()` with NVS.

### When each link has one known peer

If the transport tells you which node a message must come from (one UDP
link per peer, say), use `msg_auth_verify_from()` instead:

```c
/* on the link that belongs to node `peer` */
const void        *msg;
size_t             msg_len;
msg_auth_rx_info_t info;                    // optional; pass NULL if unused
esp_err_t err = msg_auth_verify_from(s_auth, peer, buf, len, &msg, &msg_len, &info);
if (err == ESP_OK) {
    // authentic, fresh and from `peer`; info.epoch / info.counter are the
    // verified freshness pair, e.g. for event IDs (sender, info.epoch, event_id)
}
```

An envelope from any other node gets `ESP_ERR_MSG_AUTH_WRONG_SENDER` before
the tag is computed, and that node's replay state is left alone. With plain
`msg_auth_verify()` and a check of `sender_id` afterwards, the state would
already have moved: a genuine envelope relayed onto the wrong link would be
accepted, dropped by you, and its real copy then rejected as a replay.

### Sign results

| Result | Meaning | What to do |
|---|---|---|
| `ESP_OK` | `*out_len` = message length + 28 bytes of envelope | send it |
| `ESP_ERR_MSG_AUTH_EXHAUSTED` | the counter has used all 2³² − 1 values of this epoch | recreate the context with a new epoch |
| `ESP_ERR_INVALID_SIZE` | message over 1432 bytes, or `out_cap` too small | fix the caller |
| `ESP_ERR_INVALID_ARG` | null argument, or `receiver_id` is your own ID or above `max_peer_id` | fix the caller |
| `ESP_FAIL` | the crypto library failed | report; unexpected |

On any failure `*out_len` is 0 and nothing should be sent. A counter
value reserved by a failed sign is skipped, never reused.

### Verify results

| Result | Meaning | `*sender_id` (`verify` only) |
|---|---|---|
| `ESP_OK` | authentic and fresh; `*msg_len` bytes at `*msg` | written |
| `ESP_ERR_INVALID_SIZE` | envelope over 1460 bytes | — |
| `ESP_ERR_MSG_AUTH_MALFORMED` | under 28 bytes, unknown version, or a mode this version does not accept | — |
| `ESP_ERR_MSG_AUTH_NOT_FOR_ME` | addressed to another node (an unauthenticated routing result) | — |
| `ESP_ERR_MSG_AUTH_UNKNOWN` | sender ID is your own or above `max_peer_id` | — |
| `ESP_ERR_MSG_AUTH_WRONG_SENDER` | `verify_from` only: sender ID is a valid peer, but not the expected one (unauthenticated routing result) | — |
| `ESP_ERR_MSG_AUTH_BAD_TAG` | forged, altered, or made with another key or purpose | claimed, unauthenticated |
| `ESP_ERR_MSG_AUTH_REPLAY` | authentic but not newer than the last message accepted from that sender | written |
| `ESP_ERR_INVALID_ARG` | null argument; for `verify_from`, an expected sender that is your own ID or above `max_peer_id` (whatever the envelope) | — |
| `ESP_FAIL` | the crypto library failed; not counted as a bad tag, no state changed | claimed, unauthenticated |

Rejections are listed in the order the checks run: everything above
`BAD_TAG` is decided from the header alone, before any MAC is computed.
`*msg` and `*msg_len` (and `*info` for `verify_from`) are written only on
`ESP_OK`.

### Statistics

`msg_auth_get_peer_stats()` returns per-peer counters. Its `bad_tag` counts
tag failures **claiming** that sender: the ID in a failed envelope is not
authenticated, so anyone can raise it. `msg_auth_get_stats()` returns
context-wide counters that cannot be pinned on an innocent peer:
`bad_tag_total` (every `BAD_TAG`) and `wrong_sender` (every `WRONG_SENDER`;
a rising count on a link is what a relay attack looks like).

### Rules

- **The epoch must rise on every boot, and be committed before create.**
  Keep a boot counter in NVS: read it, store the incremented value, and
  only create the context if that commit succeeded. Never sign under an
  epoch that might be reused.
- **`*msg` is borrowed.** It points into your receive buffer and stays
  valid only while that buffer is unchanged. Copy what you keep.
- **`sender_id` names a key holder, not a device.** Every node with the
  installation key can sign as any ID. If you know which node a message
  must come from (the link it arrived on, say), use
  `msg_auth_verify_from()`; don't compare `sender_id` after
  `msg_auth_verify()`, which has already updated that sender's state.
- **Messages from one sender must arrive in order.** An authentic message
  older than one already accepted is a `REPLAY`. Fine for status and
  telemetry, not for streams that reorder.
- **`msg_auth_reset_peer()` is for local recovery only.** It reopens that
  peer's old messages until a new one arrives. Call it from a button held
  at install time or a provisioning step, never because of a message.
- **Delete only when no other call is in progress.** Task context only;
  never from an ISR.

### What replay protection covers

Freshness state lives in RAM. After a **receiver** restarts, the first
authentic message from each peer is accepted whatever its age, so a
captured old message could be accepted once at that moment. That suits
state-type traffic, where newer messages supersede older ones, and
harmless events. Do **not** rely on it for one-shot commands that must
never run twice, such as unlocking a door; those need a challenge or
persistent state at a higher layer.

If a **sender** loses its NVS (erase, restore, replacement), its epoch goes
backwards and receivers reject it as `REPLAY` until each one calls
`msg_auth_reset_peer()` for it.

---

## Wire Format

Every envelope is a 12-byte header, the message, and a 16-byte tag, all
integers big-endian:

| Offset | Field | Type |
|---|---|---|
| 0 | version (`1`) | u8 |
| 1 | mode (`1` = authenticated; `2` reserved for encryption) | u8 |
| 2 | sender_id | u8 |
| 3 | receiver_id | u8 |
| 4 | epoch | u32 |
| 8 | counter | u32 |
| 12 | message (0–1432 bytes) | bytes |
| 12 + n | tag: first 16 bytes of HMAC-SHA256(derived key, bytes 0 … 11 + n) | 16 bytes |

The derived key is `HKDF-SHA256(salt = "msg_auth v1", ikm = installation
key, info = purpose, L = 32)`. A Python or PC peer can produce and check
envelopes with nothing but its standard HMAC and HKDF;
`host_test/fixtures/gen_fixtures.py` does exactly that.

A 1460-byte envelope fits one `udp_link` datagram.

---

## Examples

| Example | What it does | Hardware |
|---|---|---|
| `examples/sign_verify` | Contexts in one task run every accept and reject case (including a relayed envelope on the wrong link), print PASS/FAIL and statistics, then measure everything `MSG_AUTH_SPEC.md` §9.3 asks for (concurrency on one key, heap, stack, latency) and print it as one block | Any ESP32 board; no Wi-Fi |

---

## Testing

| Folder | What it is | How to run |
|---|---|---|
| `examples/sign_verify` | On-target acceptance test, no network | `idf.py set-target esp32c3 build flash monitor` |
| `host_test/` | Tests T1–T33 of the spec, run on `msg_auth.c` itself against the real PSA Crypto library from ESP-IDF's Mbed TLS tree, on both MAC paths, with ASan/UBSan, fault injection and multi-threaded tests; known-answer vectors generated independently in Python | `make` (Linux or WSL, `IDF_PATH` set) |

---

## Notes

**Why the installation key is imported into PSA briefly.** PSA allows a
derivation to produce a key object only when its secret was itself a key,
so raw bytes can't be turned into a key with a chosen policy.
`msg_auth_create()` therefore imports the installation key as a volatile
derivation-only key, runs HKDF into the HMAC key, and destroys the
imported key at once, on every path. Your buffer is not referenced after
create returns.

**Two MAC paths.** By default the derived key carries a truncated-MAC
policy and `psa_mac_verify()` compares tags. If a target's PSA driver
rejects that policy, build with `idf.py -DMSG_AUTH_MAC_FALLBACK=1`: the key
carries plain HMAC-SHA256, msg_auth truncates the result itself and
compares in constant time with `mbedtls_ct_memcmp()`. Wire format and
results are identical; the host tests run both.

**Several purposes.** Create one context per purpose. Each has its own
derived key, counter and freshness state.

**Memory.** One heap allocation per context, in internal RAM: the context
with its mutex, plus 24 bytes of statistics per node ID. `msg_auth_create()`
took 224 bytes in total on ESP32 for three node IDs, PSA's key storage
included. `sign` and `verify` allocate
nothing in msg_auth, but ESP-IDF's HMAC driver briefly takes about 280
bytes of heap per call and returns it (each concurrent call holds its own). If that fails the call returns
`ESP_FAIL`, never `BAD_TAG`.

**Counter life.** 2³² − 1 messages per epoch: 136 years at one message a
second, about four years at 33 a second.

---

## Known Limitations

- No encryption: messages travel in clear.
- All key holders are equally trusted. Any of them can sign as any node,
  and so can push another sender's freshness state forward;
  `msg_auth_verify_from()` stops outsiders relaying envelopes between
  links, not key holders.
- No tolerance for reordering; one high-water mark per sender.
- Replay protection lasts as long as the receiver's context (see above).
- At most 32 nodes (IDs 0–31) per installation; messages of at most 1432
  bytes.
- No sessions, key exchange or key rotation; those belong to a
  higher-level component.

---

## Requirements

- ESP-IDF v6.0.x (Mbed TLS 4.x, PSA Crypto). The build fails on other
  releases until a release has been verified.
- PSA support for SHA-256, HMAC and HKDF, and `CONFIG_MBEDTLS_THREADING_C`
  (all ESP-IDF defaults). The build checks each one.
- Durable storage for the boot epoch (NVS in the example), and protected
  storage for the installation key (NVS encryption; flash encryption on
  devices others can physically reach).

---

## License

MIT License — see LICENSE file.
