# msg_auth sign_verify

A demonstration and acceptance test for the msg_auth component. It runs every accept and reject case of msg_auth in one task, on any ESP32 board, with **no Wi-Fi and no network**: msg_auth needs nothing but bytes, so a "channel" here is just a buffer passed from one context to another. It then measures everything `MSG_AUTH_SPEC.md` §9.3 asks for on the target and prints it as one block.

The app creates five contexts from the same purpose:

| Context | Node ID | Key | Role |
| --- | --- | --- | --- |
| A | 0 | test key | sender, epoch *e* |
| A′ | 0 | test key | the same node "after a reboot", epoch *e* + 1 |
| B | 1 | test key | the receiver in every scenario |
| C | 2 | test key | a second genuine sender, for the wrong-link case |
| outsider | 0 (claimed) | test key with one bit changed | a node outside the installation |

## Requirements

- ESP-IDF **6.0.x**. msg_auth's build checks and its manifest reject other releases.
- The msg_auth component folder must be named `msg_auth`, because ESP-IDF names a component after its folder. The example finds it two levels up (`../..`, set in this folder's `CMakeLists.txt`).

`sdkconfig.defaults` sets what msg_auth needs. These are ESP-IDF's defaults anyway; they are listed so a changed global configuration can't silently remove them:

```
CONFIG_MBEDTLS_THREADING_C=y
CONFIG_MBEDTLS_SHA256_C=y
CONFIG_ESP_MAIN_TASK_STACK_SIZE=4096
```

## Run

```sh
cd examples/sign_verify
idf.py set-target esp32            # your chip
idf.py build flash monitor
```

To test the fallback MAC path (`MSG_AUTH_SPEC.md` §9.2) as well:

```sh
idf.py -B build-fallback -DMSG_AUTH_MAC_FALLBACK=1 build flash monitor
```

No board at hand? `idf.py qemu` runs the ESP32 build in Espressif's emulator (install it with `python $IDF_PATH/tools/idf_tools.py install qemu-xtensa`). The PASS/FAIL results, heap and stack figures are meaningful there; the latencies are not.

The output (from ESP32 in QEMU, ESP-IDF v6.0.3; latencies omitted because emulated timings mean nothing):

```
W (2906) sign_verify: using the INSECURE example key from menuconfig; never ship it
I (3806) sign_verify: epoch 1 (committed to NVS before create)
I (3816) sign_verify: PASS A signs, B verifies                           got ESP_OK                        want ESP_OK
I (3826) sign_verify: PASS bit flip: message                             got ESP_ERR_MSG_AUTH_BAD_TAG      want ESP_ERR_MSG_AUTH_BAD_TAG
...
I (3846) sign_verify: PASS verify_from: C's envelope relayed to A's link got ESP_ERR_MSG_AUTH_WRONG_SENDER want ESP_ERR_MSG_AUTH_WRONG_SENDER
I (3846) sign_verify: PASS verify_from: C's state untouched by relay     got ESP_OK                        want ESP_OK
I (3846) sign_verify: PASS verify_from: C's own copy still accepted      got ESP_OK                        want ESP_OK
...
I (3846) sign_verify: B <- node 0: accepted 7, bad_tag (claimed) 5, replay 2, last (2, 1)
I (3846) sign_verify: B <- node 2: accepted 2, bad_tag (claimed) 0, replay 0, last (1, 1)
I (3846) sign_verify: B context: bad_tag_total 5, wrong_sender 1
I (3846) target_checks: ---- MSG_AUTH_SPEC.md §9.3 record: copy the "9.3 |" lines ----
I (3846) target_checks: 9.3 | ESP-IDF v6.0.3, target esp32, 2 core(s)
I (3846) target_checks: 9.3 | MAC path: primary (§9.1, truncated-MAC key policy)
I (3846) target_checks: 9.3 | HMAC driver: ESP transparent HMAC driver on the SHA accelerator (CONFIG_MBEDTLS_HARDWARE_SHA=y)
I (3846) target_checks: 9.3 | HMAC peripheral: not present on this chip
I (3846) target_checks: 9.3 | Mbed TLS threading: on
I (3846) target_checks: 9.3 | HKDF into an HMAC key (DERIVE-key import, §5.1 step 5): works (msg_auth_create succeeded)
I (3846) target_checks: 9.3 | truncated-MAC policy: accepted (contexts created with it; sign/verify scenarios pass)
I (4306) sign_verify: PASS concurrent sign + verify on one key ID        got ESP_OK                        want ESP_OK
I (4306) target_checks: 9.3 | concurrency, one key ID, 4 tasks (2 sign, 2 verify_from), 800 calls in ... us: PASS (call failures 0, duplicate counters 0, rejected by receiver 0, stats exact)
I (4306) sign_verify: PASS psa_crypto_init when already initialised      got ESP_OK                        want ESP_OK
I (4306) target_checks: 9.3 | psa_crypto_init() when already initialised: 0 (PSA_SUCCESS); failure handling: host test T21
I (4306) target_checks: 9.3 | heap, create (max_peer_id 2): 224 bytes; after delete: 0 bytes not returned
I (4326) target_checks: 9.3 | heap, sign        (64 B, 32 calls): peak 280 bytes during a call, net 0 bytes
I (4366) target_checks: 9.3 | heap, verify      (64 B, 32 calls): peak 280 bytes during a call, net 0 bytes
I (4396) target_checks: 9.3 | heap, verify_from (64 B, 32 calls): peak 280 bytes during a call, net 0 bytes
I (4396) target_checks: 9.3 | stack, sign        (1432 B): 816 bytes
I (4396) target_checks: 9.3 | stack, verify      (1432 B): 880 bytes
I (4396) target_checks: 9.3 | stack, verify_from (1432 B): 880 bytes
I (4516) target_checks: 9.3 | latency    0 B: sign  ... us, verify  ... us, verify_from  ... us (mean of 100)
...
I (5146) target_checks: 9.3 | latency 1432 B: sign  ... us, verify  ... us, verify_from  ... us (mean of 100)
I (5146) target_checks: ---- end of §9.3 record ----
I (5146) sign_verify: PASS: 27 passed, 0 failed
```

**Pass criterion:** the last line says `PASS` with 0 failed. The epoch rises by 2 on every boot; press reset a few times and check that it does.

**Recording §9.3:** copy every line containing `9.3 |` into `MSG_AUTH_SPEC.md` §9.3 (hardware column) and update the chip table in the component README. Run it once per chip and per MAC path you ship.

## Scenarios

| Scenario | Expected |
| --- | --- |
| A signs, B verifies | `ESP_OK`, message and sender ID intact |
| One bit flipped in the message, the counter, the epoch or the tag | `BAD_TAG` |
| One bit flipped in the receiver ID | `NOT_FOR_ME` |
| One bit flipped in the version | `MALFORMED` |
| The unflipped original after all the flips | `ESP_OK`: no forgery moved B's state |
| Outsider signs, B verifies | `BAD_TAG` |
| Same envelope verified twice | `ESP_OK`, then `REPLAY` |
| Envelope for node 2 given to B | `NOT_FOR_ME` |
| 1461 bytes / 27 bytes / plain unsigned bytes | `INVALID_SIZE` / `MALFORMED` / `MALFORMED` |
| The largest envelope, 1460 bytes | `ESP_OK` |
| A′ (epoch + 1, counter back to 0) | `ESP_OK` |
| A again (older epoch) | `REPLAY`; after `msg_auth_reset_peer` `ESP_OK` |
| `verify_from`: A′'s envelope on A's link | `ESP_OK`, and `info.epoch` is A′'s epoch |
| `verify_from`: C's envelope on C's link | `ESP_OK` |
| `verify_from`: C's next envelope relayed onto A's link | `WRONG_SENDER`; C's statistics and state unchanged |
| `verify_from`: that same envelope on C's link | `ESP_OK`: the relay cost C nothing |
| `verify_from` with B's own ID as the expected sender | `INVALID_ARG` |
| Concurrent sign and `verify_from` on B's context (one key ID), 4 tasks | all results correct, counters distinct, statistics exact |
| `psa_crypto_init()` again | `PSA_SUCCESS` |

Then the app prints B's statistics. The 5 bad tags claiming node 0 are the four bit flips that reach the MAC plus the outsider; `bad_tag_total` agrees because no forgery claimed anyone else. The 2 replays are the repeated envelope and the older epoch. `wrong_sender` 1 is the relayed envelope.

## The §9.3 record

`main/target_checks.c` measures, in this order:

| Line | How |
| --- | --- |
| ESP-IDF, chip, cores, MAC path, HMAC driver, threading | from the build configuration |
| HKDF / truncated-MAC policy | the contexts were created with that policy and the scenarios passed |
| Concurrency, one key ID | 2 tasks sign with B while 2 tasks verify A's and C's streams on B with `verify_from` (every 8th envelope corrupted); A then verifies all of B's envelopes in counter order; B's statistics must match exactly |
| `psa_crypto_init()` | called again after start-up |
| Heap, create | free heap before `msg_auth_create()`, after it, and after `msg_auth_delete()` |
| Heap, per call | free heap and the lowest free heap (`heap_caps_monitor_local_minimum_free_size_start`) over 32 calls: *peak* is the most heap a call held at once, *net* is what was not returned. msg_auth allocates nothing; the peak is PSA's HMAC driver |
| Stack, per call | change of the stack high-water mark when one call (1432-byte message) runs in a fresh task |
| Latency | mean of 100 calls each, at 0, 64, 512 and 1432 bytes, with `esp_timer` |

## How the epoch is handled

`reserve_epochs()` is how a real application should meet the epoch contract (`MSG_AUTH_SPEC.md` §6.2):

1. read the boot counter from NVS;
2. write the incremented value and **commit** it;
3. only then create the contexts. Any NVS error stops the app before a context exists: it never signs under an epoch that might be reused.

This app reserves **two** epochs per boot because it also plays A′, a rebooted A. A normal application reserves one.

Erasing flash (`idf.py erase-flash`) resets the counter. That is the recovery case: receivers that remember the node reject its messages as `REPLAY` until they call `msg_auth_reset_peer()` for it. In this example nothing remembers between boots, because B's state is in RAM too.

## The test key

`EXAMPLE_PSK_HEX` in menuconfig (**msg_auth sign_verify example**) holds the installation key as 32–128 hex digits. The default is public and **insecure**. A real installation provisions a random key per installation and keeps it in encrypted NVS.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `#error "msg_auth: verified on ESP-IDF 6.0.x only"` | Wrong ESP-IDF release. |
| `#error "msg_auth: requires ..."` | A PSA algorithm or Mbed TLS threading was disabled in menuconfig (Component config → mbedTLS). Re-enable it, or run `idf.py fullclean` after restoring `sdkconfig.defaults`. |
| `Failed to resolve component 'msg_auth'` | The component folder is not named `msg_auth`, or it is not at `../..` relative to this folder. |
| `msg_auth_create` aborts with `ESP_FAIL` and the log shows `key derivation: <n>` | The target's PSA rejected the key policy. Rebuild with `idf.py -DMSG_AUTH_MAC_FALLBACK=1 fullclean build` and record the result in `MSG_AUTH_SPEC.md` §9.3. |
| `EXAMPLE_PSK_HEX must be 32..128 hex digits` | The menuconfig key is too short, has an odd number of digits, or contains non-hex characters. |

## Files

| File | What |
| --- | --- |
| `main/sign_verify.c` | the app: contexts, scenarios, statistics |
| `main/target_checks.c` | the §9.3 measurements |
| `main/example.h` | shared between the two |
| `main/Kconfig.projbuild` | menuconfig option for the test key |
| `sdkconfig.defaults` | settings msg_auth relies on |
| `CMakeLists.txt` | finds msg_auth at `../..`; no network components |
