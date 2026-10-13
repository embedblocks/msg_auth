# msg_auth sign_verify

A demonstration and acceptance test for the msg_auth component. It runs every accept and reject case of msg_auth in one task, on any ESP32 board, with **no Wi-Fi and no network**: msg_auth needs nothing but bytes, so a "channel" here is just a buffer passed from one context to another.

The app creates four contexts from the same key and purpose:

| Context | Node ID | Key | Role |
| --- | --- | --- | --- |
| A | 0 | test key | sender, epoch *e* |
| A′ | 0 | test key | the same node "after a reboot", epoch *e* + 1 |
| B | 1 | test key | the receiver in every scenario |
| outsider | 0 (claimed) | test key with one bit changed | a node outside the installation |

Node 2 exists only as an address, for the misaddressed case.

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
idf.py set-target esp32c3          # your chip
idf.py build flash monitor
```

The output, one line per scenario:

```
W (312) sign_verify: using the INSECURE example key from menuconfig; never ship it
I (322) sign_verify: epoch 7 (committed to NVS before create)
I (332) sign_verify: PASS A signs, B verifies                          got ESP_OK                       want ESP_OK
I (332) sign_verify: PASS bit flip: message                            got ESP_ERR_MSG_AUTH_BAD_TAG     want ESP_ERR_MSG_AUTH_BAD_TAG
...
I (452) sign_verify: PASS older epoch after msg_auth_reset_peer        got ESP_OK                       want ESP_OK
I (462) sign_verify: timing   64 B: sign  ... us, verify  ... us (mean of 200)
I (512) sign_verify: timing 1432 B: sign  ... us, verify  ... us (mean of 200)
I (512) sign_verify: B <- node 0: accepted 406, bad_tag 5, replay 2, last (8, 405)
I (512) sign_verify: B <- node 2: accepted 0, bad_tag 0, replay 0, last (0, 0), not seen
I (522) sign_verify: PASS: 19 passed, 0 failed
```

**Pass criterion:** the last line says `PASS` with 0 failed. The epoch rises by 2 on every boot; press reset a few times and check that it does.

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

Then the app times 200 sign/verify pairs at 64 and at 1432 bytes and prints B's statistics. The 5 bad tags for node 0 are the four bit flips that reach the MAC plus the outsider. The 2 replays are the repeated envelope and the older epoch.

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
| `main/sign_verify.c` | the app: contexts, scenarios, timing, statistics |
| `main/Kconfig.projbuild` | menuconfig option for the test key |
| `sdkconfig.defaults` | settings msg_auth relies on |
| `CMakeLists.txt` | finds msg_auth at `../..`; no network components |
