/*
 * msg_auth private header: pure functions (MSG_AUTH_SPEC.md §10).
 * No PSA, no RTOS, no state. Included by msg_auth.c and by the host tests.
 * Not part of the public API.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msg_auth.h"

#define MSG_AUTH_PROTO_VERSION  1
#define MSG_AUTH_MODE_AUTH      1       /* tag only                                  */
#define MSG_AUTH_MODE_AEAD      2       /* reserved; never accepted by this version  */

/* HKDF salt (§3): the 11 ASCII bytes "msg_auth v1", no terminating NUL. */
#define MSG_AUTH_HKDF_SALT      "msg_auth v1"
#define MSG_AUTH_HKDF_SALT_LEN  (sizeof MSG_AUTH_HKDF_SALT - 1)

/* Decoded envelope header (§3). */
typedef struct {
    uint8_t  version;
    uint8_t  mode;
    uint8_t  sender_id;
    uint8_t  receiver_id;
    uint32_t epoch;
    uint32_t counter;
    size_t   msg_len;           /* in_len - MSG_AUTH_OVERHEAD */
} msg_auth_hdr_t;

/* ---- wire format (§3) ---- */

void msg_auth_hdr_encode(uint8_t out[MSG_AUTH_HEADER_SIZE], uint8_t sender, uint8_t receiver,
                         uint32_t epoch, uint32_t counter);

/* Steps 1–2 of §5.4, in order:
 *   in_len > MSG_AUTH_MAX_ENVELOPE                  -> ESP_ERR_INVALID_SIZE
 *   in_len < MSG_AUTH_OVERHEAD, bad version or mode -> ESP_ERR_MSG_AUTH_MALFORMED
 * On ESP_OK fills *hdr. Never reads `in` beyond in_len, nor before the length checks. */
esp_err_t msg_auth_hdr_decode(const uint8_t *in, size_t in_len, msg_auth_hdr_t *hdr);

/* Steps 3–4 of §5.4: NOT_FOR_ME, then UNKNOWN. */
esp_err_t msg_auth_check_ids(const msg_auth_hdr_t *hdr, uint8_t my_id, uint8_t max_peer_id);

/* ---- freshness (§6) ---- */

/* true iff (e, c) > (last_e, last_c), compared lexicographically. */
bool msg_auth_is_newer(uint32_t e, uint32_t c, uint32_t last_e, uint32_t last_c);

/* ---- argument checks (§5) ---- */

/* 1..MSG_AUTH_PURPOSE_MAX bytes, each 0x21..0x7E; bounded scan. NULL -> false. */
bool msg_auth_purpose_valid(const char *purpose);

/* All argument checks of §5.1. */
esp_err_t msg_auth_check_create_args(const msg_auth_config_t *cfg, bool out_ok);

/* Checks 2–4 of §5.3 (null checks are done by the caller). */
esp_err_t msg_auth_check_sign_args(uint8_t receiver_id, uint8_t my_id, uint8_t max_peer_id,
                                   size_t msg_len, size_t out_cap);

/* Peer-ID check of §5.5 / §5.6: valid iff peer_id <= max_peer_id and != my_id. */
bool msg_auth_peer_id_ok(uint8_t peer_id, uint8_t my_id, uint8_t max_peer_id);

/* ---- constant-time compare (§8) ----
 * Fixed-length, no early exit: accumulates differences over all 16 bytes.
 * Used by the fallback path only when the build has no mbedtls_ct_memcmp(). */
bool msg_auth_ct_equal16(const uint8_t a[MSG_AUTH_TAG_SIZE], const uint8_t b[MSG_AUTH_TAG_SIZE]);

#ifdef MSG_AUTH_HOST_TEST
/* Test hooks, host builds only (T13). */
void msg_auth_test_set_counter(msg_auth_handle_t h, uint32_t counter);
bool msg_auth_test_fallback_path(void);
#endif
