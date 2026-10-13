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
