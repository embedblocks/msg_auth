/*
 * msg_auth pure functions (MSG_AUTH_SPEC.md §10). No PSA, no RTOS, no state.
 */
#include <string.h>
#include "msg_auth_priv.h"

/* ---- big-endian helpers (§3) ---- */

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---- wire format (§3) ---- */

void msg_auth_hdr_encode(uint8_t out[MSG_AUTH_HEADER_SIZE], uint8_t sender, uint8_t receiver,
                         uint32_t epoch, uint32_t counter)
{
    out[0] = MSG_AUTH_PROTO_VERSION;
    out[1] = MSG_AUTH_MODE_AUTH;
    out[2] = sender;
    out[3] = receiver;
    wr32(&out[4], epoch);
    wr32(&out[8], counter);
}

esp_err_t msg_auth_hdr_decode(const uint8_t *in, size_t in_len, msg_auth_hdr_t *hdr)
{
    /* §5.4 step 1: size limit, before anything is read */
    if (in_len > MSG_AUTH_MAX_ENVELOPE) {
        return ESP_ERR_INVALID_SIZE;
    }
    /* §5.4 step 2: whole header and tag present; nothing below reads `in` before this */
    if (in_len < MSG_AUTH_OVERHEAD) {
        return ESP_ERR_MSG_AUTH_MALFORMED;
    }
    if (in[0] != MSG_AUTH_PROTO_VERSION || in[1] != MSG_AUTH_MODE_AUTH) {
        return ESP_ERR_MSG_AUTH_MALFORMED;      /* includes mode 2 (reserved) */
    }
    hdr->version     = in[0];
    hdr->mode        = in[1];
    hdr->sender_id   = in[2];
    hdr->receiver_id = in[3];
    hdr->epoch       = rd32(&in[4]);
    hdr->counter     = rd32(&in[8]);
    hdr->msg_len     = in_len - MSG_AUTH_OVERHEAD;
    return ESP_OK;
}

esp_err_t msg_auth_check_ids(const msg_auth_hdr_t *hdr, uint8_t my_id, uint8_t max_peer_id)
{
    /* §5.4 step 3: unauthenticated routing result */
    if (hdr->receiver_id != my_id) {
        return ESP_ERR_MSG_AUTH_NOT_FOR_ME;
    }
    /* §5.4 step 4 */
    if (hdr->sender_id > max_peer_id || hdr->sender_id == my_id) {
        return ESP_ERR_MSG_AUTH_UNKNOWN;
    }
    return ESP_OK;
}

/* ---- freshness (§6.1) ---- */

bool msg_auth_is_newer(uint32_t e, uint32_t c, uint32_t last_e, uint32_t last_c)
{
    if (e != last_e) {
        return e > last_e;
    }
    return c > last_c;
}

/* ---- argument checks (§5) ---- */

bool msg_auth_purpose_valid(const char *purpose)
{
    if (purpose == NULL) {
        return false;
    }
    /* bounded scan: never reads past byte MSG_AUTH_PURPOSE_MAX */
    const size_t n = strnlen(purpose, MSG_AUTH_PURPOSE_MAX + 1);
    if (n == 0 || n > MSG_AUTH_PURPOSE_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const uint8_t b = (uint8_t)purpose[i];
        if (b < 0x21 || b > 0x7E) {
            return false;
        }
    }
    return true;
}

esp_err_t msg_auth_check_create_args(const msg_auth_config_t *cfg, bool out_ok)
{
    if (cfg == NULL || !out_ok || cfg->key == NULL || cfg->purpose == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->key_len < MSG_AUTH_KEY_MIN || cfg->key_len > MSG_AUTH_KEY_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!msg_auth_purpose_valid(cfg->purpose)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->max_peer_id >= MSG_AUTH_MAX_PEERS || cfg->my_id > cfg->max_peer_id) {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

esp_err_t msg_auth_check_sign_args(uint8_t receiver_id, uint8_t my_id, uint8_t max_peer_id,
                                   size_t msg_len, size_t out_cap)
{
    if (receiver_id > max_peer_id || receiver_id == my_id) {
        return ESP_ERR_INVALID_ARG;
    }
    if (msg_len > MSG_AUTH_MAX_MESSAGE) {
        return ESP_ERR_INVALID_SIZE;
    }
    /* msg_len <= 1432 here, so the sum cannot overflow */
    if (out_cap < msg_len + MSG_AUTH_OVERHEAD) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}

bool msg_auth_peer_id_ok(uint8_t peer_id, uint8_t my_id, uint8_t max_peer_id)
{
    return peer_id <= max_peer_id && peer_id != my_id;
}

/* ---- constant-time compare (§8) ---- */

bool msg_auth_ct_equal16(const uint8_t a[MSG_AUTH_TAG_SIZE], const uint8_t b[MSG_AUTH_TAG_SIZE])
{
    const volatile uint8_t *va = a;
    const volatile uint8_t *vb = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < MSG_AUTH_TAG_SIZE; i++) {
        diff |= (uint8_t)(va[i] ^ vb[i]);
    }
    return diff == 0;
}
