/*
 * msg_auth: per-message authentication with a pre-shared installation key.
 * Implements MSG_AUTH_SPEC.md; section references (§n) are to that file.
 *
 * Cryptography through the PSA Crypto API only (§9): HKDF-SHA256 straight into
 * a non-exportable volatile HMAC key, and one-shot psa_mac_compute /
 * psa_mac_verify calls on that key ID.
 */
#include <stdbool.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "psa/crypto.h"
#include "mbedtls/platform_util.h"

#include "msg_auth.h"
#include "msg_auth_priv.h"

#ifdef ESP_PLATFORM
#include "msg_auth_build_checks.h"
#endif

/* MAC path (§9). 0: primary, truncated-MAC key policy (§9.1).
 *                1: fallback, full HMAC key policy, truncated by msg_auth (§9.2).
 * Selected by the target checks of §9.3:  idf.py -DMSG_AUTH_MAC_FALLBACK=1 build */
#ifndef MSG_AUTH_MAC_FALLBACK
#define MSG_AUTH_MAC_FALLBACK 0
#endif

#if MSG_AUTH_MAC_FALLBACK
#define MSG_AUTH_KEY_ALG    PSA_ALG_HMAC(PSA_ALG_SHA_256)
#define MSG_AUTH_FULL_MAC   PSA_HASH_LENGTH(PSA_ALG_SHA_256)            /* 32 */
/* §8: prefer the library's verified constant-time compare when the build has it */
#if defined(__has_include)
#if __has_include("mbedtls/constant_time.h")
#include "mbedtls/constant_time.h"
#define MSG_AUTH_HAVE_CT_MEMCMP 1
#endif
#endif
#else
#define MSG_AUTH_KEY_ALG    PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), MSG_AUTH_TAG_SIZE)
#endif

#define MSG_AUTH_DERIVED_KEY_BITS   256

_Static_assert(MSG_AUTH_MAX_ENVELOPE == 1460, "envelope profile (§3)");
_Static_assert(MSG_AUTH_OVERHEAD == 28, "overhead (§3)");

static const char *TAG = "msg_auth";

/* ---- context (§5.1, §7) ---- */

struct msg_auth {
    psa_key_id_t          key;              /* volatile HMAC key; never exported      */
    StaticSemaphore_t     mutex_storage;
    SemaphoreHandle_t     mutex;
    uint8_t               my_id;
    uint8_t               max_peer_id;
    uint32_t              epoch;
    uint32_t              counter;          /* guarded by mutex                       */
    msg_auth_peer_stats_t peer[];           /* max_peer_id + 1 entries, guarded       */
};

static void lock(msg_auth_handle_t h)   { (void)xSemaphoreTake(h->mutex, portMAX_DELAY); }
static void unlock(msg_auth_handle_t h) { (void)xSemaphoreGive(h->mutex); }

/* ---- MAC (§9) ---- */

/* Tag over data[0..len) into tag[16]. ESP_OK or ESP_FAIL. */
static esp_err_t mac_sign(psa_key_id_t key, const uint8_t *data, size_t len,
                          uint8_t tag[MSG_AUTH_TAG_SIZE])
{
#if MSG_AUTH_MAC_FALLBACK
    uint8_t full[MSG_AUTH_FULL_MAC];
    size_t  n = 0;
    psa_status_t st = psa_mac_compute(key, MSG_AUTH_KEY_ALG, data, len, full, sizeof full, &n);
    esp_err_t err = ESP_FAIL;
    if (st == PSA_SUCCESS && n == sizeof full) {
        memcpy(tag, full, MSG_AUTH_TAG_SIZE);
        err = ESP_OK;
    }
    mbedtls_platform_zeroize(full, sizeof full);
    return err;
#else
    size_t n = 0;
    psa_status_t st = psa_mac_compute(key, MSG_AUTH_KEY_ALG, data, len,
                                      tag, MSG_AUTH_TAG_SIZE, &n);
    return (st == PSA_SUCCESS && n == MSG_AUTH_TAG_SIZE) ? ESP_OK : ESP_FAIL;
#endif
}

/* ESP_OK on match, ESP_ERR_MSG_AUTH_BAD_TAG on mismatch, ESP_FAIL on any crypto error. */
static esp_err_t mac_verify(psa_key_id_t key, const uint8_t *data, size_t len,
                            const uint8_t tag[MSG_AUTH_TAG_SIZE])
{
#if MSG_AUTH_MAC_FALLBACK
    uint8_t full[MSG_AUTH_FULL_MAC];
    size_t  n = 0;
    psa_status_t st = psa_mac_compute(key, MSG_AUTH_KEY_ALG, data, len, full, sizeof full, &n);
    esp_err_t err = ESP_FAIL;
    if (st == PSA_SUCCESS && n == sizeof full) {
#if MSG_AUTH_HAVE_CT_MEMCMP
        const bool equal = mbedtls_ct_memcmp(full, tag, MSG_AUTH_TAG_SIZE) == 0;
#else
        const bool equal = msg_auth_ct_equal16(full, tag);
#endif
        err = equal ? ESP_OK : ESP_ERR_MSG_AUTH_BAD_TAG;
    }
    mbedtls_platform_zeroize(full, sizeof full);
    return err;
#else
    psa_status_t st = psa_mac_verify(key, MSG_AUTH_KEY_ALG, data, len, tag, MSG_AUTH_TAG_SIZE);
    if (st == PSA_SUCCESS) {
        return ESP_OK;
    }
    if (st == PSA_ERROR_INVALID_SIGNATURE) {
        return ESP_ERR_MSG_AUTH_BAD_TAG;
    }
    return ESP_FAIL;            /* a crypto failure is never an authentication result */
#endif
}

/* HKDF (§3) directly into a PSA key object (§5.1 step 5).
 *
 * PSA permits psa_key_derivation_output_key() only when the secret was supplied
 * as a key (psa_key_derivation_input_key), never as raw bytes, so that raw input
 * cannot be laundered into a key with a different policy. The installation key is
 * therefore imported as a volatile DERIVE key, usable only for this HKDF, and
 * destroyed as soon as derivation ends, on every path (PSA wipes its copy). */
static psa_status_t derive_key(const msg_auth_config_t *cfg, size_t purpose_len,
                               psa_key_id_t *key)
{
    psa_key_attributes_t in_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&in_attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_lifetime(&in_attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&in_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&in_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    psa_key_attributes_t out_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&out_attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&out_attr, MSG_AUTH_DERIVED_KEY_BITS);
    psa_set_key_lifetime(&out_attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&out_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&out_attr, MSG_AUTH_KEY_ALG);

    psa_key_id_t ikm = PSA_KEY_ID_NULL;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    psa_status_t st = psa_import_key(&in_attr, cfg->key, cfg->key_len, &ikm);
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            (const uint8_t *)MSG_AUTH_HKDF_SALT,
                                            MSG_AUTH_HKDF_SALT_LEN);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            (const uint8_t *)cfg->purpose, purpose_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_key(&out_attr, &op, key);
    }
    (void)psa_key_derivation_abort(&op);    /* in all cases (§5.1) */
    if (ikm != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(ikm);         /* the installation key leaves PSA at once */
    }
    psa_reset_key_attributes(&in_attr);
    psa_reset_key_attributes(&out_attr);
    return st;
}

/* ---- msg_auth_create (§5.1) ---- */

esp_err_t msg_auth_create(const msg_auth_config_t *cfg, msg_auth_handle_t *out)
{
    if (out != NULL) {
        *out = NULL;                                            /* step 1 */
    }
    esp_err_t err = msg_auth_check_create_args(cfg, out != NULL);
    if (err != ESP_OK) {
        return err;
    }

    psa_status_t st = psa_crypto_init();                        /* step 2: idempotent */
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init: %d", (int)st);
        return ESP_FAIL;
    }

    const size_t size = sizeof(struct msg_auth)                 /* step 3 */
                      + ((size_t)cfg->max_peer_id + 1) * sizeof(msg_auth_peer_stats_t);
    msg_auth_handle_t h = heap_caps_calloc(1, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (h == NULL) {
        return ESP_ERR_NO_MEM;
    }
    h->key = PSA_KEY_ID_NULL;

    h->mutex = xSemaphoreCreateMutexStatic(&h->mutex_storage);  /* step 4 */
    if (h->mutex == NULL) {
        err = ESP_FAIL;
        goto fail;
    }

    const size_t purpose_len = strnlen(cfg->purpose, MSG_AUTH_PURPOSE_MAX + 1);
    st = derive_key(cfg, purpose_len, &h->key);                 /* step 5 */
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "key derivation: %d", (int)st);
        err = ESP_FAIL;
        goto fail;
    }

    h->my_id       = cfg->my_id;                                /* step 6 */
    h->max_peer_id = cfg->max_peer_id;
    h->epoch       = cfg->epoch;
    h->counter     = 0;                                         /* peers zeroed by calloc */

    *out = h;                                                   /* step 7 */
    return ESP_OK;

fail:                                                           /* single cleanup path */
    if (h->key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(h->key);
    }
    if (h->mutex != NULL) {
        vSemaphoreDelete(h->mutex);
    }
    mbedtls_platform_zeroize(h, size);
    heap_caps_free(h);
    return err;
}

/* ---- msg_auth_delete (§5.2) ---- */

esp_err_t msg_auth_delete(msg_auth_handle_t h)
{
    if (h == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const size_t size = sizeof *h + ((size_t)h->max_peer_id + 1) * sizeof h->peer[0];
    (void)psa_destroy_key(h->key);
    vSemaphoreDelete(h->mutex);
    mbedtls_platform_zeroize(h, size);
    heap_caps_free(h);
    return ESP_OK;
}

/* ---- msg_auth_sign (§5.3) ---- */

esp_err_t msg_auth_sign(msg_auth_handle_t h, uint8_t receiver_id,
                        const void *msg, size_t msg_len,
                        void *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) {
        *out_len = 0;
    }
    /* check 1 */
    if (h == NULL || out == NULL || out_len == NULL || (msg == NULL && msg_len > 0)) {
        return ESP_ERR_INVALID_ARG;
    }
    /* checks 2-4 */
    esp_err_t err = msg_auth_check_sign_args(receiver_id, h->my_id, h->max_peer_id,
                                             msg_len, out_cap);
    if (err != ESP_OK) {
        return err;
    }

    /* step 1: reserve the counter before computing the tag */
    lock(h);
    if (h->counter == UINT32_MAX) {
        unlock(h);
        return ESP_ERR_MSG_AUTH_EXHAUSTED;
    }
    const uint32_t c = h->counter;
    h->counter = c + 1;
    unlock(h);

    /* step 2 */
    uint8_t *env = out;
    msg_auth_hdr_encode(env, h->my_id, receiver_id, h->epoch, c);
    if (msg_len > 0) {
        memcpy(env + MSG_AUTH_HEADER_SIZE, msg, msg_len);
    }

    /* steps 3-4: on failure the reserved counter value is not reused */
    const size_t signed_len = MSG_AUTH_HEADER_SIZE + msg_len;
    if (mac_sign(h->key, env, signed_len, env + signed_len) != ESP_OK) {
        return ESP_FAIL;                                    /* *out_len already 0 */
    }

    *out_len = msg_len + MSG_AUTH_OVERHEAD;                 /* step 5 */
    return ESP_OK;
}

/* ---- msg_auth_verify (§5.4) ---- */

esp_err_t msg_auth_verify(msg_auth_handle_t h,
                          const void *in, size_t in_len,
                          uint8_t *sender_id,
                          const void **msg, size_t *msg_len)
{
    /* step 0 */
    if (h == NULL || in == NULL || sender_id == NULL || msg == NULL || msg_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint8_t *env = in;

    /* steps 1-2 */
    msg_auth_hdr_t hdr;
    esp_err_t err = msg_auth_hdr_decode(env, in_len, &hdr);
    if (err != ESP_OK) {
        return err;
    }
    /* steps 3-4 */
    err = msg_auth_check_ids(&hdr, h->my_id, h->max_peer_id);
    if (err != ESP_OK) {
        return err;
    }
    *sender_id = hdr.sender_id;

    /* step 5: tag first, outside the mutex. Freshness is not read or changed yet. */
    const size_t signed_len = in_len - MSG_AUTH_TAG_SIZE;
    msg_auth_peer_stats_t *p = &h->peer[hdr.sender_id];
    err = mac_verify(h->key, env, signed_len, env + signed_len);
    if (err == ESP_ERR_MSG_AUTH_BAD_TAG) {
        lock(h);
        p->bad_tag++;
        unlock(h);
        return err;
    }
    if (err != ESP_OK) {
        return ESP_FAIL;            /* crypto failure: no stats, no freshness change */
    }

    /* steps 6-7: one critical section */
    lock(h);
    if (p->seen && !msg_auth_is_newer(hdr.epoch, hdr.counter, p->last_epoch, p->last_counter)) {
        p->replay++;
        unlock(h);
        return ESP_ERR_MSG_AUTH_REPLAY;
    }
    p->last_epoch   = hdr.epoch;
    p->last_counter = hdr.counter;
    p->seen         = 1;
    p->accepted++;
    unlock(h);

    *msg     = env + MSG_AUTH_HEADER_SIZE;      /* borrowed: points into `in` */
    *msg_len = hdr.msg_len;
    return ESP_OK;
}

/* ---- msg_auth_reset_peer (§5.5) ---- */

esp_err_t msg_auth_reset_peer(msg_auth_handle_t h, uint8_t peer_id)
{
    if (h == NULL || !msg_auth_peer_id_ok(peer_id, h->my_id, h->max_peer_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    lock(h);
    h->peer[peer_id].seen = 0;                  /* stats kept */
    unlock(h);
    return ESP_OK;
}

/* ---- msg_auth_get_peer_stats (§5.6) ---- */

esp_err_t msg_auth_get_peer_stats(msg_auth_handle_t h, uint8_t peer_id,
                                  msg_auth_peer_stats_t *stats)
{
    if (h == NULL || stats == NULL || !msg_auth_peer_id_ok(peer_id, h->my_id, h->max_peer_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    lock(h);
    *stats = h->peer[peer_id];
    unlock(h);
    return ESP_OK;
}

/* ---- msg_auth_err_to_name (§5.7) ---- */

const char *msg_auth_err_to_name(esp_err_t err)
{
    switch (err) {
    case ESP_ERR_MSG_AUTH_MALFORMED:  return "ESP_ERR_MSG_AUTH_MALFORMED";
    case ESP_ERR_MSG_AUTH_NOT_FOR_ME: return "ESP_ERR_MSG_AUTH_NOT_FOR_ME";
    case ESP_ERR_MSG_AUTH_UNKNOWN:    return "ESP_ERR_MSG_AUTH_UNKNOWN";
    case ESP_ERR_MSG_AUTH_BAD_TAG:    return "ESP_ERR_MSG_AUTH_BAD_TAG";
    case ESP_ERR_MSG_AUTH_REPLAY:     return "ESP_ERR_MSG_AUTH_REPLAY";
    case ESP_ERR_MSG_AUTH_EXHAUSTED:  return "ESP_ERR_MSG_AUTH_EXHAUSTED";
    default:                          return esp_err_to_name(err);
    }
}

/* ---- host test hooks ---- */

#ifdef MSG_AUTH_HOST_TEST
void msg_auth_test_set_counter(msg_auth_handle_t h, uint32_t counter)
{
    lock(h);
    h->counter = counter;
    unlock(h);
}

bool msg_auth_test_fallback_path(void)
{
    return MSG_AUTH_MAC_FALLBACK;
}
#endif
