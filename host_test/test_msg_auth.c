/*
 * msg_auth host tests: T1–T33 of MSG_AUTH_SPEC.md §10, plus the pure functions.
 * T1–T25 are unchanged from 0.1.0; T26–T33 cover msg_auth_verify_from() and
 * msg_auth_get_stats() (0.2.0).
 *
 * Runs msg_auth.c unchanged against the real PSA Crypto library (TF-PSA-Crypto,
 * as shipped in Mbed TLS 4.x), with FreeRTOS mapped onto pthreads and fault
 * injection through shims/. Build and run with `make` (see Makefile).
 */
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"
#include "msg_auth.h"
#include "msg_auth_priv.h"
#include "shims.h"
#include "fixtures/msg_auth_kat.h"

/* ---- minimal harness ---- */

static int s_checks, s_failed;
static const char *s_test = "";

#define CHECK(cond) do { s_checks++; if (!(cond)) { s_failed++; \
    fprintf(stderr, "FAIL %s %s:%d: %s\n", s_test, __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_ERR(got, want) do { esp_err_t g_ = (got), w_ = (want); s_checks++; if (g_ != w_) { s_failed++; \
    fprintf(stderr, "FAIL %s %s:%d: %s = %s, want %s\n", s_test, __FILE__, __LINE__, #got, \
            msg_auth_err_to_name(g_), msg_auth_err_to_name(w_)); } } while (0)
#define TEST(name) static void name(void)
#define RUN(name) do { s_test = #name; int f0 = s_failed; name(); \
    printf("%-44s %s\n", #name, s_failed == f0 ? "ok" : "FAILED"); } while (0)

/* ---- helpers ---- */

#define PURPOSE  "status"
#define MAX_ID   3                   /* nodes 0..3 */
#define ID_A     0
#define ID_B     1

static uint8_t s_key[32];

static msg_auth_handle_t make_ex(const uint8_t *key, size_t key_len, const char *purpose,
                                 uint8_t my_id, uint8_t max_id, uint32_t epoch)
{
    const msg_auth_config_t cfg = {
        .key = key, .key_len = key_len, .purpose = purpose,
        .my_id = my_id, .max_peer_id = max_id, .epoch = epoch,
    };
    msg_auth_handle_t h = NULL;
    esp_err_t err = msg_auth_create(&cfg, &h);
    if (err != ESP_OK) {
        fprintf(stderr, "msg_auth_create: %s\n", msg_auth_err_to_name(err));
        abort();
    }
    return h;
}

static msg_auth_handle_t make(uint8_t my_id, uint32_t epoch)
{
    return make_ex(s_key, sizeof s_key, PURPOSE, my_id, MAX_ID, epoch);
}

typedef struct {
    uint8_t buf[MSG_AUTH_MAX_ENVELOPE + 8];
    size_t  len;
} env_t;

static env_t sign(msg_auth_handle_t h, uint8_t to, const void *msg, size_t len)
{
    env_t e = { .len = 0 };
    esp_err_t err = msg_auth_sign(h, to, msg, len, e.buf, sizeof e.buf, &e.len);
    if (err != ESP_OK) {
        fprintf(stderr, "msg_auth_sign: %s\n", msg_auth_err_to_name(err));
        abort();
    }
    return e;
}

static esp_err_t verify(msg_auth_handle_t h, const env_t *e)
{
    uint8_t sender; const void *m; size_t n;
    return msg_auth_verify(h, e->buf, e->len, &sender, &m, &n);
}

static uint32_t env_counter(const env_t *e)
{
    return ((uint32_t)e->buf[8] << 24) | ((uint32_t)e->buf[9] << 16) |
           ((uint32_t)e->buf[10] << 8) | e->buf[11];
}

static msg_auth_peer_stats_t stats(msg_auth_handle_t h, uint8_t peer)
{
    msg_auth_peer_stats_t s;
    esp_err_t err = msg_auth_get_peer_stats(h, peer, &s);
    if (err != ESP_OK) abort();
    return s;
}

/* Builds a correctly tagged envelope by hand, with the KAT-derived key. */
static env_t craft(const uint8_t dk[32], uint8_t version, uint8_t mode, uint8_t s, uint8_t r,
                   uint32_t epoch, uint32_t counter, const void *msg, size_t len)
{
    env_t e = { .len = len + MSG_AUTH_OVERHEAD };
    msg_auth_hdr_encode(e.buf, s, r, epoch, counter);
    e.buf[0] = version;
    e.buf[1] = mode;
    memcpy(e.buf + MSG_AUTH_HEADER_SIZE, msg, len);

    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&a, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_key_id_t k;
    if (psa_import_key(&a, dk, 32, &k) != PSA_SUCCESS) abort();
    uint8_t full[32]; size_t n;
    if (psa_mac_compute(k, PSA_ALG_HMAC(PSA_ALG_SHA_256), e.buf, MSG_AUTH_HEADER_SIZE + len,
                        full, sizeof full, &n) != PSA_SUCCESS) abort();
    psa_destroy_key(k);
    memcpy(e.buf + MSG_AUTH_HEADER_SIZE + len, full, MSG_AUTH_TAG_SIZE);
    return e;
}

/* ================= pure functions ================= */

TEST(pure_header_roundtrip)
{
    uint8_t b[MSG_AUTH_OVERHEAD + 5] = {0};
    msg_auth_hdr_encode(b, 7, 9, 0x01020304, 0xA0B0C0D0);
    const uint8_t want[12] = {1, 1, 7, 9, 1, 2, 3, 4, 0xA0, 0xB0, 0xC0, 0xD0};
    CHECK(memcmp(b, want, 12) == 0);
    msg_auth_hdr_t h;
    CHECK_ERR(msg_auth_hdr_decode(b, sizeof b, &h), ESP_OK);
    CHECK(h.sender_id == 7 && h.receiver_id == 9 && h.epoch == 0x01020304 &&
          h.counter == 0xA0B0C0D0 && h.msg_len == 5);
    CHECK_ERR(msg_auth_hdr_decode(b, MSG_AUTH_MAX_ENVELOPE + 1, &h), ESP_ERR_INVALID_SIZE);
    CHECK_ERR(msg_auth_hdr_decode(b, MSG_AUTH_OVERHEAD - 1, &h), ESP_ERR_MSG_AUTH_MALFORMED);
}

TEST(pure_is_newer)
{
    CHECK(!msg_auth_is_newer(5, 5, 5, 5));
    CHECK(msg_auth_is_newer(5, 6, 5, 5));
    CHECK(!msg_auth_is_newer(5, 4, 5, 5));
    CHECK(msg_auth_is_newer(6, 0, 5, UINT32_MAX));
    CHECK(!msg_auth_is_newer(4, UINT32_MAX, 5, 0));
    CHECK(msg_auth_is_newer(UINT32_MAX, 0, UINT32_MAX - 1, UINT32_MAX - 1));
    CHECK(!msg_auth_is_newer(0, 0, UINT32_MAX, 0));     /* no wrap-around comparison */
}

TEST(pure_ct_equal16)
{
    uint8_t a[16], b[16];
    for (int i = 0; i < 16; i++) a[i] = b[i] = (uint8_t)(i * 13);
    CHECK(msg_auth_ct_equal16(a, b));
    for (int i = 0; i < 16; i++) {
        for (int bit = 0; bit < 8; bit++) {
            b[i] ^= (uint8_t)(1u << bit);
            CHECK(!msg_auth_ct_equal16(a, b));
            b[i] ^= (uint8_t)(1u << bit);
        }
    }
}

/* ================= T1–T25 ================= */

TEST(t01_roundtrip)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    static uint8_t msg[MSG_AUTH_MAX_MESSAGE];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 7 + 3);
    const size_t lens[] = {0, 1, 100, MSG_AUTH_MAX_MESSAGE};
    for (size_t i = 0; i < 4; i++) {
        env_t e = sign(a, ID_B, lens[i] ? msg : NULL, lens[i]);
        CHECK(e.len == lens[i] + MSG_AUTH_OVERHEAD);
        uint8_t sender = 0xEE; const void *m = NULL; size_t n = 99999;
        CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &sender, &m, &n), ESP_OK);
        CHECK(sender == ID_A);
        CHECK(n == lens[i]);
        CHECK(m == e.buf + MSG_AUTH_HEADER_SIZE);           /* borrowed, zero copy */
        CHECK(n == 0 || memcmp(m, msg, n) == 0);
    }
    CHECK(stats(b, ID_A).accepted == 4);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t02_bit_flips)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    const char msg[] = "flip me";
    env_t e = sign(a, ID_B, msg, sizeof msg);
    for (size_t off = 0; off < e.len; off++) {
        for (int bit = 0; bit < 8; bit++) {
            env_t f = e;
            f.buf[off] ^= (uint8_t)(1u << bit);
            esp_err_t want = ESP_ERR_MSG_AUTH_BAD_TAG;
            if (off == 0 || off == 1) {
                want = ESP_ERR_MSG_AUTH_MALFORMED;
            } else if (off == 3) {
                want = ESP_ERR_MSG_AUTH_NOT_FOR_ME;
            } else if (off == 2 && (f.buf[2] > MAX_ID || f.buf[2] == ID_B)) {
                want = ESP_ERR_MSG_AUTH_UNKNOWN;
            }
            CHECK_ERR(verify(b, &f), want);
        }
    }
    CHECK_ERR(verify(b, &e), ESP_OK);           /* none of that advanced freshness */
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t03_wrong_key_or_purpose)
{
    uint8_t other[32];
    memcpy(other, s_key, sizeof other);
    other[31] ^= 1;
    msg_auth_handle_t b  = make(ID_B, 1);
    msg_auth_handle_t xk = make_ex(other, sizeof other, PURPOSE, ID_A, MAX_ID, 1);
    msg_auth_handle_t xp = make_ex(s_key, sizeof s_key, "doorbell", ID_A, MAX_ID, 1);
    env_t e1 = sign(xk, ID_B, "hi", 2);
    env_t e2 = sign(xp, ID_B, "hi", 2);
    CHECK_ERR(verify(b, &e1), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK_ERR(verify(b, &e2), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK(stats(b, ID_A).bad_tag == 2 && stats(b, ID_A).seen == 0);
    msg_auth_delete(b); msg_auth_delete(xk); msg_auth_delete(xp);
}

TEST(t04_replay_same_envelope)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    env_t e = sign(a, ID_B, "x", 1);
    CHECK_ERR(verify(b, &e), ESP_OK);
    CHECK_ERR(verify(b, &e), ESP_ERR_MSG_AUTH_REPLAY);
    msg_auth_peer_stats_t s = stats(b, ID_A);
    CHECK(s.accepted == 1 && s.replay == 1);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t05_older_counter_and_gaps)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    env_t e[6];
    for (int i = 0; i < 6; i++) e[i] = sign(a, ID_B, "x", 1);
    CHECK_ERR(verify(b, &e[0]), ESP_OK);
    CHECK_ERR(verify(b, &e[3]), ESP_OK);        /* gap: 1 and 2 skipped */
    CHECK_ERR(verify(b, &e[2]), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK_ERR(verify(b, &e[5]), ESP_OK);
    CHECK_ERR(verify(b, &e[4]), ESP_ERR_MSG_AUTH_REPLAY);
    msg_auth_peer_stats_t s = stats(b, ID_A);
    CHECK(s.last_epoch == 1 && s.last_counter == 5);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t06_new_epoch_counter_zero)
{
    msg_auth_handle_t a1 = make(ID_A, 10), b = make(ID_B, 1);
    msg_auth_test_set_counter(a1, 0xFFFF0000u);
    env_t old = sign(a1, ID_B, "old", 3);
    CHECK_ERR(verify(b, &old), ESP_OK);
    msg_auth_handle_t a2 = make(ID_A, 11);      /* reboot: higher epoch, counter 0 */
    env_t e = sign(a2, ID_B, "new", 3);
    CHECK(env_counter(&e) == 0);
    CHECK_ERR(verify(b, &e), ESP_OK);
    msg_auth_delete(a1); msg_auth_delete(a2); msg_auth_delete(b);
}

TEST(t07_lower_epoch_then_reset)
{
    msg_auth_handle_t hi = make(ID_A, 20), lo = make(ID_A, 3), b = make(ID_B, 1);
    env_t e1 = sign(hi, ID_B, "a", 1);
    CHECK_ERR(verify(b, &e1), ESP_OK);
    env_t e2 = sign(lo, ID_B, "b", 1);
    CHECK_ERR(verify(b, &e2), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK_ERR(msg_auth_reset_peer(b, ID_A), ESP_OK);
    CHECK_ERR(verify(b, &e2), ESP_OK);
    msg_auth_peer_stats_t s = stats(b, ID_A);
    CHECK(s.accepted == 2 && s.replay == 1 && s.last_epoch == 3);   /* stats kept */
    msg_auth_delete(hi); msg_auth_delete(lo); msg_auth_delete(b);
}

TEST(t08_not_for_me)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    env_t e = sign(a, 2, "x", 1);
    uint8_t sender = 0xEE;
    const void *m = (const void *)0x1; size_t n = 77;
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &sender, &m, &n), ESP_ERR_MSG_AUTH_NOT_FOR_ME);
    CHECK(sender == 0xEE && m == (const void *)0x1 && n == 77);     /* nothing written */
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t09_unknown_sender)
{
    msg_auth_handle_t b = make_ex(kat_key32, 32, "status", ID_B, MAX_ID, 1);
    env_t own   = craft(hkdf_k32_status, 1, 1, ID_B, ID_B, 1, 0, "x", 1);
    env_t above = craft(hkdf_k32_status, 1, 1, MAX_ID + 1, ID_B, 1, 0, "x", 1);
    long calls = shim_mac_calls();
    uint8_t sender = 0xEE; const void *m; size_t n;
    CHECK_ERR(msg_auth_verify(b, own.buf, own.len, &sender, &m, &n), ESP_ERR_MSG_AUTH_UNKNOWN);
    CHECK_ERR(msg_auth_verify(b, above.buf, above.len, &sender, &m, &n), ESP_ERR_MSG_AUTH_UNKNOWN);
    CHECK(sender == 0xEE);
    CHECK(shim_mac_calls() == calls);           /* rejected before any MAC */
    env_t ok = craft(hkdf_k32_status, 1, 1, MAX_ID, ID_B, 1, 0, "x", 1);
    CHECK_ERR(verify(b, &ok), ESP_OK);          /* highest valid ID accepted */
    msg_auth_delete(b);
}

TEST(t10_forged_high_counter)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    env_t e = sign(a, ID_B, "x", 1);
    env_t forged = e;
    forged.buf[8] = 0x7F;                       /* counter 0x7F000000, tag unchanged */
    CHECK_ERR(verify(b, &forged), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK(stats(b, ID_A).seen == 0);
    CHECK_ERR(verify(b, &e), ESP_OK);           /* genuine counter 0 still accepted */
    env_t e2 = sign(a, ID_B, "y", 1);
    CHECK_ERR(verify(b, &e2), ESP_OK);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t11_malformed)
{
    msg_auth_handle_t b = make_ex(kat_key32, 32, "status", ID_B, MAX_ID, 1);
    env_t good = craft(hkdf_k32_status, 1, 1, ID_A, ID_B, 1, 0, "x", 1);
    for (size_t len = 0; len < MSG_AUTH_OVERHEAD; len++) {
        uint8_t s; const void *m; size_t n;
        CHECK_ERR(msg_auth_verify(b, good.buf, len, &s, &m, &n), ESP_ERR_MSG_AUTH_MALFORMED);
    }
    env_t v2 = craft(hkdf_k32_status, 2, 1, ID_A, ID_B, 1, 0, "x", 1);  /* correctly tagged */
    env_t m2 = craft(hkdf_k32_status, 1, 2, ID_A, ID_B, 1, 0, "x", 1);  /* mode 2 reserved */
    env_t m0 = craft(hkdf_k32_status, 1, 0, ID_A, ID_B, 1, 0, "x", 1);
    CHECK_ERR(verify(b, &v2), ESP_ERR_MSG_AUTH_MALFORMED);
    CHECK_ERR(verify(b, &m2), ESP_ERR_MSG_AUTH_MALFORMED);
    CHECK_ERR(verify(b, &m0), ESP_ERR_MSG_AUTH_MALFORMED);
    CHECK_ERR(verify(b, &good), ESP_OK);
    msg_auth_peer_stats_t s = stats(b, ID_A);
    CHECK(s.bad_tag == 0 && s.replay == 0 && s.accepted == 1);
    msg_auth_delete(b);
}

TEST(t12_size_limit)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    static uint8_t msg[MSG_AUTH_MAX_MESSAGE + 1];
    env_t e = sign(a, ID_B, msg, MSG_AUTH_MAX_MESSAGE);
    CHECK(e.len == 1460);
    CHECK_ERR(verify(b, &e), ESP_OK);
    env_t big = e;
    big.len = MSG_AUTH_MAX_ENVELOPE + 1;
    long calls = shim_mac_calls();
    CHECK_ERR(verify(b, &big), ESP_ERR_INVALID_SIZE);
    CHECK(shim_mac_calls() == calls);           /* before any MAC */
    CHECK(stats(b, ID_A).bad_tag == 0);
    /* signer enforces it too */
    uint8_t out[MSG_AUTH_MAX_ENVELOPE + 32]; size_t n = 5;
    CHECK_ERR(msg_auth_sign(a, ID_B, msg, MSG_AUTH_MAX_MESSAGE + 1, out, sizeof out, &n),
              ESP_ERR_INVALID_SIZE);
    CHECK(n == 0);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t13_counter_exhaustion)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    msg_auth_test_set_counter(a, UINT32_MAX - 1);
    env_t e = sign(a, ID_B, "last", 4);
    CHECK(env_counter(&e) == UINT32_MAX - 1);
    CHECK_ERR(verify(b, &e), ESP_OK);
    uint8_t out[64]; size_t n = 123;
    CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, out, sizeof out, &n), ESP_ERR_MSG_AUTH_EXHAUSTED);
    CHECK(n == 0);
    n = 123;
    CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, out, sizeof out, &n), ESP_ERR_MSG_AUTH_EXHAUSTED);
    CHECK(n == 0);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t14_repeated_epoch)
{
    msg_auth_handle_t a = make(ID_A, 5), b = make(ID_B, 1);
    env_t e0 = sign(a, ID_B, "x", 1), e1 = sign(a, ID_B, "x", 1), e2 = sign(a, ID_B, "x", 1);
    (void)e0; (void)e1;
    CHECK_ERR(verify(b, &e2), ESP_OK);                      /* last = (5, 2) */
    msg_auth_handle_t again = make(ID_A, 5);                /* contract violated */
    env_t r[4];
    for (int i = 0; i < 4; i++) r[i] = sign(again, ID_B, "y", 1);
    CHECK_ERR(verify(b, &r[0]), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK_ERR(verify(b, &r[2]), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK_ERR(verify(b, &r[3]), ESP_OK);                    /* only higher counters */
    msg_auth_delete(b);
    b = make(ID_B, 1);                                      /* receiver lost its state */
    CHECK_ERR(verify(b, &r[0]), ESP_OK);                    /* first one accepted regardless */
    msg_auth_delete(a); msg_auth_delete(again); msg_auth_delete(b);
}

TEST(t15_argument_checks)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    msg_auth_config_t cfg = { .key = s_key, .key_len = 32, .purpose = PURPOSE,
                              .my_id = 0, .max_peer_id = MAX_ID, .epoch = 1 };
    msg_auth_handle_t h = (msg_auth_handle_t)0x1;

    /* create */
    CHECK_ERR(msg_auth_create(NULL, &h), ESP_ERR_INVALID_ARG);
    CHECK(h == NULL);
    CHECK_ERR(msg_auth_create(&cfg, NULL), ESP_ERR_INVALID_ARG);
    msg_auth_config_t c = cfg; c.key = NULL;           CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.purpose = NULL;                         CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.key_len = 15;                           CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.key_len = 65;                           CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.max_peer_id = MSG_AUTH_MAX_PEERS;       CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.my_id = MAX_ID + 1;                     CHECK_ERR(msg_auth_create(&c, &h), ESP_ERR_INVALID_ARG);
    c = cfg; c.max_peer_id = 31; c.my_id = 31;         CHECK_ERR(msg_auth_create(&c, &h), ESP_OK);
    CHECK(h != NULL);
    msg_auth_delete(h);
    c = cfg; c.max_peer_id = 0; c.my_id = 0;           CHECK_ERR(msg_auth_create(&c, &h), ESP_OK);
    msg_auth_delete(h);

    /* delete */
    CHECK_ERR(msg_auth_delete(NULL), ESP_ERR_INVALID_ARG);

    /* sign: *out_len zeroed on every failure, counter unchanged */
    uint8_t out[64]; size_t n;
    n = 9; CHECK_ERR(msg_auth_sign(NULL, ID_B, "x", 1, out, sizeof out, &n), ESP_ERR_INVALID_ARG); CHECK(n == 0);
    n = 9; CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, NULL, sizeof out, &n), ESP_ERR_INVALID_ARG);   CHECK(n == 0);
    CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, out, sizeof out, NULL), ESP_ERR_INVALID_ARG);
    n = 9; CHECK_ERR(msg_auth_sign(a, ID_B, NULL, 1, out, sizeof out, &n), ESP_ERR_INVALID_ARG);   CHECK(n == 0);
    n = 9; CHECK_ERR(msg_auth_sign(a, ID_A, "x", 1, out, sizeof out, &n), ESP_ERR_INVALID_ARG);    CHECK(n == 0);
    n = 9; CHECK_ERR(msg_auth_sign(a, MAX_ID + 1, "x", 1, out, sizeof out, &n), ESP_ERR_INVALID_ARG); CHECK(n == 0);
    n = 9; CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, out, MSG_AUTH_OVERHEAD, &n), ESP_ERR_INVALID_SIZE); CHECK(n == 0);
    n = 9; CHECK_ERR(msg_auth_sign(a, ID_B, NULL, 0, out, MSG_AUTH_OVERHEAD, &n), ESP_OK);          CHECK(n == 28);
    env_t e = sign(a, ID_B, "x", 1);
    CHECK(env_counter(&e) == 1);                /* only the successful sign used a counter */

    /* verify: nothing written on step 0-4 failures */
    uint8_t s = 0xEE; const void *m = (const void *)0x1; size_t ml = 77;
    CHECK_ERR(msg_auth_verify(NULL, e.buf, e.len, &s, &m, &ml), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify(b, NULL, e.len, &s, &m, &ml), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, NULL, &m, &ml), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &s, NULL, &ml), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &s, &m, NULL), ESP_ERR_INVALID_ARG);
    CHECK(s == 0xEE && m == (const void *)0x1 && ml == 77);
    /* bad tag: only sender_id written */
    env_t bad = e; bad.buf[bad.len - 1] ^= 0x80;
    CHECK_ERR(msg_auth_verify(b, bad.buf, bad.len, &s, &m, &ml), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK(s == ID_A && m == (const void *)0x1 && ml == 77);
    /* replay: only sender_id written */
    CHECK_ERR(verify(b, &e), ESP_OK);
    s = 0xEE;
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &s, &m, &ml), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK(s == ID_A && m == (const void *)0x1 && ml == 77);

    /* reset_peer / get_peer_stats */
    msg_auth_peer_stats_t st;
    CHECK_ERR(msg_auth_reset_peer(NULL, ID_A), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_get_peer_stats(NULL, ID_A, &st), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_get_peer_stats(b, ID_A, NULL), ESP_ERR_INVALID_ARG);

    /* error names */
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_MALFORMED), "ESP_ERR_MSG_AUTH_MALFORMED") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_NOT_FOR_ME), "ESP_ERR_MSG_AUTH_NOT_FOR_ME") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_UNKNOWN), "ESP_ERR_MSG_AUTH_UNKNOWN") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_BAD_TAG), "ESP_ERR_MSG_AUTH_BAD_TAG") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_REPLAY), "ESP_ERR_MSG_AUTH_REPLAY") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_EXHAUSTED), "ESP_ERR_MSG_AUTH_EXHAUSTED") == 0);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_INVALID_ARG), "ESP_ERR_INVALID_ARG") == 0);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t16_purpose_validation)
{
    char p33[34], p32[33];
    memset(p33, 'a', 33); p33[33] = 0;
    memset(p32, 'a', 32); p32[32] = 0;
    CHECK(!msg_auth_purpose_valid(""));
    CHECK(msg_auth_purpose_valid("a"));
    CHECK(msg_auth_purpose_valid(p32));
    CHECK(!msg_auth_purpose_valid(p33));
    CHECK(!msg_auth_purpose_valid("a b"));       /* 0x20 */
    CHECK(!msg_auth_purpose_valid("a\x7f"));
    CHECK(!msg_auth_purpose_valid("a\x80"));
    CHECK(msg_auth_purpose_valid("!~"));         /* 0x21, 0x7E: both ends */
    CHECK(!msg_auth_purpose_valid(NULL));
    /* unterminated: exactly 33 bytes, no NUL; ASan catches any read past the bound */
    char *raw = malloc(MSG_AUTH_PURPOSE_MAX + 1);
    memset(raw, 'z', MSG_AUTH_PURPOSE_MAX + 1);
    CHECK(!msg_auth_purpose_valid(raw));
    msg_auth_config_t cfg = { .key = s_key, .key_len = 32, .purpose = raw,
                              .my_id = 0, .max_peer_id = 1, .epoch = 1 };
    msg_auth_handle_t h;
    CHECK_ERR(msg_auth_create(&cfg, &h), ESP_ERR_INVALID_ARG);
    free(raw);
    cfg.purpose = p32;
    CHECK_ERR(msg_auth_create(&cfg, &h), ESP_OK);
    msg_auth_delete(h);
}

TEST(t17_key_edge_cases)
{
    const size_t lens[] = {16, 64};
    const uint8_t fills[] = {0x00, 0xFF};
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            uint8_t k[64];
            memset(k, fills[j], sizeof k);
            msg_auth_handle_t a = make_ex(k, lens[i], PURPOSE, ID_A, MAX_ID, 1);
            msg_auth_handle_t b = make_ex(k, lens[i], PURPOSE, ID_B, MAX_ID, 1);
            env_t e = sign(a, ID_B, "k", 1);
            CHECK_ERR(verify(b, &e), ESP_OK);
            msg_auth_delete(a); msg_auth_delete(b);
        }
    }
    /* all-zero 16 vs all-zero 64 are different keys */
    uint8_t z[64] = {0};
    msg_auth_handle_t a = make_ex(z, 16, PURPOSE, ID_A, MAX_ID, 1);
    msg_auth_handle_t b = make_ex(z, 64, PURPOSE, ID_B, MAX_ID, 1);
    env_t e = sign(a, ID_B, "k", 1);
    CHECK_ERR(verify(b, &e), ESP_ERR_MSG_AUTH_BAD_TAG);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t18_peer_id_checks)
{
    msg_auth_handle_t b = make(ID_B, 1);
    msg_auth_peer_stats_t st;
    CHECK_ERR(msg_auth_reset_peer(b, ID_B), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_reset_peer(b, MAX_ID + 1), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_reset_peer(b, MAX_ID), ESP_OK);
    CHECK_ERR(msg_auth_reset_peer(b, 0), ESP_OK);
    CHECK_ERR(msg_auth_get_peer_stats(b, ID_B, &st), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_get_peer_stats(b, MAX_ID + 1, &st), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_get_peer_stats(b, 255, &st), ESP_ERR_INVALID_ARG);
    memset(&st, 0xAA, sizeof st);
    CHECK_ERR(msg_auth_get_peer_stats(b, MAX_ID, &st), ESP_OK);
    CHECK(st.accepted == 0 && st.bad_tag == 0 && st.replay == 0 && st.seen == 0);
    msg_auth_delete(b);
}

TEST(t19_known_answers)
{
    /* HMAC: the PSA library against independent values */
    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&at, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&at, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&at, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_key_id_t k;
    CHECK(psa_import_key(&at, hkdf_k32_status, 32, &k) == PSA_SUCCESS);
    uint8_t mac[32]; size_t n = 0;
    CHECK(psa_mac_compute(k, PSA_ALG_HMAC(PSA_ALG_SHA_256), kat_hmac_data, sizeof kat_hmac_data,
                          mac, sizeof mac, &n) == PSA_SUCCESS && n == 32);
    CHECK(memcmp(mac, kat_hmac_full, 32) == 0);
    CHECK(memcmp(mac, kat_hmac_trunc, 16) == 0);
    psa_destroy_key(k);

    /* HKDF: each derived key is non-exportable, so check it through the tags it
     * produces: msg_auth's tag must equal HMAC(fixture key, header || message). */
    struct { const uint8_t *key; size_t key_len; const char *purpose; const uint8_t *dk; } hk[] = {
        { kat_key16, 16, "status",   hkdf_k16_status },
        { kat_key32, 32, "status",   hkdf_k32_status },
        { kat_key32, 32, "doorbell", hkdf_k32_doorbell },
        { kat_key64, 64, "AAAAAAAAAAAAAAAA~!#$%&'()*+,-./0", hkdf_k64_p32 },
    };
    for (size_t i = 0; i < sizeof hk / sizeof hk[0]; i++) {
        msg_auth_handle_t a = make_ex(hk[i].key, hk[i].key_len, hk[i].purpose, 0, 1, 42);
        env_t e = sign(a, 1, "kat", 3);
        env_t want = craft(hk[i].dk, 1, 1, 0, 1, 42, 0, "kat", 3);
        CHECK(e.len == want.len && memcmp(e.buf, want.buf, e.len) == 0);
        msg_auth_delete(a);
    }

    /* Envelopes: exact bytes */
    {
        msg_auth_handle_t a = make_ex(kat_key32, 32, "status", 0, 3, 7);
        env_t e = sign(a, 1, kat_env_basic_msg, KAT_ENV_BASIC_MSG_LEN);
        CHECK(e.len == sizeof kat_env_basic && memcmp(e.buf, kat_env_basic, e.len) == 0);
        msg_auth_delete(a);
    }
    {
        msg_auth_handle_t a = make_ex(kat_key32, 32, "status", 3, 3, 0x01020304);
        msg_auth_test_set_counter(a, 0xA0B0C0D0);
        env_t e = sign(a, 2, NULL, 0);
        CHECK(e.len == sizeof kat_env_empty && memcmp(e.buf, kat_env_empty, e.len) == 0);
        msg_auth_delete(a);
    }
    {
        msg_auth_handle_t a = make_ex(kat_key16, 16, "x", 31, 31, 0xFFFFFFFF);
        msg_auth_test_set_counter(a, 0xFFFFFFFE);
        env_t e = sign(a, 30, kat_env_max_ids_msg, KAT_ENV_MAX_IDS_MSG_LEN);
        CHECK(e.len == sizeof kat_env_max_ids && memcmp(e.buf, kat_env_max_ids, e.len) == 0);
        msg_auth_delete(a);
        /* and the receiver accepts the fixture */
        msg_auth_handle_t r = make_ex(kat_key16, 16, "x", 30, 31, 1);
        uint8_t s; const void *m; size_t ml;
        CHECK_ERR(msg_auth_verify(r, kat_env_max_ids, sizeof kat_env_max_ids, &s, &m, &ml), ESP_OK);
        CHECK(s == 31 && ml == KAT_ENV_MAX_IDS_MSG_LEN &&
              memcmp(m, kat_env_max_ids_msg, ml) == 0);
        msg_auth_delete(r);
    }
}

TEST(t20_crypto_failure)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    /* sign */
    uint8_t out[64]; size_t n = 9;
    shim_faults.mac = true;
    CHECK_ERR(msg_auth_sign(a, ID_B, "x", 1, out, sizeof out, &n), ESP_FAIL);
    shim_faults.mac = false;
    CHECK(n == 0);
    env_t e = sign(a, ID_B, "x", 1);
    CHECK(env_counter(&e) == 1);                /* reserved counter 0 not reused */
    /* verify */
    uint8_t s = 0xEE; const void *m = (const void *)0x1; size_t ml = 77;
    shim_faults.mac = true;
    CHECK_ERR(msg_auth_verify(b, e.buf, e.len, &s, &m, &ml), ESP_FAIL);
    shim_faults.mac = false;
    CHECK(s == ID_A && m == (const void *)0x1 && ml == 77);
    msg_auth_peer_stats_t st = stats(b, ID_A);
    CHECK(st.bad_tag == 0 && st.seen == 0 && st.accepted == 0);
    CHECK_ERR(verify(b, &e), ESP_OK);           /* freshness untouched */
    /* crypto failure after state exists: still no change */
    env_t e2 = sign(a, ID_B, "y", 1);
    shim_faults.mac = true;
    CHECK_ERR(verify(b, &e2), ESP_FAIL);
    shim_faults.mac = false;
    st = stats(b, ID_A);
    CHECK(st.last_counter == 1 && st.bad_tag == 0 && st.accepted == 1);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t21_create_failures)
{
    const msg_auth_config_t cfg = { .key = s_key, .key_len = 32, .purpose = PURPOSE,
                                    .my_id = 0, .max_peer_id = MAX_ID, .epoch = 1 };
    const int allocs0 = shim_live_allocs(), keys0 = shim_live_keys();
    struct { const char *what; esp_err_t want; } cases[] = {
        { "psa_init",  ESP_FAIL },
        { "heap",      ESP_ERR_NO_MEM },
        { "mutex",     ESP_FAIL },
        { "import",    ESP_FAIL },
        { "salt",      ESP_FAIL },
        { "secret",    ESP_FAIL },
        { "info",      ESP_FAIL },
        { "output",    ESP_FAIL },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        shim_clear_faults();
        switch (i) {
        case 0: shim_faults.psa_init = true; break;
        case 1: shim_faults.heap = true; break;
        case 2: shim_faults.mutex = true; break;
        case 3: shim_faults.import = true; break;
        case 4: shim_faults.derive_input_step = PSA_KEY_DERIVATION_INPUT_SALT; break;
        case 5: shim_faults.derive_input_step = PSA_KEY_DERIVATION_INPUT_SECRET; break;
        case 6: shim_faults.derive_input_step = PSA_KEY_DERIVATION_INPUT_INFO; break;
        case 7: shim_faults.derive_output = true; break;
        }
        msg_auth_handle_t h = (msg_auth_handle_t)0x1;
        esp_err_t err = msg_auth_create(&cfg, &h);
        shim_clear_faults();
        CHECK_ERR(err, cases[i].want);
        CHECK(h == NULL);
        CHECK(shim_live_allocs() == allocs0);
        CHECK(shim_live_keys() == keys0);      /* neither derived nor imported key left */
    }
    /* and a normal create/delete balances too */
    msg_auth_handle_t h;
    CHECK_ERR(msg_auth_create(&cfg, &h), ESP_OK);
    CHECK(shim_live_allocs() == allocs0 + 1);
    CHECK(shim_live_keys() == keys0 + 1);       /* only the derived key: imported one gone */
    CHECK_ERR(msg_auth_delete(h), ESP_OK);
    CHECK(shim_live_allocs() == allocs0 && shim_live_keys() == keys0);
}

/* ---- concurrency (T22–T24) ---- */

#define THREADS 4

static pthread_barrier_t s_barrier;

typedef struct {
    msg_auth_handle_t h;
    const env_t      *envs;
    int               count;
    esp_err_t         result;      /* T24 */
    uint32_t         *counters;    /* T23 */
    bool              use_from;    /* T33: go through msg_auth_verify_from(expected) */
    uint8_t           expected;
} job_t;

static esp_err_t job_verify(const job_t *j, const env_t *e)
{
    if (!j->use_from) {
        return verify(j->h, e);
    }
    const void *m; size_t n;
    return msg_auth_verify_from(j->h, j->expected, e->buf, e->len, &m, &n, NULL);
}

static void *verify_bad_job(void *arg)
{
    job_t *j = arg;
    pthread_barrier_wait(&s_barrier);
    for (int i = 0; i < j->count; i++) {
        if (job_verify(j, &j->envs[i]) != ESP_ERR_MSG_AUTH_BAD_TAG) {
            j->result = ESP_FAIL;
        }
    }
    return NULL;
}

TEST(t22_concurrent_bad_tags)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    enum { PER = 300 };
    static env_t bad[THREADS][PER];
    for (int t = 0; t < THREADS; t++) {
        for (int i = 0; i < PER; i++) {
            bad[t][i] = sign(a, ID_B, "z", 1);
            bad[t][i].buf[bad[t][i].len - 2] ^= 0x01;
        }
    }
    pthread_t th[THREADS]; job_t jobs[THREADS];
    pthread_barrier_init(&s_barrier, NULL, THREADS);
    for (int t = 0; t < THREADS; t++) {
        jobs[t] = (job_t){ .h = b, .envs = bad[t], .count = PER, .result = ESP_OK };
        pthread_create(&th[t], NULL, verify_bad_job, &jobs[t]);
    }
    for (int t = 0; t < THREADS; t++) {
        pthread_join(th[t], NULL);
        CHECK_ERR(jobs[t].result, ESP_OK);
    }
    pthread_barrier_destroy(&s_barrier);
    CHECK(stats(b, ID_A).bad_tag == THREADS * PER);
    CHECK(stats(b, ID_A).seen == 0);
    msg_auth_delete(a); msg_auth_delete(b);
}

static void *sign_job(void *arg)
{
    job_t *j = arg;
    pthread_barrier_wait(&s_barrier);
    for (int i = 0; i < j->count; i++) {
        env_t e = sign(j->h, ID_B, "c", 1);
        j->counters[i] = env_counter(&e);
    }
    return NULL;
}

static int cmp_u32(const void *x, const void *y)
{
    uint32_t a = *(const uint32_t *)x, b = *(const uint32_t *)y;
    return (a > b) - (a < b);
}

TEST(t23_concurrent_sign)
{
    msg_auth_handle_t a = make(ID_A, 1);
    enum { PER = 2000 };
    static uint32_t ctr[THREADS * PER];
    pthread_t th[THREADS]; job_t jobs[THREADS];
    pthread_barrier_init(&s_barrier, NULL, THREADS);
    for (int t = 0; t < THREADS; t++) {
        jobs[t] = (job_t){ .h = a, .count = PER, .counters = &ctr[t * PER] };
        pthread_create(&th[t], NULL, sign_job, &jobs[t]);
    }
    for (int t = 0; t < THREADS; t++) pthread_join(th[t], NULL);
    pthread_barrier_destroy(&s_barrier);
    qsort(ctr, THREADS * PER, sizeof ctr[0], cmp_u32);
    int dup = 0;
    for (int i = 1; i < THREADS * PER; i++) dup += ctr[i] == ctr[i - 1];
    CHECK(dup == 0);
    CHECK(ctr[0] == 0 && ctr[THREADS * PER - 1] == THREADS * PER - 1);
    msg_auth_delete(a);
}

static void *verify_one_job(void *arg)
{
    job_t *j = arg;
    pthread_barrier_wait(&s_barrier);
    j->result = job_verify(j, j->envs);
    return NULL;
}

TEST(t24_concurrent_consecutive)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    enum { ROUNDS = 2000 };
    int both = 0, older_rejected = 0, bad = 0;
    pthread_barrier_init(&s_barrier, NULL, 2);
    for (int r = 0; r < ROUNDS; r++) {
        env_t older = sign(a, ID_B, "o", 1), newer = sign(a, ID_B, "n", 1);
        job_t jo = { .h = b, .envs = &older }, jn = { .h = b, .envs = &newer };
        pthread_t to, tn;
        pthread_create(&to, NULL, verify_one_job, &jo);
        pthread_create(&tn, NULL, verify_one_job, &jn);
        pthread_join(to, NULL); pthread_join(tn, NULL);
        if (jo.result == ESP_OK && jn.result == ESP_OK) both++;
        else if (jo.result == ESP_ERR_MSG_AUTH_REPLAY && jn.result == ESP_OK) older_rejected++;
        else bad++;
    }
    pthread_barrier_destroy(&s_barrier);
    CHECK(bad == 0);
    msg_auth_peer_stats_t st = stats(b, ID_A);
    CHECK(st.accepted == (uint32_t)(2 * both + older_rejected));
    CHECK(st.replay == (uint32_t)older_rejected);
    CHECK(st.last_counter == 2 * ROUNDS - 1);
    printf("    (t24: %d rounds both accepted, %d older rejected)\n", both, older_rejected);
    msg_auth_delete(a); msg_auth_delete(b);
}

TEST(t25_receiver_restart)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1);
    env_t e = sign(a, ID_B, "old", 3);
    CHECK_ERR(verify(b, &e), ESP_OK);
    env_t e2 = sign(a, ID_B, "new", 3);
    CHECK_ERR(verify(b, &e2), ESP_OK);
    msg_auth_delete(b);
    b = make(ID_B, 1);                          /* receiver restarts: state lost */
    CHECK_ERR(verify(b, &e), ESP_OK);           /* documented §6.3: accepted once */
    CHECK_ERR(verify(b, &e), ESP_ERR_MSG_AUTH_REPLAY);
    msg_auth_delete(a); msg_auth_delete(b);
}

/* ================= T26–T33: msg_auth_verify_from, context stats (0.2.0) ================= */

#define ID_C     2                   /* a receiver with two peers, A and B */

static msg_auth_stats_t ctx_stats(msg_auth_handle_t h)
{
    msg_auth_stats_t s;
    if (msg_auth_get_stats(h, &s) != ESP_OK) abort();
    return s;
}

static esp_err_t verify_from(msg_auth_handle_t h, uint8_t expected, const env_t *e)
{
    const void *m; size_t n;
    return msg_auth_verify_from(h, expected, e->buf, e->len, &m, &n, NULL);
}

static bool peer_stats_equal(msg_auth_peer_stats_t x, msg_auth_peer_stats_t y)
{
    return x.accepted == y.accepted && x.bad_tag == y.bad_tag && x.replay == y.replay &&
           x.last_epoch == y.last_epoch && x.last_counter == y.last_counter && x.seen == y.seen;
}

/* T26 (review T-a, T-e): right sender gives the same result, message and stats
 * as msg_auth_verify(); info holds the envelope's freshness pair; info may be NULL. */
TEST(t26_verify_from_right_sender)
{
    msg_auth_handle_t a  = make(ID_A, 9);
    msg_auth_handle_t r1 = make(ID_C, 1), r2 = make(ID_C, 1);   /* identical receivers */
    msg_auth_test_set_counter(a, 0x10203040);
    const size_t lens[] = {0, 5, MSG_AUTH_MAX_MESSAGE};
    static uint8_t msg[MSG_AUTH_MAX_MESSAGE];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 11 + 1);
    for (size_t i = 0; i < 3; i++) {
        env_t e = sign(a, ID_C, lens[i] ? msg : NULL, lens[i]);
        uint8_t s; const void *m1, *m2; size_t n1, n2;
        msg_auth_rx_info_t info = { 0xEEEEEEEE, 0xEEEEEEEE };
        CHECK_ERR(msg_auth_verify(r1, e.buf, e.len, &s, &m1, &n1), ESP_OK);
        CHECK_ERR(msg_auth_verify_from(r2, ID_A, e.buf, e.len, &m2, &n2,
                                       i == 1 ? NULL : &info), ESP_OK);     /* T-e */
        CHECK(m1 == m2 && n1 == n2 && n2 == lens[i]);
        CHECK(m2 == e.buf + MSG_AUTH_HEADER_SIZE);
        if (i != 1) {
            CHECK(info.epoch == 9 && info.counter == env_counter(&e));
        }
        /* and the same replay result */
        CHECK_ERR(msg_auth_verify(r1, e.buf, e.len, &s, &m1, &n1), ESP_ERR_MSG_AUTH_REPLAY);
        CHECK_ERR(verify_from(r2, ID_A, &e), ESP_ERR_MSG_AUTH_REPLAY);
    }
    CHECK(peer_stats_equal(stats(r1, ID_A), stats(r2, ID_A)));
    CHECK(stats(r2, ID_A).accepted == 3 && stats(r2, ID_A).replay == 3);
    msg_auth_delete(a); msg_auth_delete(r1); msg_auth_delete(r2);
}

/* T27 (review T-b): the cross-link scenario. B's genuine envelope relayed onto A's
 * link is rejected without touching B's state, and B's own copy is then accepted.
 * The second half documents the 0.1.0 behaviour that verify_from removes. */
TEST(t27_cross_link)
{
    msg_auth_handle_t b = make(ID_B, 1), r = make(ID_C, 1);
    env_t first = sign(b, ID_C, "b0", 2);
    CHECK_ERR(verify_from(r, ID_B, &first), ESP_OK);            /* B's state exists */
    const msg_auth_peer_stats_t b0 = stats(r, ID_B), a0 = stats(r, ID_A);

    env_t e = sign(b, ID_C, "b1", 2);
    long calls = shim_mac_calls();
    const void *m = (const void *)0x1; size_t n = 77;
    msg_auth_rx_info_t info = { 0xEEEEEEEE, 0xEEEEEEEE };
    CHECK_ERR(msg_auth_verify_from(r, ID_A, e.buf, e.len, &m, &n, &info),
              ESP_ERR_MSG_AUTH_WRONG_SENDER);
    CHECK(shim_mac_calls() == calls);                           /* before any MAC */
    CHECK(m == (const void *)0x1 && n == 77 && info.epoch == 0xEEEEEEEE);
    CHECK(peer_stats_equal(stats(r, ID_B), b0));                /* B untouched */
    CHECK(peer_stats_equal(stats(r, ID_A), a0));                /* A untouched */
    CHECK(ctx_stats(r).wrong_sender == 1 && ctx_stats(r).bad_tag_total == 0);
    CHECK_ERR(verify_from(r, ID_B, &e), ESP_OK);                /* B's own copy accepted */

    /* 0.1.0 shape, for contrast: verify + caller-side check consumes B's message */
    msg_auth_handle_t r_old = make(ID_C, 1);
    env_t e2 = sign(b, ID_C, "b2", 2);
    uint8_t s;
    CHECK_ERR(msg_auth_verify(r_old, e2.buf, e2.len, &s, &m, &n), ESP_OK);
    CHECK(s == ID_B);                                           /* caller drops: not ID_A */
    CHECK_ERR(verify(r_old, &e2), ESP_ERR_MSG_AUTH_REPLAY);     /* B's own copy lost */
    msg_auth_delete(b); msg_auth_delete(r); msg_auth_delete(r_old);
}

/* T28 (review T-c): WRONG_SENDER takes priority over a bad tag; nobody's bad_tag moves. */
TEST(t28_wrong_sender_before_tag)
{
    msg_auth_handle_t b = make(ID_B, 1), r = make(ID_C, 1);
    env_t forged = sign(b, ID_C, "x", 1);
    forged.buf[forged.len - 1] ^= 0x01;                         /* claims B, bad tag */
    CHECK_ERR(verify_from(r, ID_A, &forged), ESP_ERR_MSG_AUTH_WRONG_SENDER);
    CHECK(stats(r, ID_A).bad_tag == 0 && stats(r, ID_B).bad_tag == 0);
    CHECK(ctx_stats(r).bad_tag_total == 0 && ctx_stats(r).wrong_sender == 1);
    /* on the right link the same forgery is a bad tag, charged as a claim */
    CHECK_ERR(verify_from(r, ID_B, &forged), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK(stats(r, ID_B).bad_tag == 1 && ctx_stats(r).bad_tag_total == 1);
    msg_auth_delete(b); msg_auth_delete(r);
}

/* T29 (review T-d + T15 for verify_from): argument checks in step 0, whatever the
 * envelope; outputs (msg, msg_len, info) untouched on every failure path. */
TEST(t29_verify_from_arguments_and_outputs)
{
    msg_auth_handle_t a = make(ID_A, 1), r = make(ID_C, 1);
    env_t e = sign(a, ID_C, "x", 1);
    const void *m = (const void *)0x1; size_t n = 77;
    msg_auth_rx_info_t info = { 0xEEEEEEEE, 0xDDDDDDDD };
#define UNTOUCHED (m == (const void *)0x1 && n == 77 && \
                   info.epoch == 0xEEEEEEEE && info.counter == 0xDDDDDDDD)

    /* invalid expected_sender: own ID, above max, 255; with a good, a short and an
     * oversized envelope, INVALID_ARG every time (step 0, envelope not read) */
    const uint8_t bad_ids[] = { ID_C, MAX_ID + 1, 255 };
    const size_t  lens[]    = { e.len, 0, 5, MSG_AUTH_MAX_ENVELOPE + 1 };
    long calls = shim_mac_calls();
    for (size_t i = 0; i < sizeof bad_ids; i++) {
        for (size_t j = 0; j < 4; j++) {
            CHECK_ERR(msg_auth_verify_from(r, bad_ids[i], e.buf, lens[j], &m, &n, &info),
                      ESP_ERR_INVALID_ARG);
        }
    }
    CHECK(shim_mac_calls() == calls);
    /* null arguments */
    CHECK_ERR(msg_auth_verify_from(NULL, ID_A, e.buf, e.len, &m, &n, &info), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify_from(r, ID_A, NULL, e.len, &m, &n, &info),     ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify_from(r, ID_A, e.buf, e.len, NULL, &n, &info),  ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_verify_from(r, ID_A, e.buf, e.len, &m, NULL, &info),  ESP_ERR_INVALID_ARG);
    CHECK(UNTOUCHED);
    /* the highest valid ID passes step 0 (ID_A is used below) */
    msg_auth_handle_t r3 = make(ID_C, 1);
    env_t e3 = craft(hkdf_k32_status, 1, 1, MAX_ID, ID_C, 1, 0, "x", 1);   /* wrong key: fine */
    CHECK_ERR(msg_auth_verify_from(r3, MAX_ID, e3.buf, e3.len, &m, &n, &info),
              ESP_ERR_MSG_AUTH_BAD_TAG);                                    /* got past step 0 */
    msg_auth_delete(r3);

    /* every rejection after step 0 leaves the outputs alone */
    env_t big = e;   big.len = MSG_AUTH_MAX_ENVELOPE + 1;
    env_t shrt = e;  shrt.len = MSG_AUTH_OVERHEAD - 1;
    env_t nfm  = sign(a, ID_B, "x", 1);
    env_t bad  = e;  bad.buf[bad.len - 1] ^= 0x80;
    env_t own  = e;  own.buf[2] = ID_C;       /* claims the receiver's own ID */
    msg_auth_handle_t bb = make(ID_B, 1);
    env_t wrong = sign(bb, ID_C, "x", 1);
    struct { const env_t *env; esp_err_t want; } cases[] = {
        { &big,   ESP_ERR_INVALID_SIZE },
        { &shrt,  ESP_ERR_MSG_AUTH_MALFORMED },
        { &nfm,   ESP_ERR_MSG_AUTH_NOT_FOR_ME },
        { &own,   ESP_ERR_MSG_AUTH_UNKNOWN },
        { &wrong, ESP_ERR_MSG_AUTH_WRONG_SENDER },
        { &bad,   ESP_ERR_MSG_AUTH_BAD_TAG },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK_ERR(msg_auth_verify_from(r, ID_A, cases[i].env->buf, cases[i].env->len,
                                       &m, &n, &info), cases[i].want);
        CHECK(UNTOUCHED);
    }
    CHECK_ERR(verify_from(r, ID_A, &e), ESP_OK);
    CHECK_ERR(msg_auth_verify_from(r, ID_A, e.buf, e.len, &m, &n, &info), ESP_ERR_MSG_AUTH_REPLAY);
    CHECK(UNTOUCHED);
#undef UNTOUCHED

    /* get_stats and the new error name */
    msg_auth_stats_t st;
    CHECK_ERR(msg_auth_get_stats(NULL, &st), ESP_ERR_INVALID_ARG);
    CHECK_ERR(msg_auth_get_stats(r, NULL), ESP_ERR_INVALID_ARG);
    CHECK(strcmp(msg_auth_err_to_name(ESP_ERR_MSG_AUTH_WRONG_SENDER),
                 "ESP_ERR_MSG_AUTH_WRONG_SENDER") == 0);
    msg_auth_delete(a); msg_auth_delete(bb); msg_auth_delete(r);
}

/* T30 (T2 through verify_from): every single-bit flip gives the first check it
 * reaches; a sender byte flipped to another valid peer gives WRONG_SENDER. */
TEST(t30_verify_from_bit_flips)
{
    msg_auth_handle_t a = make(ID_A, 1), r = make(ID_C, 1);
    const char msg[] = "flip me";
    env_t e = sign(a, ID_C, msg, sizeof msg);
    uint32_t want_bad = 0, want_wrong = 0;
    for (size_t off = 0; off < e.len; off++) {
        for (int bit = 0; bit < 8; bit++) {
            env_t f = e;
            f.buf[off] ^= (uint8_t)(1u << bit);
            esp_err_t want = ESP_ERR_MSG_AUTH_BAD_TAG;
            if (off == 0 || off == 1) {
                want = ESP_ERR_MSG_AUTH_MALFORMED;
            } else if (off == 3) {
                want = ESP_ERR_MSG_AUTH_NOT_FOR_ME;
            } else if (off == 2 && (f.buf[2] > MAX_ID || f.buf[2] == ID_C)) {
                want = ESP_ERR_MSG_AUTH_UNKNOWN;                /* step 4 runs before 4a */
            } else if (off == 2) {
                want = ESP_ERR_MSG_AUTH_WRONG_SENDER;           /* another valid peer */
            }
            want_bad   += want == ESP_ERR_MSG_AUTH_BAD_TAG;
            want_wrong += want == ESP_ERR_MSG_AUTH_WRONG_SENDER;
            CHECK_ERR(verify_from(r, ID_A, &f), want);
        }
    }
    CHECK(want_wrong > 0);
    CHECK(ctx_stats(r).bad_tag_total == want_bad && ctx_stats(r).wrong_sender == want_wrong);
    CHECK(stats(r, ID_A).bad_tag == want_bad);                  /* all claimed A */
    CHECK(stats(r, ID_B).bad_tag == 0 && stats(r, MAX_ID).bad_tag == 0);
    CHECK_ERR(verify_from(r, ID_A, &e), ESP_OK);                /* freshness untouched */
    msg_auth_delete(a); msg_auth_delete(r);
}

/* T31 (T20 through verify_from): crypto failure is ESP_FAIL, no stats, no state. */
TEST(t31_verify_from_crypto_failure)
{
    msg_auth_handle_t a = make(ID_A, 1), r = make(ID_C, 1);
    env_t e = sign(a, ID_C, "x", 1);
    const void *m = (const void *)0x1; size_t n = 77;
    msg_auth_rx_info_t info = { 0xEEEEEEEE, 0xEEEEEEEE };
    shim_faults.mac = true;
    CHECK_ERR(msg_auth_verify_from(r, ID_A, e.buf, e.len, &m, &n, &info), ESP_FAIL);
    shim_faults.mac = false;
    CHECK(m == (const void *)0x1 && n == 77 && info.epoch == 0xEEEEEEEE);
    msg_auth_peer_stats_t st = stats(r, ID_A);
    CHECK(st.bad_tag == 0 && st.seen == 0 && st.accepted == 0);
    CHECK(ctx_stats(r).bad_tag_total == 0 && ctx_stats(r).wrong_sender == 0);
    CHECK_ERR(verify_from(r, ID_A, &e), ESP_OK);
    env_t e2 = sign(a, ID_C, "y", 1);
    shim_faults.mac = true;
    CHECK_ERR(verify_from(r, ID_A, &e2), ESP_FAIL);
    shim_faults.mac = false;
    st = stats(r, ID_A);
    CHECK(st.last_counter == 0 && st.accepted == 1 && st.bad_tag == 0);
    CHECK_ERR(verify_from(r, ID_A, &e2), ESP_OK);
    msg_auth_delete(a); msg_auth_delete(r);
}

/* T32: context-wide counters. bad_tag_total counts BAD_TAG from both entry points
 * whatever sender is claimed; REPLAY, NOT_FOR_ME etc. do not count. */
TEST(t32_context_stats)
{
    msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1), r = make(ID_C, 1);
    msg_auth_stats_t st;
    memset(&st, 0xAA, sizeof st);
    CHECK_ERR(msg_auth_get_stats(r, &st), ESP_OK);
    CHECK(st.bad_tag_total == 0 && st.wrong_sender == 0);
    env_t ea = sign(a, ID_C, "a", 1), eb = sign(b, ID_C, "b", 1);
    env_t ba = ea; ba.buf[ba.len - 1] ^= 1;
    env_t bb = eb; bb.buf[bb.len - 1] ^= 1;
    CHECK_ERR(verify(r, &ba), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK_ERR(verify_from(r, ID_B, &bb), ESP_ERR_MSG_AUTH_BAD_TAG);
    CHECK_ERR(verify_from(r, ID_A, &eb), ESP_ERR_MSG_AUTH_WRONG_SENDER);
    CHECK_ERR(verify_from(r, ID_B, &ea), ESP_ERR_MSG_AUTH_WRONG_SENDER);
    CHECK_ERR(verify(r, &ea), ESP_OK);
    CHECK_ERR(verify(r, &ea), ESP_ERR_MSG_AUTH_REPLAY);
    env_t nfm = sign(a, ID_B, "n", 1);
    CHECK_ERR(verify(r, &nfm), ESP_ERR_MSG_AUTH_NOT_FOR_ME);
    st = ctx_stats(r);
    CHECK(st.bad_tag_total == 2 && st.wrong_sender == 2);
    CHECK(stats(r, ID_A).bad_tag == 1 && stats(r, ID_B).bad_tag == 1);
    CHECK_ERR(msg_auth_reset_peer(r, ID_A), ESP_OK);            /* reset keeps stats */
    CHECK(ctx_stats(r).bad_tag_total == 2);
    msg_auth_delete(a); msg_auth_delete(b); msg_auth_delete(r);
}

/* T33: concurrency through verify_from.
 * (a) T22 via verify_from: bad_tag and bad_tag_total exact.
 * (b) T24 via verify_from: outcomes consistent with §6.1.
 * (c) two links in parallel, each fed its own sender's stream plus the other
 *     sender's envelopes: every own envelope accepted, every cross one
 *     WRONG_SENDER, and the counts exact (WRONG_SENDER never races state). */
static void *link_job(void *arg)
{
    job_t *j = arg;
    pthread_barrier_wait(&s_barrier);
    j->result = ESP_OK;
    for (int i = 0; i < j->count; i++) {
        const env_t *own = &j->envs[2 * i], *cross = &j->envs[2 * i + 1];
        if (job_verify(j, cross) != ESP_ERR_MSG_AUTH_WRONG_SENDER) j->result = ESP_FAIL;
        if (job_verify(j, own)   != ESP_OK)                        j->result = ESP_FAIL;
    }
    return NULL;
}

TEST(t33_concurrent_verify_from)
{
    /* (a) */
    {
        msg_auth_handle_t a = make(ID_A, 1), r = make(ID_C, 1);
        enum { PER = 300 };
        static env_t bad[THREADS][PER];
        for (int t = 0; t < THREADS; t++) {
            for (int i = 0; i < PER; i++) {
                bad[t][i] = sign(a, ID_C, "z", 1);
                bad[t][i].buf[bad[t][i].len - 2] ^= 0x01;
            }
        }
        pthread_t th[THREADS]; job_t jobs[THREADS];
        pthread_barrier_init(&s_barrier, NULL, THREADS);
        for (int t = 0; t < THREADS; t++) {
            jobs[t] = (job_t){ .h = r, .envs = bad[t], .count = PER, .result = ESP_OK,
                               .use_from = true, .expected = ID_A };
            pthread_create(&th[t], NULL, verify_bad_job, &jobs[t]);
        }
        for (int t = 0; t < THREADS; t++) {
            pthread_join(th[t], NULL);
            CHECK_ERR(jobs[t].result, ESP_OK);
        }
        pthread_barrier_destroy(&s_barrier);
        CHECK(stats(r, ID_A).bad_tag == THREADS * PER && stats(r, ID_A).seen == 0);
        CHECK(ctx_stats(r).bad_tag_total == THREADS * PER);
        msg_auth_delete(a); msg_auth_delete(r);
    }
    /* (b) */
    {
        msg_auth_handle_t a = make(ID_A, 1), r = make(ID_C, 1);
        enum { ROUNDS = 1000 };
        int both = 0, older_rejected = 0, bad = 0;
        pthread_barrier_init(&s_barrier, NULL, 2);
        for (int i = 0; i < ROUNDS; i++) {
            env_t older = sign(a, ID_C, "o", 1), newer = sign(a, ID_C, "n", 1);
            job_t jo = { .h = r, .envs = &older, .use_from = true, .expected = ID_A };
            job_t jn = { .h = r, .envs = &newer, .use_from = true, .expected = ID_A };
            pthread_t to, tn;
            pthread_create(&to, NULL, verify_one_job, &jo);
            pthread_create(&tn, NULL, verify_one_job, &jn);
            pthread_join(to, NULL); pthread_join(tn, NULL);
            if (jo.result == ESP_OK && jn.result == ESP_OK) both++;
            else if (jo.result == ESP_ERR_MSG_AUTH_REPLAY && jn.result == ESP_OK) older_rejected++;
            else bad++;
        }
        pthread_barrier_destroy(&s_barrier);
        CHECK(bad == 0);
        msg_auth_peer_stats_t st = stats(r, ID_A);
        CHECK(st.accepted == (uint32_t)(2 * both + older_rejected));
        CHECK(st.replay == (uint32_t)older_rejected);
        CHECK(st.last_counter == 2 * ROUNDS - 1);
        msg_auth_delete(a); msg_auth_delete(r);
    }
    /* (c) */
    {
        msg_auth_handle_t a = make(ID_A, 1), b = make(ID_B, 1), r = make(ID_C, 1);
        enum { PER = 1000 };
        static env_t link_a[2 * PER], link_b[2 * PER];
        for (int i = 0; i < PER; i++) {
            env_t ea = sign(a, ID_C, "a", 1), eb = sign(b, ID_C, "b", 1);
            link_a[2 * i] = ea; link_a[2 * i + 1] = eb;    /* own A, relayed B */
            link_b[2 * i] = eb; link_b[2 * i + 1] = ea;    /* own B, relayed A */
        }
        pthread_t ta, tb;
        job_t ja = { .h = r, .envs = link_a, .count = PER, .use_from = true, .expected = ID_A };
        job_t jb = { .h = r, .envs = link_b, .count = PER, .use_from = true, .expected = ID_B };
        pthread_barrier_init(&s_barrier, NULL, 2);
        pthread_create(&ta, NULL, link_job, &ja);
        pthread_create(&tb, NULL, link_job, &jb);
        pthread_join(ta, NULL); pthread_join(tb, NULL);
        pthread_barrier_destroy(&s_barrier);
        CHECK_ERR(ja.result, ESP_OK);
        CHECK_ERR(jb.result, ESP_OK);
        CHECK(stats(r, ID_A).accepted == PER && stats(r, ID_A).replay == 0);
        CHECK(stats(r, ID_B).accepted == PER && stats(r, ID_B).replay == 0);
        CHECK(ctx_stats(r).wrong_sender == 2 * PER && ctx_stats(r).bad_tag_total == 0);
        msg_auth_delete(a); msg_auth_delete(b); msg_auth_delete(r);
    }
}

int main(void)
{
    if (getenv("MSG_AUTH_TEST_VERBOSE")) shim_log_verbose = 1;
    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed\n");
        return 2;
    }
    for (size_t i = 0; i < sizeof s_key; i++) s_key[i] = (uint8_t)(0xA5 ^ (i * 29));

    printf("msg_auth host tests, MAC path: %s\n",
           msg_auth_test_fallback_path() ? "fallback (§9.2)" : "primary (§9.1)");

    RUN(pure_header_roundtrip);
    RUN(pure_is_newer);
    RUN(pure_ct_equal16);
    RUN(t01_roundtrip);
    RUN(t02_bit_flips);
    RUN(t03_wrong_key_or_purpose);
    RUN(t04_replay_same_envelope);
    RUN(t05_older_counter_and_gaps);
    RUN(t06_new_epoch_counter_zero);
    RUN(t07_lower_epoch_then_reset);
    RUN(t08_not_for_me);
    RUN(t09_unknown_sender);
    RUN(t10_forged_high_counter);
    RUN(t11_malformed);
    RUN(t12_size_limit);
    RUN(t13_counter_exhaustion);
    RUN(t14_repeated_epoch);
    RUN(t15_argument_checks);
    RUN(t16_purpose_validation);
    RUN(t17_key_edge_cases);
    RUN(t18_peer_id_checks);
    RUN(t19_known_answers);
    RUN(t20_crypto_failure);
    RUN(t21_create_failures);
    RUN(t22_concurrent_bad_tags);
    RUN(t23_concurrent_sign);
    RUN(t24_concurrent_consecutive);
    RUN(t25_receiver_restart);
    RUN(t26_verify_from_right_sender);
    RUN(t27_cross_link);
    RUN(t28_wrong_sender_before_tag);
    RUN(t29_verify_from_arguments_and_outputs);
    RUN(t30_verify_from_bit_flips);
    RUN(t31_verify_from_crypto_failure);
    RUN(t32_context_stats);
    RUN(t33_concurrent_verify_from);

    const int leaks = shim_live_allocs(), keys = shim_live_keys();
    if (leaks || keys) {
        fprintf(stderr, "FAIL: %d allocations and %d keys still live at exit\n", leaks, keys);
        s_failed++;
    }
    printf("%d checks, %d failed\n", s_checks, s_failed);
    mbedtls_psa_crypto_free();
    return s_failed ? 1 : 0;
}
