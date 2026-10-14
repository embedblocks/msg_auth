/*
 * msg_auth sign_verify: in-process demonstration and acceptance test (MSG_AUTH_SPEC.md §11).
 *
 * No Wi-Fi, no network: msg_auth needs nothing but bytes. These contexts live in
 * one task:
 *
 *   A         node 0, the test key
 *   A'        node 0 again, "after a reboot" (epoch + 1)
 *   B         node 1, the test key: the receiver in every scenario
 *   C         node 2, the test key: a second genuine sender, for the cross-link case
 *   outsider  claims to be node 0, but holds a different key
 *
 * A "channel" is just a buffer passed from one context to another. Each scenario
 * logs its result and expectation and prints PASS or FAIL. Then target_checks.c
 * measures everything MSG_AUTH_SPEC.md §9.3 asks for and prints it as one block.
 *
 * The epoch comes from a boot counter in NVS, committed before any context is
 * created (§6.2). This app reserves two epochs per boot, because it also runs
 * a second "rebooted" A with a higher epoch.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "msg_auth.h"
#include "example.h"

static const char *TAG = "sign_verify";

#define PURPOSE      "status"
#define ID_A         0
#define ID_B         1
#define ID_C         2              /* a second genuine sender */
#define MAX_ID       2

static msg_auth_handle_t s_a, s_a2, s_b, s_c, s_out;
static int s_pass, s_fail;
static uint32_t s_epoch;

/* one envelope buffer, static: 1460 bytes is too much for a default stack */
static uint8_t s_env[MSG_AUTH_MAX_ENVELOPE + 1];
static size_t  s_env_len;
static uint8_t s_msg[MSG_AUTH_MAX_MESSAGE];

/* ---- helpers ---- */

static size_t parse_hex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = hex; p[0] && p[1] && n < cap; p += 2) {
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) {
            return 0;
        }
        out[n++] = (uint8_t)v;
    }
    return (strlen(hex) == 2 * n) ? n : 0;
}

/* §6.2: read the boot counter, commit the incremented value, and only then use it.
 * Fails closed: any NVS error stops the app before a context exists. */
static uint32_t reserve_epochs(uint32_t count)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* Erased storage is a recovery event (§6.2 rule 4): peers that remember
         * this node will reject it until they run msg_auth_reset_peer(). */
        ESP_LOGW(TAG, "NVS erased: epoch restarts, peers need a reset (§6.4)");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("msg_auth_ex", NVS_READWRITE, &nvs));
    uint32_t last = 0;
    err = nvs_get_u32(nvs, "epoch", &last);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_ERROR_CHECK(err);
    }
    if (last > UINT32_MAX - count) {
        ESP_LOGE(TAG, "epoch space exhausted: re-provision (§6.2 rule 3)");
        abort();
    }
    ESP_ERROR_CHECK(nvs_set_u32(nvs, "epoch", last + count));
    ESP_ERROR_CHECK(nvs_commit(nvs));           /* committed before create */
    nvs_close(nvs);
    return last + 1;                            /* first of `count` fresh epochs */
}

static void sign_or_die(msg_auth_handle_t from, uint8_t to, const void *msg, size_t len)
{
    ESP_ERROR_CHECK(msg_auth_sign(from, to, msg, len, s_env, sizeof s_env, &s_env_len));
}

static esp_err_t b_verify(const void *in, size_t len, uint8_t *sender,
                          const void **msg, size_t *msg_len)
{
    return msg_auth_verify(s_b, in, len, sender, msg, msg_len);
}

void expect(const char *scenario, esp_err_t got, esp_err_t want)
{
    const bool ok = got == want;
    ok ? s_pass++ : s_fail++;
    ESP_LOGI(TAG, "%-4s %-45s got %-29s want %s", ok ? "PASS" : "FAIL", scenario,
             msg_auth_err_to_name(got), msg_auth_err_to_name(want));
}

/* Verify a copy of the current envelope with one bit flipped. */
static void flip_case(const char *scenario, size_t offset, uint8_t mask, esp_err_t want)
{
    static uint8_t copy[MSG_AUTH_MAX_ENVELOPE];
    memcpy(copy, s_env, s_env_len);
    copy[offset] ^= mask;
    uint8_t s; const void *m; size_t n;
    expect(scenario, b_verify(copy, s_env_len, &s, &m, &n), want);
}

/* ---- scenarios ---- */

static void run_scenarios(void)
{
    uint8_t sender; const void *m; size_t n;
    const char text[] = "temp=21.5;door=closed";

    /* 1. A signs, B verifies: message and sender intact */
    sign_or_die(s_a, ID_B, text, sizeof text);
    esp_err_t err = b_verify(s_env, s_env_len, &sender, &m, &n);
    if (err == ESP_OK && (sender != ID_A || n != sizeof text || memcmp(m, text, n) != 0)) {
        err = ESP_FAIL;                         /* accepted, but not intact */
    }
    expect("A signs, B verifies", err, ESP_OK);

    /* 2. single bit flips (§10 T2): nothing below advances B's state */
    sign_or_die(s_a, ID_B, text, sizeof text);
    flip_case("bit flip: message",          MSG_AUTH_HEADER_SIZE + 3, 0x10, ESP_ERR_MSG_AUTH_BAD_TAG);
    flip_case("bit flip: header counter",   11, 0x01, ESP_ERR_MSG_AUTH_BAD_TAG);
    flip_case("bit flip: header epoch",     4,  0x80, ESP_ERR_MSG_AUTH_BAD_TAG);
    flip_case("bit flip: header receiver",  3,  0x02, ESP_ERR_MSG_AUTH_NOT_FOR_ME);
    flip_case("bit flip: header version",   0,  0x04, ESP_ERR_MSG_AUTH_MALFORMED);
    flip_case("bit flip: tag",              s_env_len - 1, 0x01, ESP_ERR_MSG_AUTH_BAD_TAG);
    expect("unflipped original still accepted", b_verify(s_env, s_env_len, &sender, &m, &n), ESP_OK);

    /* 3. outsider: different key, claims to be node 0 */
    sign_or_die(s_out, ID_B, text, sizeof text);
    expect("outsider signs, B verifies", b_verify(s_env, s_env_len, &sender, &m, &n),
           ESP_ERR_MSG_AUTH_BAD_TAG);

    /* 4. replay */
    sign_or_die(s_a, ID_B, "ring", 4);
    expect("same envelope, first time", b_verify(s_env, s_env_len, &sender, &m, &n), ESP_OK);
    expect("same envelope, second time", b_verify(s_env, s_env_len, &sender, &m, &n),
           ESP_ERR_MSG_AUTH_REPLAY);

    /* 5. addressed to node 2 */
    sign_or_die(s_a, ID_C, text, sizeof text);
    expect("envelope for node 2 given to B", b_verify(s_env, s_env_len, &sender, &m, &n),
           ESP_ERR_MSG_AUTH_NOT_FOR_ME);

    /* 6. oversized, truncated, unsigned */
    sign_or_die(s_a, ID_B, s_msg, MSG_AUTH_MAX_MESSAGE);
    expect("oversized (1461 bytes)", b_verify(s_env, MSG_AUTH_MAX_ENVELOPE + 1, &sender, &m, &n),
           ESP_ERR_INVALID_SIZE);
    expect("truncated (27 bytes)", b_verify(s_env, MSG_AUTH_OVERHEAD - 1, &sender, &m, &n),
           ESP_ERR_MSG_AUTH_MALFORMED);
    const char plain[] = "an unsigned message that was never wrapped";
    expect("unsigned bytes", b_verify(plain, sizeof plain, &sender, &m, &n),
           ESP_ERR_MSG_AUTH_MALFORMED);
    expect("largest envelope (1460 bytes)", b_verify(s_env, s_env_len, &sender, &m, &n), ESP_OK);

    /* 7. A "reboots": second context with epoch + 1, counter back to 0 */
    sign_or_die(s_a2, ID_B, text, sizeof text);
    expect("newer epoch, counter 0", b_verify(s_env, s_env_len, &sender, &m, &n), ESP_OK);

    /* 8. the old epoch is now history */
    sign_or_die(s_a, ID_B, text, sizeof text);
    expect("older epoch", b_verify(s_env, s_env_len, &sender, &m, &n), ESP_ERR_MSG_AUTH_REPLAY);
    ESP_ERROR_CHECK(msg_auth_reset_peer(s_b, ID_A));   /* administrative, local (§6.4) */
    expect("older epoch after msg_auth_reset_peer", b_verify(s_env, s_env_len, &sender, &m, &n),
           ESP_OK);

    /* 9. msg_auth_verify_from: B knows which sender each "link" belongs to */
    msg_auth_rx_info_t info = { 0, 0 };
    sign_or_die(s_a2, ID_B, text, sizeof text);
    err = msg_auth_verify_from(s_b, ID_A, s_env, s_env_len, &m, &n, &info);
    if (err == ESP_OK && (info.epoch != s_epoch + 1 || n != sizeof text)) {
        err = ESP_FAIL;                         /* accepted, but info or message wrong */
    }
    expect("verify_from: A's envelope on A's link", err, ESP_OK);

    sign_or_die(s_c, ID_B, "from C", 6);        /* first message from C */
    expect("verify_from: C's envelope on C's link",
           msg_auth_verify_from(s_b, ID_C, s_env, s_env_len, &m, &n, NULL), ESP_OK);

    /* the cross-link case: C's genuine envelope relayed onto A's link */
    msg_auth_peer_stats_t c_before, c_after;
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(s_b, ID_C, &c_before));
    sign_or_die(s_c, ID_B, "from C", 6);
    expect("verify_from: C's envelope relayed to A's link",
           msg_auth_verify_from(s_b, ID_A, s_env, s_env_len, &m, &n, NULL),
           ESP_ERR_MSG_AUTH_WRONG_SENDER);
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(s_b, ID_C, &c_after));
    expect("verify_from: C's state untouched by relay",
           memcmp(&c_before, &c_after, sizeof c_before) == 0 ? ESP_OK : ESP_FAIL, ESP_OK);
    expect("verify_from: C's own copy still accepted",
           msg_auth_verify_from(s_b, ID_C, s_env, s_env_len, &m, &n, NULL), ESP_OK);
    expect("verify_from: expected sender = own ID",
           msg_auth_verify_from(s_b, ID_B, s_env, s_env_len, &m, &n, NULL), ESP_ERR_INVALID_ARG);
}

static void print_stats(uint8_t peer)
{
    msg_auth_peer_stats_t st;
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(s_b, peer, &st));
    ESP_LOGI(TAG, "B <- node %u: accepted %" PRIu32 ", bad_tag (claimed) %" PRIu32
             ", replay %" PRIu32 ", last (%" PRIu32 ", %" PRIu32 ")%s",
             peer, st.accepted, st.bad_tag, st.replay, st.last_epoch, st.last_counter,
             st.seen ? "" : ", not seen");
}

static void print_ctx_stats(void)
{
    msg_auth_stats_t st;
    ESP_ERROR_CHECK(msg_auth_get_stats(s_b, &st));
    ESP_LOGI(TAG, "B context: bad_tag_total %" PRIu32 ", wrong_sender %" PRIu32,
             st.bad_tag_total, st.wrong_sender);
}

void app_main(void)
{
    ESP_LOGW(TAG, "using the INSECURE example key from menuconfig; never ship it");

    uint8_t key[MSG_AUTH_KEY_MAX], other[MSG_AUTH_KEY_MAX];
    const size_t key_len = parse_hex(CONFIG_EXAMPLE_PSK_HEX, key, sizeof key);
    if (key_len < MSG_AUTH_KEY_MIN) {
        ESP_LOGE(TAG, "EXAMPLE_PSK_HEX must be 32..128 hex digits (16..64 bytes)");
        return;
    }
    memcpy(other, key, key_len);
    other[0] ^= 0x01;                           /* the outsider's key: one bit different */

    const uint32_t epoch = reserve_epochs(2);  /* epoch for A, epoch + 1 for "rebooted" A */
    s_epoch = epoch;
    ESP_LOGI(TAG, "epoch %" PRIu32 " (committed to NVS before create)", epoch);

    msg_auth_config_t cfg = {
        .key = key, .key_len = key_len, .purpose = PURPOSE,
        .my_id = ID_A, .max_peer_id = MAX_ID, .epoch = epoch,
    };
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_a));
    cfg.epoch = epoch + 1;
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_a2));
    cfg.my_id = ID_B;
    cfg.epoch = epoch;                          /* B's own signing is only used by the checks */
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_b));
    cfg.my_id = ID_C;
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_c));
    cfg.key = other;
    cfg.my_id = ID_A;
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &s_out));

    for (size_t i = 0; i < sizeof s_msg; i++) {
        s_msg[i] = (uint8_t)(i * 31 + 7);
    }

    run_scenarios();
    print_stats(ID_A);
    print_stats(ID_C);
    print_ctx_stats();

    /* §9.3: A' (newest epoch) and C sign to B; B also signs to A (for the
     * same-key concurrency check). `key` is still needed for the create check. */
    const example_nodes_t nodes = {
        .a = s_a2, .a_id = ID_A, .b = s_b, .b_id = ID_B, .c = s_c, .c_id = ID_C,
        .a_receiver = s_a,
        .key = key, .key_len = key_len, .purpose = PURPOSE, .max_peer_id = MAX_ID,
    };
    target_checks_run(&nodes);

    memset(key, 0, sizeof key);                 /* not retained by msg_auth: wipe it */
    memset(other, 0, sizeof other);

    ESP_LOGI(TAG, "%s: %d passed, %d failed", s_fail ? "FAIL" : "PASS", s_pass, s_fail);

    msg_auth_delete(s_a);
    msg_auth_delete(s_a2);
    msg_auth_delete(s_b);
    msg_auth_delete(s_c);
    msg_auth_delete(s_out);
}
