/*
 * The target checks of MSG_AUTH_SPEC.md §9.3, measured in one run.
 *
 * Prints a block of lines starting with "9.3 |" that can be pasted into the
 * spec's §9.3 table. Correctness checks (concurrency, psa_crypto_init) also
 * count as PASS/FAIL scenarios of the example.
 *
 * What each figure means:
 *   heap, create     bytes one msg_auth_create() takes (the context plus PSA's key
 *                    slot), and what is left after msg_auth_delete() (should be 0)
 *   heap, per call   peak: the deepest transient heap use during the calls (this
 *                    includes PSA's own allocations; msg_auth itself makes none);
 *                    net: heap not returned after the calls (should be 0)
 *   stack            bytes of task stack a single call uses, measured as the change
 *                    of the high-water mark in a fresh task
 *   latency          mean microseconds per call, esp_timer, interrupts enabled
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "psa/crypto.h"
#include "sdkconfig.h"
#include "soc/soc_caps.h"
#include "msg_auth.h"
#include "example.h"

static const char *TAG = "target_checks";

#ifdef EXAMPLE_MAC_FALLBACK
#define MAC_PATH "fallback (§9.2, full HMAC key policy, truncated by msg_auth)"
#else
#define MAC_PATH "primary (§9.1, truncated-MAC key policy)"
#endif

#define REC(fmt, ...)  ESP_LOGI(TAG, "9.3 | " fmt, ##__VA_ARGS__)

static const example_nodes_t *N;

static uint8_t s_msg[MSG_AUTH_MAX_MESSAGE];
static uint8_t s_env[MSG_AUTH_MAX_ENVELOPE];
static size_t  s_env_len;

static esp_err_t sign_to_b(msg_auth_handle_t from, size_t len)
{
    return msg_auth_sign(from, N->b_id, s_msg, len, s_env, sizeof s_env, &s_env_len);
}

/* ================= build and configuration ================= */

static void record_build(void)
{
    REC("ESP-IDF %s, target %s, %d core(s)", esp_get_idf_version(), CONFIG_IDF_TARGET,
        portNUM_PROCESSORS);
    REC("MAC path: %s", MAC_PATH);
#if CONFIG_MBEDTLS_HARDWARE_SHA
    REC("HMAC driver: ESP transparent HMAC driver on the SHA accelerator "
        "(CONFIG_MBEDTLS_HARDWARE_SHA=y)");
#else
    REC("HMAC driver: Mbed TLS built-in software HMAC (CONFIG_MBEDTLS_HARDWARE_SHA=n)");
#endif
#if SOC_HMAC_SUPPORTED
    REC("HMAC peripheral: present on this chip, not used (it takes eFuse keys only; "
        "msg_auth's key is a volatile PSA key)");
#else
    REC("HMAC peripheral: not present on this chip");
#endif
#if CONFIG_MBEDTLS_THREADING_C
    REC("Mbed TLS threading: on");
#else
    REC("Mbed TLS threading: OFF");
#endif
}

/* ================= HKDF into the key, truncated-MAC policy ================= */

static void record_key_policy(void)
{
    /* Contexts already exist and the scenarios passed through them, so both the
     * derivation and the selected key policy work on this target. */
    REC("HKDF into an HMAC key (DERIVE-key import, §5.1 step 5): works "
        "(msg_auth_create succeeded)");
#ifdef EXAMPLE_MAC_FALLBACK
    REC("truncated-MAC policy: not tested by this build (fallback path built); "
        "rebuild without MSG_AUTH_MAC_FALLBACK to test it");
#else
    REC("truncated-MAC policy: accepted (contexts created with it; sign/verify scenarios pass)");
#endif
}

/* ================= psa_crypto_init when already initialised ================= */

static void record_psa_init(void)
{
    const psa_status_t st = psa_crypto_init();
    expect("psa_crypto_init when already initialised", st == PSA_SUCCESS ? ESP_OK : ESP_FAIL,
           ESP_OK);
    REC("psa_crypto_init() when already initialised: %d (%s); failure handling: host test T21",
        (int)st, st == PSA_SUCCESS ? "PSA_SUCCESS" : "unexpected");
}

/* ================= heap ================= */

static void record_heap_create(void)
{
    const msg_auth_config_t cfg = {
        .key = N->key, .key_len = N->key_len, .purpose = N->purpose,
        .my_id = 0, .max_peer_id = N->max_peer_id, .epoch = 1,
    };
    const size_t before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    msg_auth_handle_t h = NULL;
    ESP_ERROR_CHECK(msg_auth_create(&cfg, &h));
    const size_t created = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    ESP_ERROR_CHECK(msg_auth_delete(h));
    const size_t after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    REC("heap, create (max_peer_id %u): %d bytes; after delete: %d bytes not returned",
        N->max_peer_id, (int)(before - created), (int)(before - after));
}

#define HEAP_CALLS 32
static uint8_t s_heap_env[HEAP_CALLS][64 + MSG_AUTH_OVERHEAD];
static size_t  s_heap_len[HEAP_CALLS];

typedef enum { OP_SIGN, OP_VERIFY, OP_VERIFY_FROM } op_t;
static const char *const OP_NAME[] = { "sign", "verify", "verify_from" };

static void record_heap_calls(op_t op)
{
    if (op != OP_SIGN) {                        /* fresh envelopes, signed beforehand */
        for (int i = 0; i < HEAP_CALLS; i++) {
            ESP_ERROR_CHECK(msg_auth_sign(N->a, N->b_id, s_msg, 64, s_heap_env[i],
                                          sizeof s_heap_env[i], &s_heap_len[i]));
        }
    }
    const size_t before = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_start());
    esp_err_t err = ESP_OK;
    for (int i = 0; i < HEAP_CALLS && err == ESP_OK; i++) {
        const void *m; size_t ml; uint8_t s;
        switch (op) {
        case OP_SIGN:
            err = sign_to_b(N->a, 64);
            break;
        case OP_VERIFY:
            err = msg_auth_verify(N->b, s_heap_env[i], s_heap_len[i], &s, &m, &ml);
            break;
        case OP_VERIFY_FROM:
            err = msg_auth_verify_from(N->b, N->a_id, s_heap_env[i], s_heap_len[i], &m, &ml, NULL);
            break;
        }
    }
    const size_t low = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_stop());
    const size_t after = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    ESP_ERROR_CHECK(err);
    REC("heap, %-11s (64 B, %d calls): peak %d bytes during a call, net %d bytes",
        OP_NAME[op], HEAP_CALLS, (int)(before - low), (int)(before - after));
}

/* ================= stack ================= */

typedef struct {
    op_t              op;
    esp_err_t         err;
    UBaseType_t       used;
    SemaphoreHandle_t done;
} stack_job_t;

static uint8_t s_stack_env[MSG_AUTH_MAX_ENVELOPE];
static size_t  s_stack_len;

static void stack_task(void *arg)
{
    stack_job_t *j = arg;
    const UBaseType_t before = uxTaskGetStackHighWaterMark(NULL);
    const void *m; size_t ml; uint8_t s;
    switch (j->op) {
    case OP_SIGN:
        j->err = sign_to_b(N->a, MSG_AUTH_MAX_MESSAGE);
        break;
    case OP_VERIFY:
        j->err = msg_auth_verify(N->b, s_stack_env, s_stack_len, &s, &m, &ml);
        break;
    case OP_VERIFY_FROM:
        j->err = msg_auth_verify_from(N->b, N->a_id, s_stack_env, s_stack_len, &m, &ml, NULL);
        break;
    }
    j->used = before - uxTaskGetStackHighWaterMark(NULL);   /* bytes on ESP-IDF */
    xSemaphoreGive(j->done);
    vTaskDelete(NULL);
}

static void record_stack(op_t op)
{
    if (op != OP_SIGN) {
        ESP_ERROR_CHECK(msg_auth_sign(N->a, N->b_id, s_msg, MSG_AUTH_MAX_MESSAGE, s_stack_env,
                                      sizeof s_stack_env, &s_stack_len));
    }
    stack_job_t j = { .op = op, .err = ESP_FAIL, .done = xSemaphoreCreateBinary() };
    if (xTaskCreate(stack_task, "stack_probe", 8192, &j, 5, NULL) != pdPASS) {
        abort();
    }
    xSemaphoreTake(j.done, portMAX_DELAY);
    vSemaphoreDelete(j.done);
    ESP_ERROR_CHECK(j.err);
    REC("stack, %-11s (1432 B): %u bytes", OP_NAME[op], (unsigned)j.used);
}

/* ================= latency ================= */

#define TIMING_RUNS 100

static void record_latency(size_t len)
{
    int64_t t_sign = 0, t_verify = 0, t_from = 0;
    for (int i = 0; i < 2 * TIMING_RUNS; i++) {
        int64_t t0 = esp_timer_get_time();
        ESP_ERROR_CHECK(sign_to_b(N->a, len));
        int64_t t1 = esp_timer_get_time();
        const void *m; size_t ml; uint8_t s;
        esp_err_t err;
        if (i % 2 == 0) {
            err = msg_auth_verify(N->b, s_env, s_env_len, &s, &m, &ml);
        } else {
            err = msg_auth_verify_from(N->b, N->a_id, s_env, s_env_len, &m, &ml, NULL);
        }
        int64_t t2 = esp_timer_get_time();
        ESP_ERROR_CHECK(err);
        t_sign += t1 - t0;
        *(i % 2 == 0 ? &t_verify : &t_from) += t2 - t1;
    }
    REC("latency %4u B: sign %5" PRId64 " us, verify %5" PRId64 " us, verify_from %5" PRId64
        " us (mean of %d)", (unsigned)len, t_sign / (2 * TIMING_RUNS), t_verify / TIMING_RUNS,
        t_from / TIMING_RUNS, TIMING_RUNS);
}

/* ================= concurrency on one key ID ================= */
/*
 * Four tasks use B's context, and therefore B's single PSA key ID, at once:
 *   two signers   B signs to A                    (counters must be distinct)
 *   verifier A    B verifies A's stream           (verify_from(A); every 8th a bad tag)
 *   verifier C    B verifies C's stream           (verify_from(C); every 8th a bad tag)
 * Afterwards A verifies every envelope the signers produced, in counter order,
 * and B's statistics must match the counts exactly.
 */
#define CC_PER     200
#define CC_MSG     32
#define CC_ENV     (CC_MSG + MSG_AUTH_OVERHEAD)
#define CC_START   BIT0

typedef struct {
    uint8_t  buf[CC_PER][CC_ENV];
    uint8_t  corrupt[CC_PER];
} cc_stream_t;

static cc_stream_t s_cc_a, s_cc_c;
static uint8_t     s_cc_signed[2][CC_PER][CC_ENV];

typedef struct {
    int                 kind;           /* 0, 1: signer index; 2: verifier A; 3: verifier C */
    int                 failures;
    EventGroupHandle_t  start;
    SemaphoreHandle_t   done;
} cc_job_t;

static void cc_task(void *arg)
{
    cc_job_t *j = arg;
    xEventGroupWaitBits(j->start, CC_START, pdFALSE, pdTRUE, portMAX_DELAY);
    for (int i = 0; i < CC_PER; i++) {
        if (j->kind < 2) {
            size_t len = 0;
            if (msg_auth_sign(N->b, N->a_id, s_msg, CC_MSG, s_cc_signed[j->kind][i], CC_ENV,
                              &len) != ESP_OK || len != CC_ENV) {
                j->failures++;
            }
        } else {
            const cc_stream_t *st = j->kind == 2 ? &s_cc_a : &s_cc_c;
            const uint8_t expected = j->kind == 2 ? N->a_id : N->c_id;
            const void *m; size_t ml;
            const esp_err_t want = st->corrupt[i] ? ESP_ERR_MSG_AUTH_BAD_TAG : ESP_OK;
            if (msg_auth_verify_from(N->b, expected, st->buf[i], CC_ENV, &m, &ml, NULL) != want) {
                j->failures++;
            }
        }
        if ((i & 15) == 15) {
            taskYIELD();
        }
    }
    xSemaphoreGive(j->done);
    vTaskDelete(NULL);
}

static uint32_t env_counter(const uint8_t *e)
{
    return ((uint32_t)e[8] << 24) | ((uint32_t)e[9] << 16) | ((uint32_t)e[10] << 8) | e[11];
}

static int cmp_counter(const void *x, const void *y)
{
    const uint32_t a = env_counter(x), b = env_counter(y);
    return (a > b) - (a < b);
}

static void fill_stream(cc_stream_t *st, msg_auth_handle_t from)
{
    for (int i = 0; i < CC_PER; i++) {
        size_t len = 0;
        ESP_ERROR_CHECK(msg_auth_sign(from, N->b_id, s_msg, CC_MSG, st->buf[i], CC_ENV, &len));
        st->corrupt[i] = (i % 8) == 7;
        if (st->corrupt[i]) {
            st->buf[i][CC_ENV - 1] ^= 0x01;     /* that genuine message is never delivered */
        }
    }
}

static void record_concurrency(void)
{
    fill_stream(&s_cc_a, N->a);
    fill_stream(&s_cc_c, N->c);
    msg_auth_stats_t ctx0, ctx1;
    msg_auth_peer_stats_t pa0, pa1, pc0, pc1;
    ESP_ERROR_CHECK(msg_auth_get_stats(N->b, &ctx0));
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(N->b, N->a_id, &pa0));
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(N->b, N->c_id, &pc0));

    EventGroupHandle_t start = xEventGroupCreate();
    SemaphoreHandle_t  done  = xSemaphoreCreateCounting(4, 0);
    cc_job_t jobs[4];
    for (int k = 0; k < 4; k++) {
        jobs[k] = (cc_job_t){ .kind = k, .start = start, .done = done };
        if (xTaskCreatePinnedToCore(cc_task, "cc", 4096, &jobs[k], 5, NULL,
                                    tskNO_AFFINITY) != pdPASS) {
            abort();
        }
    }
    const int64_t t0 = esp_timer_get_time();
    xEventGroupSetBits(start, CC_START);
    for (int k = 0; k < 4; k++) {
        xSemaphoreTake(done, portMAX_DELAY);
    }
    const int64_t elapsed = esp_timer_get_time() - t0;
    vEventGroupDelete(start);
    vSemaphoreDelete(done);

    int failures = 0;
    for (int k = 0; k < 4; k++) {
        failures += jobs[k].failures;
    }

    /* signers: counters distinct, and every envelope authentic to A in counter order */
    static uint8_t all[2 * CC_PER][CC_ENV];
    memcpy(all, s_cc_signed, sizeof all);
    qsort(all, 2 * CC_PER, CC_ENV, cmp_counter);
    int dup = 0, rejected = 0;
    for (int i = 0; i < 2 * CC_PER; i++) {
        if (i > 0 && env_counter(all[i]) == env_counter(all[i - 1])) {
            dup++;
        }
        uint8_t s; const void *m; size_t ml;
        if (msg_auth_verify(N->a_receiver, all[i], CC_ENV, &s, &m, &ml) != ESP_OK) {
            rejected++;
        }
    }

    /* statistics exact */
    const uint32_t bad_per_stream = CC_PER / 8;
    ESP_ERROR_CHECK(msg_auth_get_stats(N->b, &ctx1));
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(N->b, N->a_id, &pa1));
    ESP_ERROR_CHECK(msg_auth_get_peer_stats(N->b, N->c_id, &pc1));
    const bool stats_ok =
        ctx1.bad_tag_total - ctx0.bad_tag_total == 2 * bad_per_stream &&
        pa1.bad_tag - pa0.bad_tag == bad_per_stream &&
        pc1.bad_tag - pc0.bad_tag == bad_per_stream &&
        pa1.accepted - pa0.accepted == CC_PER - bad_per_stream &&
        pc1.accepted - pc0.accepted == CC_PER - bad_per_stream &&
        pa1.replay == pa0.replay && pc1.replay == pc0.replay;

    const bool ok = failures == 0 && dup == 0 && rejected == 0 && stats_ok;
    expect("concurrent sign + verify on one key ID", ok ? ESP_OK : ESP_FAIL, ESP_OK);
    REC("concurrency, one key ID, 4 tasks (2 sign, 2 verify_from), %d calls in %" PRId64
        " us: %s (call failures %d, duplicate counters %d, rejected by receiver %d, stats %s)",
        4 * CC_PER, elapsed, ok ? "PASS" : "FAIL", failures, dup, rejected,
        stats_ok ? "exact" : "WRONG");
}

/* ================= entry ================= */

void target_checks_run(const example_nodes_t *n)
{
    N = n;
    for (size_t i = 0; i < sizeof s_msg; i++) {
        s_msg[i] = (uint8_t)(i * 13 + 5);
    }

    /* The concurrency and psa_crypto_init checks also log a PASS/FAIL line;
     * only the "9.3 |" lines belong in the spec. */
    ESP_LOGI(TAG, "---- MSG_AUTH_SPEC.md §9.3 record: copy the \"9.3 |\" lines ----");
    record_build();
    record_key_policy();
    record_concurrency();
    record_psa_init();
    record_heap_create();
    record_heap_calls(OP_SIGN);
    record_heap_calls(OP_VERIFY);
    record_heap_calls(OP_VERIFY_FROM);
    record_stack(OP_SIGN);
    record_stack(OP_VERIFY);
    record_stack(OP_VERIFY_FROM);
    const size_t lens[] = { 0, 64, 512, MSG_AUTH_MAX_MESSAGE };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        record_latency(lens[i]);
    }
    ESP_LOGI(TAG, "---- end of §9.3 record ----");
}
