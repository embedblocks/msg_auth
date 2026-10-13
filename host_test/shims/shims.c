/* Host shim implementations and fault injection (see shims.h). */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "freertos/semphr.h"
#include "psa/crypto.h"
#include "shims.h"

int shim_log_verbose = 0;

const char *esp_err_to_name(esp_err_t err)
{
    switch (err) {
    case ESP_OK:                return "ESP_OK";
    case ESP_FAIL:              return "ESP_FAIL";
    case ESP_ERR_NO_MEM:        return "ESP_ERR_NO_MEM";
    case ESP_ERR_INVALID_ARG:   return "ESP_ERR_INVALID_ARG";
    case ESP_ERR_INVALID_STATE: return "ESP_ERR_INVALID_STATE";
    case ESP_ERR_INVALID_SIZE:  return "ESP_ERR_INVALID_SIZE";
    default:                    return "UNKNOWN ERROR";
    }
}

/* ---- heap ---- */

shim_faults_t shim_faults;
static atomic_int s_live_allocs;
static atomic_int s_live_keys;
static atomic_long s_mac_calls;

void *heap_caps_calloc(size_t n, size_t size, unsigned caps)
{
    (void)caps;
    if (shim_faults.heap) {
        return NULL;
    }
    void *p = calloc(n, size);
    if (p) atomic_fetch_add(&s_live_allocs, 1);
    return p;
}

void heap_caps_free(void *p)
{
    if (p) atomic_fetch_sub(&s_live_allocs, 1);
    free(p);
}

/* ---- semaphores ---- */

SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *storage)
{
    if (shim_faults.mutex || storage == NULL) {
        return NULL;
    }
    pthread_mutex_init(&storage->m, NULL);
    return storage;
}

BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t wait)
{
    (void)wait;
    return pthread_mutex_lock(&s->m) == 0 ? pdTRUE : pdFALSE;
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t s)
{
    return pthread_mutex_unlock(&s->m) == 0 ? pdTRUE : pdFALSE;
}

void vSemaphoreDelete(SemaphoreHandle_t s)
{
    pthread_mutex_destroy(&s->m);
}

/* ---- PSA wrappers (-Wl,--wrap=...) ---- */

psa_status_t __real_psa_crypto_init(void);
psa_status_t __real_psa_key_derivation_input_bytes(psa_key_derivation_operation_t *op,
        psa_key_derivation_step_t step, const uint8_t *data, size_t len);
psa_status_t __real_psa_import_key(const psa_key_attributes_t *attr, const uint8_t *data,
        size_t len, mbedtls_svc_key_id_t *key);
psa_status_t __real_psa_key_derivation_input_key(psa_key_derivation_operation_t *op,
        psa_key_derivation_step_t step, mbedtls_svc_key_id_t key);
psa_status_t __real_psa_key_derivation_output_key(const psa_key_attributes_t *attr,
        psa_key_derivation_operation_t *op, mbedtls_svc_key_id_t *key);
psa_status_t __real_psa_destroy_key(mbedtls_svc_key_id_t key);
psa_status_t __real_psa_mac_compute(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
        const uint8_t *in, size_t in_len, uint8_t *mac, size_t mac_size, size_t *mac_len);
psa_status_t __real_psa_mac_verify(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
        const uint8_t *in, size_t in_len, const uint8_t *mac, size_t mac_len);

/* Every key created through import or derivation, to count the live ones. */
#define MAX_TRACKED 64
static pthread_mutex_t s_keys_lock = PTHREAD_MUTEX_INITIALIZER;
static psa_key_id_t    s_keys[MAX_TRACKED];

static void track(psa_key_id_t key)
{
    pthread_mutex_lock(&s_keys_lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (s_keys[i] == 0) { s_keys[i] = key; break; }
    }
    pthread_mutex_unlock(&s_keys_lock);
    atomic_fetch_add(&s_live_keys, 1);
}

psa_status_t __wrap_psa_import_key(const psa_key_attributes_t *attr, const uint8_t *data,
        size_t len, mbedtls_svc_key_id_t *key)
{
    if (shim_faults.import) return PSA_ERROR_INSUFFICIENT_MEMORY;
    psa_status_t st = __real_psa_import_key(attr, data, len, key);
    if (st == PSA_SUCCESS) track(*key);
    return st;
}

psa_status_t __wrap_psa_key_derivation_input_key(psa_key_derivation_operation_t *op,
        psa_key_derivation_step_t step, mbedtls_svc_key_id_t key)
{
    if (shim_faults.derive_input_step != 0 && shim_faults.derive_input_step == (int)step) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    return __real_psa_key_derivation_input_key(op, step, key);
}

psa_status_t __wrap_psa_crypto_init(void)
{
    if (shim_faults.psa_init) return PSA_ERROR_HARDWARE_FAILURE;
    return __real_psa_crypto_init();
}

psa_status_t __wrap_psa_key_derivation_input_bytes(psa_key_derivation_operation_t *op,
        psa_key_derivation_step_t step, const uint8_t *data, size_t len)
{
    if (shim_faults.derive_input_step != 0 && shim_faults.derive_input_step == (int)step) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    return __real_psa_key_derivation_input_bytes(op, step, data, len);
}

psa_status_t __wrap_psa_key_derivation_output_key(const psa_key_attributes_t *attr,
        psa_key_derivation_operation_t *op, mbedtls_svc_key_id_t *key)
{
    if (shim_faults.derive_output) return PSA_ERROR_INSUFFICIENT_MEMORY;
    psa_status_t st = __real_psa_key_derivation_output_key(attr, op, key);
    if (st == PSA_SUCCESS) track(*key);
    return st;
}

psa_status_t __wrap_psa_destroy_key(mbedtls_svc_key_id_t key)
{
    psa_status_t st = __real_psa_destroy_key(key);
    if (st == PSA_SUCCESS) {
        pthread_mutex_lock(&s_keys_lock);
        for (int i = 0; i < MAX_TRACKED; i++) {
            if (s_keys[i] == key) { s_keys[i] = 0; atomic_fetch_sub(&s_live_keys, 1); break; }
        }
        pthread_mutex_unlock(&s_keys_lock);
    }
    return st;
}

psa_status_t __wrap_psa_mac_compute(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
        const uint8_t *in, size_t in_len, uint8_t *mac, size_t mac_size, size_t *mac_len)
{
    atomic_fetch_add(&s_mac_calls, 1);
    if (shim_faults.mac) return PSA_ERROR_HARDWARE_FAILURE;
    return __real_psa_mac_compute(key, alg, in, in_len, mac, mac_size, mac_len);
}

psa_status_t __wrap_psa_mac_verify(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
        const uint8_t *in, size_t in_len, const uint8_t *mac, size_t mac_len)
{
    atomic_fetch_add(&s_mac_calls, 1);
    if (shim_faults.mac) return PSA_ERROR_HARDWARE_FAILURE;
    return __real_psa_mac_verify(key, alg, in, in_len, mac, mac_len);
}

int  shim_live_allocs(void) { return atomic_load(&s_live_allocs); }
int  shim_live_keys(void)   { return atomic_load(&s_live_keys); }
long shim_mac_calls(void)   { return atomic_load(&s_mac_calls); }
void shim_clear_faults(void) { memset(&shim_faults, 0, sizeof shim_faults); }
