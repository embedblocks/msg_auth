/* Host shim control: fault injection and resource counters for the tests. */
#pragma once
#include <stdbool.h>

typedef struct {
    bool heap;                  /* heap_caps_calloc returns NULL                   */
    bool mutex;                 /* xSemaphoreCreateMutexStatic returns NULL        */
    bool psa_init;              /* psa_crypto_init fails                           */
    bool import;                /* psa_import_key fails                            */
    int  derive_input_step;     /* nonzero: derivation input fails for this step   */
    bool derive_output;         /* psa_key_derivation_output_key fails             */
    bool mac;                   /* psa_mac_compute / psa_mac_verify fail           */
} shim_faults_t;

extern shim_faults_t shim_faults;
extern int shim_log_verbose;

int  shim_live_allocs(void);    /* heap_caps allocations not yet freed             */
int  shim_live_keys(void);      /* PSA keys imported or derived, not yet destroyed      */
long shim_mac_calls(void);      /* psa_mac_compute + psa_mac_verify calls so far   */
void shim_clear_faults(void);
