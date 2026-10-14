/* Shared between sign_verify.c (scenarios) and target_checks.c (§9.3 record). */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "msg_auth.h"

typedef struct {
    msg_auth_handle_t a;            /* signs to b (newest epoch of node a_id)        */
    uint8_t           a_id;
    msg_auth_handle_t b;            /* the receiver; also signs to a_receiver        */
    uint8_t           b_id;
    msg_auth_handle_t c;            /* a second sender to b                          */
    uint8_t           c_id;
    msg_auth_handle_t a_receiver;   /* node a_id as a receiver of b's envelopes      */
    const uint8_t    *key;          /* for the create() heap measurement only        */
    size_t            key_len;
    const char       *purpose;
    uint8_t           max_peer_id;
} example_nodes_t;

/* Logs one PASS/FAIL line and counts it (sign_verify.c). */
void expect(const char *scenario, esp_err_t got, esp_err_t want);

/* Runs every MSG_AUTH_SPEC.md §9.3 check and prints the record block. */
void target_checks_run(const example_nodes_t *n);
