/*
 * Build-time checks (MSG_AUTH_SPEC.md §9, §10). ESP-IDF builds only.
 */
#pragma once

#include "sdkconfig.h"
#include "esp_idf_version.h"
#include "psa/crypto.h"

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0) || ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 1, 0)
#error "msg_auth: verified on ESP-IDF 6.0.x only; this ESP-IDF release is unverified"
#endif
#if !defined(PSA_WANT_ALG_SHA_256) || !PSA_WANT_ALG_SHA_256
#error "msg_auth: requires SHA-256 in PSA; set CONFIG_MBEDTLS_SHA256_C=y in menuconfig"
#endif
#if !defined(PSA_WANT_ALG_HMAC) || !PSA_WANT_ALG_HMAC || !defined(PSA_WANT_KEY_TYPE_HMAC) || !PSA_WANT_KEY_TYPE_HMAC
#error "msg_auth: requires PSA_WANT_ALG_HMAC and PSA_WANT_KEY_TYPE_HMAC in the PSA crypto configuration"
#endif
#if !defined(PSA_WANT_ALG_HKDF) || !PSA_WANT_ALG_HKDF
#error "msg_auth: requires PSA_WANT_ALG_HKDF in the PSA crypto configuration"
#endif
#if !defined(MBEDTLS_THREADING_C)
#error "msg_auth: concurrent use of one key ID requires MBEDTLS_THREADING_C (CONFIG_MBEDTLS_THREADING_C=y)"
#endif
