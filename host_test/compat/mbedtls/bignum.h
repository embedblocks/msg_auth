/*
 * Host-build stand-in for ESP-IDF's components/mbedtls/port/include/mbedtls/bignum.h.
 *
 * Espressif's Mbed TLS fork includes "mbedtls/bignum.h" from its built-in drivers and
 * provides that header in ESP-IDF's port folder (it adds sdkconfig.h, which a host
 * build does not have). Upstream Mbed TLS never includes this name, so the file is
 * harmless there.
 */
#pragma once
#include "mbedtls/private/bignum.h"
