/* Host shim: the subset of esp_err.h that msg_auth uses. */
#pragma once
#include <stdint.h>

typedef int esp_err_t;

#define ESP_OK                 0
#define ESP_FAIL              -1
#define ESP_ERR_NO_MEM         0x101
#define ESP_ERR_INVALID_ARG    0x102
#define ESP_ERR_INVALID_STATE  0x103
#define ESP_ERR_INVALID_SIZE   0x104

const char *esp_err_to_name(esp_err_t err);
