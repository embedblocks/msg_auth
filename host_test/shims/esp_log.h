/* Host shim: logging to stderr, enabled with MSG_AUTH_TEST_VERBOSE=1. */
#pragma once
#include <stdio.h>
extern int shim_log_verbose;
#define ESP_LOGE(tag, fmt, ...) do { if (shim_log_verbose) fprintf(stderr, "E %s: " fmt "\n", tag, ##__VA_ARGS__); } while (0)
#define ESP_LOGW ESP_LOGE
#define ESP_LOGI ESP_LOGE
#define ESP_LOGD ESP_LOGE
