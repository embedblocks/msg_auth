# msg_auth host tests (MSG_AUTH_SPEC.md §10).
#
#   make                 build PSA Crypto once, then run all tests on both MAC paths
#                        (primary §9.1 and fallback §9.2) with ASan + UBSan
#   make primary         primary path only
#   make fallback        fallback path only
#   make fixtures        regenerate fixtures/msg_auth_kat.h (Python 3, stdlib only)
#   make clean
#
# PSA Crypto comes from the Mbed TLS 4.x tree that ESP-IDF 6.0 ships, so the
# tests run against the same library source as the target. Override with
#   make MBEDTLS_DIR=/path/to/mbedtls-4.x
# (a checkout of Mbed TLS 4.x with its tf-psa-crypto submodule).
# On WSL with ESP-IDF installed on Windows, point IDF_PATH at it through /mnt:
#   make IDF_PATH=/mnt/c/esp/v6.0/esp-idf
# After changing IDF_PATH or MBEDTLS_DIR, run `make clean` first.

IDF_PATH    ?= $(HOME)/esp/esp-idf
MBEDTLS_DIR ?= $(IDF_PATH)/components/mbedtls/mbedtls
PSA_SRC     := $(MBEDTLS_DIR)/tf-psa-crypto

OUT     := out
PSA_OUT := $(OUT)/psa
PSA_LIB := $(PSA_OUT)/core/libtfpsacrypto.a
PSA_CFG := $(OUT)/host_crypto_config.h

COMP := ..
SAN  := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined
CFLAGS += -std=c11 -D_GNU_SOURCE -g -O1 -Wall -Wextra -Werror -Wno-unused-parameter $(SAN) \
          -DMSG_AUTH_HOST_TEST \
          -Ishims -I. -I$(COMP)/include -I$(COMP)/private \
          -I$(PSA_SRC)/include -I$(PSA_SRC)/drivers/builtin/include -I$(PSA_OUT)/include \
          -DTF_PSA_CRYPTO_CONFIG_FILE='"$(abspath $(PSA_CFG))"'
WRAPS := psa_crypto_init psa_import_key psa_key_derivation_input_bytes \
         psa_key_derivation_input_key psa_key_derivation_output_key \
         psa_destroy_key psa_mac_compute psa_mac_verify
LDFLAGS += $(SAN) $(foreach f,$(WRAPS),-Wl,--wrap=$(f)) -lpthread

SRCS := test_msg_auth.c shims/shims.c $(COMP)/src/msg_auth.c $(COMP)/src/msg_auth_pure.c
DEPS := $(SRCS) $(wildcard $(COMP)/include/*.h $(COMP)/private/*.h shims/*.h shims/freertos/*.h fixtures/*.h)

.PHONY: all primary fallback fixtures clean
all: primary fallback

primary: $(OUT)/test_primary
	./$<
fallback: $(OUT)/test_fallback
	./$<

$(OUT)/test_primary: $(DEPS) $(PSA_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(PSA_LIB) $(LDFLAGS)

$(OUT)/test_fallback: $(DEPS) $(PSA_LIB)
	$(CC) $(CFLAGS) -DMSG_AUTH_MAC_FALLBACK=1 -o $@ $(SRCS) $(PSA_LIB) $(LDFLAGS)

# Default PSA configuration plus pthread threading, for the concurrency tests (T22–T24).
# compat/ supplies two headers that Espressif's fork expects from ESP-IDF's port folder.
$(PSA_CFG):
	@test -f $(PSA_SRC)/include/psa/crypto_config.h || { \
	    echo "No Mbed TLS 4.x tf-psa-crypto at $(PSA_SRC)"; \
	    echo "Set IDF_PATH to an ESP-IDF 6.0 tree (mbedtls submodule checked out) or MBEDTLS_DIR."; exit 1; }
	@mkdir -p $(OUT)
	cp $(PSA_SRC)/include/psa/crypto_config.h $@
	python3 $(PSA_SRC)/scripts/config.py --file $@ set MBEDTLS_THREADING_C
	python3 $(PSA_SRC)/scripts/config.py --file $@ set MBEDTLS_THREADING_PTHREAD

$(PSA_LIB): $(PSA_CFG)
	cmake -S $(PSA_SRC) -B $(PSA_OUT) -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=OFF \
	      -DENABLE_PROGRAMS=OFF -DTF_PSA_CRYPTO_CONFIG_FILE=$(abspath $(PSA_CFG)) \
	      -DCMAKE_C_FLAGS="-I$(abspath compat)"
	cmake --build $(PSA_OUT) --target tfpsacrypto -j

fixtures:
	python3 -I fixtures/gen_fixtures.py > fixtures/msg_auth_kat.h

clean:
	rm -rf $(OUT)
