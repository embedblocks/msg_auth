idf_component_register(
    SRCS     "sign_verify.c" "target_checks.c"
    REQUIRES msg_auth nvs_flash esp_timer mbedtls heap
)

# Report the MAC path msg_auth was built with (the same -D the component reads).
if(MSG_AUTH_MAC_FALLBACK)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE EXAMPLE_MAC_FALLBACK=1)
endif()
