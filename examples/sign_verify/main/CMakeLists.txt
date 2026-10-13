idf_component_register(
    SRCS     "sign_verify.c"
    REQUIRES msg_auth nvs_flash esp_timer
)
