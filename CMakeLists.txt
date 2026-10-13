idf_component_register(
    SRCS              "src/msg_auth.c" "src/msg_auth_pure.c"
    INCLUDE_DIRS      "include"
    PRIV_INCLUDE_DIRS "private" "src"
    PRIV_REQUIRES     mbedtls heap log
)

# MAC path (MSG_AUTH_SPEC.md §9). Default: primary path, truncated-MAC key policy (§9.1).
# If the target's PSA rejects that policy (§9.3):  idf.py -DMSG_AUTH_MAC_FALLBACK=1 build
# Wire format and results are identical on both paths.
if(MSG_AUTH_MAC_FALLBACK)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE MSG_AUTH_MAC_FALLBACK=1)
endif()
