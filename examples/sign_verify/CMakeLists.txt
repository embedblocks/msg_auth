cmake_minimum_required(VERSION 3.16)

# msg_auth itself, two levels up. No network components: msg_auth needs only bytes.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(msg_auth_sign_verify)
