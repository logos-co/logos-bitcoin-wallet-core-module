# The module lives in the Rust crate under rust-lib/; the builder compiles it to a
# staticlib and links it into the plugin with the generated Qt glue.
cmake_minimum_required(VERSION 3.14)
project(BitcoinWalletCoreModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found")
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/metadata.json" METADATA_JSON)
string(JSON MODULE_NAME GET ${METADATA_JSON} name)

# On Windows the OpenSSL SQLCipher bundles reads the certificate store (winstore) through crypt32.
if(WIN32)
    set(CORE_LINK_LIBRARIES crypt32)
endif()
logos_module(NAME ${MODULE_NAME} LINK_LIBRARIES ${CORE_LINK_LIBRARIES})
