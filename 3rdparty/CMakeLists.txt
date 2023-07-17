find_package(OpenSSL)

if (NOT ${OPENSSL_FOUND})
    message(FATAL_ERROR "Couldn't find openssl")
endif ()

set(APPLE_OPPENSSH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/apple-openssh")
set(ODIR "${APPLE_OPPENSSH_DIR}/openssh")
set(CDIR "${ODIR}/openbsd-compat")

add_library(bcrypt_pbkdf STATIC ${CDIR}/bcrypt_pbkdf.c ${ODIR}/hash.c ${CDIR}/blowfish.c ${CDIR}/explicit_bzero.c ${CDIR}/blowfish.c ${CDIR}/freezero.c)
target_include_directories(bcrypt_pbkdf PRIVATE "${APPLE_OPPENSSH_DIR}/openssh" ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bcrypt_pbkdf OpenSSL::Crypto)

add_custom_target(openssh_config_h
                   COMMAND ${CMAKE_COMMAND} -E copy "${APPLE_OPPENSSH_DIR}/generated-config.h" "${APPLE_OPPENSSH_DIR}/openssh/config.h"
)

add_dependencies(bcrypt_pbkdf openssh_config_h)
