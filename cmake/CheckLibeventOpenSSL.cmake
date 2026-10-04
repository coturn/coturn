# Fail configure when libevent_openssl is linked against a different OpenSSL
# major version than the one coturn builds with.
#
# On macOS two-level namespaces keep both copies loaded in one process, and an
# SSL* created by one OpenSSL gets handed to the other through
# bufferevent_openssl_socket_new(), which crashes in SSL_set_bio. Typical
# trigger: Homebrew's `openssl` formula moving to a new major while libevent
# still depends on the previous one.
#
# turn_check_libevent_openssl_abi(<libevent_openssl library> <OpenSSL major>)
function(turn_check_libevent_openssl_abi event_openssl_lib ssl_major)
    if(NOT APPLE OR NOT event_openssl_lib OR TURN_ALLOW_OPENSSL_MISMATCH)
        return()
    endif()

    find_program(TURN_OTOOL otool)
    if(NOT TURN_OTOOL)
        return()
    endif()

    execute_process(COMMAND ${TURN_OTOOL} -L "${event_openssl_lib}"
        OUTPUT_VARIABLE _otool_out
        RESULT_VARIABLE _otool_rc
        ERROR_QUIET)
    if(NOT _otool_rc EQUAL 0)
        return()
    endif()

    # libssl.3.dylib / libcrypto.3.dylib: the number is the OpenSSL soname major.
    string(REGEX MATCHALL "lib(ssl|crypto)\\.[0-9]+(\\.[0-9]+)*\\.dylib" _deps "${_otool_out}")
    foreach(_dep ${_deps})
        string(REGEX REPLACE "^lib(ssl|crypto)\\.([0-9]+).*$" "\\2" _dep_major "${_dep}")
        if(NOT _dep_major STREQUAL ssl_major)
            message(FATAL_ERROR
                "libevent_openssl (${event_openssl_lib}) links ${_dep}, but coturn is "
                "building against OpenSSL ${ssl_major}.x. Mixing two OpenSSL majors "
                "crashes turnserver on the first TLS connection.\n"
                "Point CMake at the OpenSSL libevent uses (e.g. "
                "-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@${_dep_major})), or rebuild "
                "libevent against OpenSSL ${ssl_major}. Override with "
                "-DTURN_ALLOW_OPENSSL_MISMATCH=ON.")
        endif()
    endforeach()
endfunction()
