include(FetchContent)

FetchContent_Declare(
    Unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.6.0
)
FetchContent_MakeAvailable(Unity)

function(coturn_add_test name)
    add_executable(${name} ${name}.c ${ARGN})
    target_include_directories(${name} PRIVATE ../src/apps/relay)
    target_link_libraries(${name} PRIVATE turnclient unity)
    add_test(NAME ${name} COMMAND ${name})
    list(APPEND COTURN_TEST_TARGETS ${name})
    set(COTURN_TEST_TARGETS ${COTURN_TEST_TARGETS} PARENT_SCOPE)
endfunction()

coturn_add_test(test_ioaddr)
coturn_add_test(test_stun_msg)
coturn_add_test(test_base64)
coturn_add_test(test_http_server ../src/apps/relay/http_buffer.c)
coturn_add_test(test_acme ../src/apps/relay/acme.c)
coturn_add_test(test_redis_conninfo ../src/apps/relay/dbdrivers/dbd_redis_conninfo.c)
coturn_add_test(test_log_min_level)
coturn_add_test(test_ratelimit ../src/server/ns_turn_ratelimit.c)
target_include_directories(test_ratelimit PRIVATE ../src/server ../src)

# Alternate-server list regression test (#1988). The test compiles the real
# src/apps/relay/netengine.c into its own translation unit (to reach the static
# add_alt_server/del_alt_server), with link-only stubs for the rest of the
# relay in test_alt_server_stubs.c, so it needs the relay's full include set.
find_package(OpenSSL QUIET)
find_package(PkgConfig QUIET)
pkg_check_modules(LIBEVENT QUIET libevent)
coturn_add_test(test_alt_server_list test_alt_server_stubs.c)
target_include_directories(test_alt_server_list PRIVATE
    ../src/server
    ../src/apps/common
    ../src
    ../src/client
    ${OPENSSL_INCLUDE_DIR}
    ${LIBEVENT_INCLUDE_DIRS})
target_compile_definitions(test_alt_server_list PRIVATE
    TURN_NO_MONGO TURN_NO_MYSQL TURN_NO_PQ TURN_NO_PROMETHEUS
    TURN_NO_SCTP TURN_NO_SYSTEMD TURN_NO_THREAD_BARRIERS TURN_NO_HIREDIS
    _FILE_OFFSET_BITS=64)
# The #1988 bug left the list mutex locked; if it regresses, the follow-up
# add_alt_server blocks forever, so fail by timeout instead of hanging ctest.
set_tests_properties(test_alt_server_list PROPERTIES TIMEOUT 60)

# SQLite DB-driver interface test. Compiles the driver in isolation with a small
# support/stub layer, so it needs the same include set the relay build uses.
find_package(SQLite QUIET)
if(SQLite_FOUND)
    find_package(OpenSSL QUIET)
    pkg_check_modules(LIBEVENT QUIET libevent)
    add_executable(test_sqlite_dbd
        test_sqlite_dbd.c
        test_sqlite_support.c
        ../src/apps/relay/dbdrivers/dbd_sqlite.c)
    target_include_directories(test_sqlite_dbd PRIVATE
        ../src/apps/relay
        ../src/server
        ../src/apps/common
        ../src
        ../src/client
        ${OPENSSL_INCLUDE_DIR}
        ${LIBEVENT_INCLUDE_DIRS})
    target_compile_definitions(test_sqlite_dbd PRIVATE
        TURN_NO_MONGO TURN_NO_MYSQL TURN_NO_PQ TURN_NO_PROMETHEUS
        TURN_NO_SCTP TURN_NO_SYSTEMD TURN_NO_THREAD_BARRIERS TURN_NO_HIREDIS
        _FILE_OFFSET_BITS=64)
    target_link_libraries(test_sqlite_dbd PRIVATE turnclient unity SQLite::sqlite)
    add_test(NAME test_sqlite_dbd COMMAND test_sqlite_dbd)
    list(APPEND COTURN_TEST_TARGETS test_sqlite_dbd)
else()
    message(STATUS "SQLite not found; skipping test_sqlite_dbd")
endif()

# PostgreSQL DB-driver interface test. libpq is replaced by a capturing stub, so
# only the libpq *headers* are needed (not the library or a server). The shared
# relay stubs come from test_sqlite_support.c.
find_path(LIBPQ_INCLUDE_DIR libpq-fe.h
    HINTS /opt/homebrew/opt/libpq/include /usr/local/opt/libpq/include
          /usr/include/postgresql /usr/local/include)
if(LIBPQ_INCLUDE_DIR)
    find_package(OpenSSL QUIET)
    pkg_check_modules(LIBEVENT QUIET libevent)
    add_executable(test_pgsql_dbd
        test_pgsql_dbd.c
        test_pgsql_stub.c
        test_sqlite_support.c
        ../src/apps/relay/dbdrivers/dbd_pgsql.c)
    target_include_directories(test_pgsql_dbd PRIVATE
        ../src/apps/relay
        ../src/server
        ../src/apps/common
        ../src
        ../src/client
        ${LIBPQ_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LIBEVENT_INCLUDE_DIRS})
    # NB: TURN_NO_PQ is intentionally NOT defined, so the driver body compiles.
    target_compile_definitions(test_pgsql_dbd PRIVATE
        TURN_NO_MONGO TURN_NO_MYSQL TURN_NO_PROMETHEUS
        TURN_NO_SCTP TURN_NO_SYSTEMD TURN_NO_THREAD_BARRIERS TURN_NO_HIREDIS
        _FILE_OFFSET_BITS=64)
    target_link_libraries(test_pgsql_dbd PRIVATE turnclient unity)
    add_test(NAME test_pgsql_dbd COMMAND test_pgsql_dbd)
    list(APPEND COTURN_TEST_TARGETS test_pgsql_dbd)
else()
    message(STATUS "libpq headers not found; skipping test_pgsql_dbd")
endif()

# MySQL DB-driver interface test. libmysqlclient is replaced by a capturing stub,
# so only the MySQL *headers* are needed. OpenSSL is linked for the (compiled but
# never called) decryptPassword() path. Shared relay stubs from
# test_sqlite_support.c.
find_path(MYSQL_INCLUDE_DIR mysql.h
    HINTS /opt/homebrew/opt/mysql-client/include/mysql /opt/homebrew/opt/mysql/include/mysql
          /usr/local/opt/mysql-client/include/mysql /usr/include/mysql /usr/local/include/mysql)
if(MYSQL_INCLUDE_DIR)
    find_package(OpenSSL QUIET)
    pkg_check_modules(LIBEVENT QUIET libevent)
    add_executable(test_mysql_dbd
        test_mysql_dbd.c
        test_mysql_stub.c
        test_sqlite_support.c
        ../src/apps/relay/dbdrivers/dbd_mysql.c)
    target_include_directories(test_mysql_dbd PRIVATE
        ../src/apps/relay
        ../src/server
        ../src/apps/common
        ../src
        ../src/client
        ${MYSQL_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${LIBEVENT_INCLUDE_DIRS})
    # NB: TURN_NO_MYSQL is intentionally NOT defined, so the driver body compiles.
    target_compile_definitions(test_mysql_dbd PRIVATE
        TURN_NO_MONGO TURN_NO_PQ TURN_NO_PROMETHEUS
        TURN_NO_SCTP TURN_NO_SYSTEMD TURN_NO_THREAD_BARRIERS TURN_NO_HIREDIS
        _FILE_OFFSET_BITS=64)
    target_link_libraries(test_mysql_dbd PRIVATE turnclient unity)
    if(OPENSSL_FOUND)
        target_link_libraries(test_mysql_dbd PRIVATE OpenSSL::Crypto)
    endif()
    add_test(NAME test_mysql_dbd COMMAND test_mysql_dbd)
    list(APPEND COTURN_TEST_TARGETS test_mysql_dbd)
else()
    message(STATUS "MySQL headers not found; skipping test_mysql_dbd")
endif()

# Redis format-string-injection regression test (GHSA-4g7c-p5wg-j4hp).
# Compiles the real hiredis_libevent2.c (included by the test) with a capturing
# redisAsyncCommand() stub and asserts attacker-controlled USERNAME/REALM never
# enter the Redis command format string. Needs only the hiredis + libevent
# headers (the hiredis library itself is stubbed out).
pkg_check_modules(HIREDIS QUIET hiredis)
pkg_check_modules(LIBEVENT QUIET libevent)
if(HIREDIS_FOUND AND LIBEVENT_FOUND)
    find_package(OpenSSL QUIET)
    add_executable(test_redis_format test_redis_format.c)
    target_include_directories(test_redis_format PRIVATE
        ../src/apps/relay
        ../src/server
        ../src/apps/common
        ../src
        ../src/client
        ${HIREDIS_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${LIBEVENT_INCLUDE_DIRS})
    target_link_directories(test_redis_format PRIVATE ${LIBEVENT_LIBRARY_DIRS})
    target_link_libraries(test_redis_format PRIVATE turnclient unity ${LIBEVENT_LIBRARIES})
    add_test(NAME test_redis_format COMMAND test_redis_format)
    list(APPEND COTURN_TEST_TARGETS test_redis_format)
else()
    message(STATUS "hiredis/libevent headers not found; skipping test_redis_format")
endif()

# Vendored Prometheus client (src/prometheus). Fully self-contained: only the
# client sources plus pthread are needed, no turnclient/microhttpd.
add_executable(test_prometheus
    test_prometheus.c
    ../src/prometheus/prom.c)
target_include_directories(test_prometheus PRIVATE ../src/prometheus)
find_package(Threads REQUIRED)
target_link_libraries(test_prometheus PRIVATE unity Threads::Threads)
add_test(NAME test_prometheus COMMAND test_prometheus)
list(APPEND COTURN_TEST_TARGETS test_prometheus)

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${COTURN_TEST_TARGETS}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
