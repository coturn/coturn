# Author: Kang Lin <kl222@126.com>

project(turnserver)

check_function_exists("pthread_barrier_init" HAVE_THREAD_BARRIERS)
if(NOT HAVE_THREAD_BARRIERS)
    list(APPEND turnserver_DEFINED TURN_NO_THREAD_BARRIERS)
endif()

if(MSVC OR MINGW)
    list(APPEND turnserver_LIBS iphlpapi)
endif()

set(HEADER_FILES
    tls_listener.h
    mainrelay.h
    turn_admin_server.h
    dtls_listener.h
    libtelnet.h
    ns_ioalib_impl.h
    ns_sm.h
    turn_ports.h
    userdb.h
    dbdrivers/dbdriver.h
    prom_server.h
    dbdrivers/dbd_redis.h
    )

set(SOURCE_FILES
    mainrelay.c
    netengine.c
    libtelnet.c
    turn_admin_server.c
    tls_listener.c
    dtls_listener.c
    ns_ioalib_engine_impl.c
    turn_ports.c
    http_server.c
    acme.c
    userdb.c
    dbdrivers/dbdriver.c
    prom_server.c
    dbdrivers/dbd_redis.c
    )

find_package(SQLite)
if(SQLite_FOUND)
    list(APPEND turnserver_LIBS SQLite::sqlite)
    list(APPEND SOURCE_FILES dbdrivers/dbd_sqlite.c)
    list(APPEND HEADER_FILES dbdrivers/dbd_sqlite.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_SQLITE)
endif()

find_package(PostgreSQL)
if(PostgreSQL_FOUND)
    list(APPEND turnserver_LIBS PostgreSQL::pq)
    list(APPEND SOURCE_FILES dbdrivers/dbd_pgsql.c)
    list(APPEND HEADER_FILES dbdrivers/dbd_pgsql.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_PQ)
endif()

option(WITH_MYSQL "Use mysql" ON)
if(WITH_MYSQL)
    find_package(MySQL)
    if(MySQL_FOUND)
    list(APPEND turnserver_LIBS MySQL::mysql)
    list(APPEND SOURCE_FILES dbdrivers/dbd_mysql.c)
      list(APPEND HEADER_FILES dbdrivers/dbd_mysql.h)
    else()
        list(APPEND turnserver_DEFINED TURN_NO_MYSQL)
    endif()
else()
    list(APPEND turnserver_DEFINED TURN_NO_MYSQL)
endif()

if(WIN32 OR APPLE)
	find_package(mongoc-1.0)
	if(mongoc-1.0_FOUND)
		list(APPEND turnserver_LIBS mongo::mongoc_shared)
    list(APPEND SOURCE_FILES dbdrivers/dbd_mongo.c)
		list(APPEND HEADER_FILES dbdrivers/dbd_mongo.h)
	else()
		list(APPEND turnserver_DEFINED TURN_NO_MONGO)
	endif()
else()
	find_package(mongo)
	if(mongo_FOUND)
        list(APPEND turnserver_LIBS mongo)
        list(APPEND SOURCE_FILES dbdrivers/dbd_mongo.c)
		list(APPEND HEADER_FILES dbdrivers/dbd_mongo.h)
	else()
        list(APPEND turnserver_DEFINED TURN_NO_MONGO)
	endif()
endif()

pkg_check_modules(HIREDIS IMPORTED_TARGET hiredis)
if(HIREDIS_FOUND)
    list(APPEND turnserver_LIBS PkgConfig::HIREDIS)
    list(APPEND SOURCE_FILES hiredis_libevent2.c dbdrivers/dbd_redis.c)
    list(APPEND HEADER_FILES hiredis_libevent2.h dbdrivers/dbd_redis.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_HIREDIS)
endif()

if(UNIX AND (NOT APPLE))
    find_package(libsystemd)
    if(NOT libsystemd_FOUND)
        list(APPEND turnserver_DEFINED TURN_NO_SYSTEMD)
    endif()
else()
    list(APPEND turnserver_DEFINED TURN_NO_SYSTEMD)
endif()

find_package(Prometheus)
if(Prometheus_FOUND)
    list(APPEND turnserver_LIBS ${Prometheus_LIBRARIES})
    list(APPEND turnserver_include_dirs ${Prometheus_INCLUDE_DIRS})
else()
    message(AUTHOR_WARNING "Could not find prometheus. Please install "
        "prom, microhttpd, and set Prometheus_ROOT. "
        "See docs/Prometheus.md")
    list(APPEND turnserver_DEFINED TURN_NO_PROMETHEUS)
endif()

list(APPEND turnserver_DEFINED TURN_NO_SCTP)

message("turnserver_LIBS:${turnserver_LIBS}")

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE turn_server ${turnserver_LIBS})
target_include_directories(${PROJECT_NAME} PRIVATE ${turnserver_include_dirs})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${turnserver_DEFINED})
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

INSTALL(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    )

install(DIRECTORY
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/
    DESTINATION DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    )

if(WIN32)
    add_custom_target(turnadmin ALL
        COMMAND
            ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:${PROJECT_NAME}>/turnadmin.exe
        DEPENDS ${PROJECT_NAME})
    INSTALL(FILES $<TARGET_FILE_DIR:${PROJECT_NAME}>/turnadmin.exe
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT Runtime)
else()
    add_custom_target(turnadmin ALL
        COMMAND
            ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:${PROJECT_NAME}>/turnadmin
        DEPENDS ${PROJECT_NAME})
    INSTALL(FILES $<TARGET_FILE_DIR:${PROJECT_NAME}>/turnadmin
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT Runtime
		)
endif()
