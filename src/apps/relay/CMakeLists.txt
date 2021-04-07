# Author: Kang Lin (kl222@126.com)

project(turnserver)

set(HEAD_FILES
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
    )

find_package(SQLite)
if(SQLite_FOUND)
    list(APPEND turnserver_LIBS SQLite::sqlite)
    list(APPEND SOURCE_FILES dbdrivers/dbd_sqlite.c)
    list(APPEND HEAD_FILES dbdrivers/dbd_sqlite.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_SQLITE)
endif()

find_package(PostgreSQL)
if(PostgreSQL_FOUND)
    list(APPEND turnserver_LIBS PostgreSQL::pq)
    list(APPEND SOURCE_FILES dbdrivers/dbd_pgsql.c)
    list(APPEND HEAD_FILES dbdrivers/dbd_pgsql.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_PQ)
endif()

find_package(MySQL)
if(MySQL_FOUND)
    list(APPEND turnserver_LIBS MySQL::mysql)
    list(APPEND SOURCE_FILES dbdrivers/dbd_mysql.c)
    list(APPEND HEAD_FILES dbdrivers/dbd_mysql.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_MYSQL)
endif()

find_package(mongo)
if(mongo_FOUND)
    list(APPEND turnserver_LIBS mongo)
    list(APPEND SOURCE_FILES dbdrivers/dbd_mongo.c)
    list(APPEND HEAD_FILES dbdrivers/dbd_mongo.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_MONGO)
endif()

find_package(hiredis)
if(hiredis_FOUND)
    list(APPEND turnserver_LIBS hiredis::hiredis)
    list(APPEND SOURCE_FILES dbdrivers/dbd_redis.c)
    list(APPEND HEAD_FILES dbdrivers/dbd_redis.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_HIREDIS)
endif()

find_package(libsystemd)
if(libsystemd_FOUND)
else()
    list(APPEND turnserver_DEFINED TURN_NO_SYSTEMD)
endif()

find_package(Prometheus)
if(Prometheus_FOUND)
    list(APPEND SOURCE_FILES prom_server.c)
    list(APPEND HEAD_FILES prom_server.h)
else()
    list(APPEND turnserver_DEFINED TURN_NO_PROMETHEUS)
endif()

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEAD_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE turn_server ${turnserver_LIBS})
target_include_directories(${PROJECT_NAME} PRIVATE ${turnserver_include_dirs})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${turnserver_DEFINED})

add_custom_target(turnadmin ALL
    COMMAND 
        ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE_NAME:${PROJECT_NAME}> turnadmin
    DEPENDS ${PROJECT_NAME})

INSTALL(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    )

INSTALL(FILES $<TARGET_FILE_DIR:${PROJECT_NAME}>/turnadmin
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT Runtime)
