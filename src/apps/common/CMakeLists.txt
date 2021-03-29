# Author: Kang Lin (kl222@126.com)

project(turncommon)

set(SOURCE_FILES
    apputils.c
    ns_turn_utils.c
    stun_buffer.c
    )

set(HEADER_FILES
    apputils.h
    ns_turn_openssl.h
    ns_turn_utils.h
    stun_buffer.h
    )

if(NOT WIN32)
    set(COMMON_LIBS pthread)
endif()
set(libevent_components core extra openssl)
if(NOT WIN32)
    list(APPEND libevent_components pthreads)
endif()
find_package(Libevent COMPONENTS ${libevent_components})
if(Libevent_FOUND)
    foreach(_libevent_com ${libevent_components})
        list(APPEND COMMON_LIBS Libevent::${_libevent_com})
    endforeach()
endif()

find_package(hiredis)
if(hiredis_FOUND)
    list(APPEND SOURCE_FILES hiredis_libevent2.c)
    list(APPEND HEADER_FILES hiredis_libevent2.h)
    list(APPEND COMMON_LIBS hiredis::hiredis)
else()
    list(APPEND COMMON_DEFINED TURN_NO_HIREDIS)
endif()
message("COMMON_LIBS:${COMMON_LIBS}")

add_library(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(${PROJECT_NAME} PUBLIC ${COMMON_LIBS})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${COMMON_DEFINED})
target_compile_options(${PROJECT_NAME} PUBLIC -Wno-deprecated-declarations)

# See: http://www.it1352.com/478094.html
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/server>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/client>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/apps/common>
    ${COMMON_INCLUDE_DIR}
    )

# Install head files
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${VERSION}
    )

INSTALL(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Config
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT Runtime
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    INCLUDES DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}
        ${CMAKE_INSTALL_INCLUDEDIR}/turn
        ${CMAKE_INSTALL_INCLUDEDIR}/turn/client
    )

export(TARGETS ${PROJECT_NAME}
    APPEND FILE ${CMAKE_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    )

# Install cmake configure files
install(EXPORT ${PROJECT_NAME}Config
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake"
    )
# Install cmake version configure file
if(DEFINED VERSION)
    write_basic_package_version_file(
        "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        VERSION ${VERSION}
        COMPATIBILITY AnyNewerVersion)
    install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake")
endif()
