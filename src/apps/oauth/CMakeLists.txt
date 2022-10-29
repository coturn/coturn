# Author: Kang Lin <kl222@126.com>

project(turnutils_oauth)

set(SOURCE_FILES
    oauth.c
    )

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE turnclient)
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
