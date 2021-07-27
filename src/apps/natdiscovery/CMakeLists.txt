# Author: Kang Lin (kl222@126.com)

project(turnutils_natdiscovery)

set(SOURCE_FILES
    natdiscovery.c
    )
source_group("Source Files" FILES "${SOURCE_FILES}")

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE turnclient)
INSTALL(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    )
