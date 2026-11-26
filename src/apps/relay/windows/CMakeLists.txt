# The file is a example of windows service
# Author: Kang Lin <kl222@126.com>
#
# ### Usage:
#   - Build:
# 
#          cd src\apps\relay\windows
#          mkdir build
#          cd build
#          cmake ..
#          cmake --build .
#
#   - Programe:
# 
#          cd bin\Debug
#          dir
# 
#          2025/05/29  11:12    <DIR>          .
#          2025/05/29  11:12    <DIR>          ..
#          2025/05/29  11:12           148,480 coturn_example.exe
#          2025/05/29  11:12         3,543,040 coturn_example.pdb
# 
#   - Usage:
# 
#     ; Show usage
#     coturn_example.exe -h
#     ; Using Administrator Privileges to install service
#     coturn_example.exe -install
#     ; Using Administrator Privileges to remove service
#     coturn_example.exe -remove
# 
#     ; Viewing Log Events Using the Event Manager
#     ; Managing coturn services using the service manager

cmake_minimum_required(VERSION 3.5)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(coturn_example)

IF(NOT WIN32)
    message(FATAL_ERROR "OS must be windows")
ENDIF()

set(HEADER_FILES
    ServiceInstaller.h
	Service.h
    )

set(SOURCE_FILES
    ServiceInstaller.cpp
	Service.cpp
	Example.c
    )

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})
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

