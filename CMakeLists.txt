# Author: Kang Lin (kl222@126.com)

cmake_minimum_required(VERSION 3.5)

project(coturn)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)
# TODO: Modify this when the version is released
SET(BUILD_VERSION "4.5.2")

# Find Git Version Patch
IF(EXISTS "${CMAKE_SOURCE_DIR}/.git")
    if(NOT GIT)
        SET(GIT $ENV{GIT})
    endif()
    if(NOT GIT)
        FIND_PROGRAM(GIT NAMES git git.exe git.cmd)
    endif()
    IF(GIT)
        EXECUTE_PROCESS(
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMAND ${GIT} describe --tags
            OUTPUT_VARIABLE GIT_VERSION  OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT GIT_VERSION)
            EXECUTE_PROCESS(
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                COMMAND ${GIT} rev-parse --short HEAD
                OUTPUT_VARIABLE GIT_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE
            )
        endif()
        SET(BUILD_VERSION ${GIT_VERSION})
    ENDIF()
ENDIF()
message("BUILD_VERSION:${BUILD_VERSION}")
set(VERSION ${BUILD_VERSION})

if(NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif(NOT DEFINED CMAKE_BUILD_TYPE)
string(TOLOWER "${CMAKE_BUILD_TYPE}" build_type)
if("debug" STREQUAL build_type)
    add_definitions(-D_DEBUG)
endif()

IF(MSVC)
    # This option is to enable the /MP switch for Visual Studio 2005 and above compilers
    OPTION(WIN32_USE_MP "Set to ON to build with the /MP option (Visual Studio 2005 and above)." ON)
    MARK_AS_ADVANCED(WIN32_USE_MP)
    IF(WIN32_USE_MP)
        #SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
        add_compile_options(/MP)
    ENDIF(WIN32_USE_MP)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
ENDIF(MSVC)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
include(GenerateExportHeader)
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckFunctionExists)

# Create install runtime target
add_custom_target(install-runtime
  COMMAND
     "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=Runtime 
     -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake"
)
# Create uninstall runtime target
add_custom_target(uninstall-runtime
  COMMAND
     "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=Runtime 
     -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
)
# Create will be delete files
CONFIGURE_FILE(
    "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
# Create unistall target
ADD_CUSTOM_TARGET(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
    )

add_subdirectory(src)

install(DIRECTORY man DESTINATION .
    COMPONENT Runtime)
install(DIRECTORY turndb/
    DESTINATION share/turnserver
        COMPONENT Runtime)
install(DIRECTORY turndb/
    DESTINATION doc/turnserver
        COMPONENT Runtime)
install(FILES
            LICENSE
            README.turnserver
            README.turnadmin
            README.turnutils
            INSTALL
            postinstall.txt
        DESTINATION doc/turnserver
            COMPONENT Runtime)
install(FILES examples/etc/turnserver.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
        COMPONENT Runtime
    RENAME turnserver.conf.default
    )
install(DIRECTORY
            examples/etc
            examples/scripts
    DESTINATION share/examples/turnserver
    PATTERN "rfc5769.sh" EXCLUDE
    )
