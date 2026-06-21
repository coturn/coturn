# Find libmicrohttpd.
#
# libmicrohttpd serves coturn's Prometheus /metrics endpoint. This module
# locates it.
#
# Set MicroHTTPD_DIR or MicroHTTPD_ROOT (variable or environment) to point at a
# non-standard install prefix.
#
# Defines on success:
#  MicroHTTPD_FOUND        - libmicrohttpd was found
#  MicroHTTPD_INCLUDE_DIRS - include directories
#  MicroHTTPD_LIBRARIES    - libraries to link

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
pkg_check_modules(PC_microhttpd QUIET libmicrohttpd)

find_path(MicroHTTPD_INCLUDE_DIR
    NAMES microhttpd.h
    HINTS ${MicroHTTPD_DIR} ${MicroHTTPD_ROOT} ${PC_microhttpd_INCLUDE_DIRS} /usr
    PATHS $ENV{MicroHTTPD_DIR} $ENV{MicroHTTPD_ROOT}
    PATH_SUFFIXES include
    )

find_library(MicroHTTPD_LIBRARY
    NAMES microhttpd
    HINTS ${MicroHTTPD_DIR} ${MicroHTTPD_ROOT} ${PC_microhttpd_LIBRARY_DIRS}
    PATHS $ENV{MicroHTTPD_DIR} $ENV{MicroHTTPD_ROOT}
    PATH_SUFFIXES lib ${CMAKE_INSTALL_LIBDIR})

find_package_handle_standard_args(MicroHTTPD
    REQUIRED_VARS MicroHTTPD_LIBRARY MicroHTTPD_INCLUDE_DIR)

set(MicroHTTPD_INCLUDE_DIRS ${MicroHTTPD_INCLUDE_DIR})
set(MicroHTTPD_LIBRARIES ${MicroHTTPD_LIBRARY})

mark_as_advanced(MicroHTTPD_INCLUDE_DIR MicroHTTPD_LIBRARY)
