# Author: Kang Lin (kl222@126.com)
#
# Find Prometheus.
#
# Set this variable to any additional path you want the module to search:
#  Prometheus_DIR or Prometheus_ROOT
#
# Try to find prometheus
# Once done, this will define:
#  Prometheus_FOUND        - Prometheus (or all requested components of prom, microhttpd) was found.
#  Prometheus_INCLUDE_DIRS - Libevent include directories
#  Prometheus_LIBRARIES    - libraries needed to use Prometheus
#

include(FindPackageHandleStandardArgs)

find_package(PkgConfig)
pkg_check_modules(PC_prom QUIET prom)
pkg_check_modules(PC_microhttd QUIET microhttpd)

find_path(microhttpd_include_dir
    NAMES microhttpd.h
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_microhttd_INCLUDE_DIRS} /usr
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES include
    )

find_library(
    microhttpd_libs
    NAMES microhttpd
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_microhttd_LIBRARY_DIRS}
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES lib ${CMAKE_INSTALL_LIBDIR})

find_path(prom_INCLUDE_DIR
    NAMES prom.h
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_prom_INCLUDE_DIRS} /usr
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES include
    )

find_library(
    prom_libs
    NAMES prom
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_prom_LIBRARY_DIRS}
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES lib ${CMAKE_INSTALL_LIBDIR})

find_package_handle_standard_args(Prometheus
    REQUIRED_VARS prom_libs prom_INCLUDE_DIR
        microhttpd_include_dir microhttpd_libs
        )

set(Prometheus_INCLUDE_DIRS
    ${prom_INCLUDE_DIR}
    ${microhttpd_include_dir})
set(Prometheus_LIBRARIES ${prom_libs} ${microhttpd_libs})
