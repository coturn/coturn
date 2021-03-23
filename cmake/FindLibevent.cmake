# Author: Kang Lin (kl222@126.com)

# Try to find Libevent
# Once done, this will define
#
# Libevent_FOUND        - system has Libevent
# Libevent_INCLUDE_DIRS - Libevent include directories
# Libevent_LIBRARIES    - libraries needed to use Libevent
#
# and the following imported targets
#
# Libevent::core        - the core functons of Libevent
# Libevent::extra       - extra functions, contains http, dns and rpc
# Libevent::pthreads    - multiple threads for Libevent, not exists on Windows
# Libevent::openssl     - openssl support for Libevent

macro(no_component_msg _comp)
    if(${CMAKE_FIND_PACKAGE_NAME}_FIND_REQUIRED_${_comp})
        set(pthreadlib)
        if(NOT WIN32)
            set(pthreadlib ", pthreads")
        endif()
        message(FATAL_ERROR "Your libevent library does not contain a ${_comp} component!\n"
                "The valid components are core, extra${pthreadlib} and openssl.")
    else()
        message_if_needed(WARNING "Your libevent library does not contain a ${_comp} component!")
    endif()
endmacro()

set(_AVAILABLE_LIBS core extra openssl pthreads)
set(_EVENT_COMPONENTS)
if(${CMAKE_FIND_PACKAGE_NAME}_FIND_COMPONENTS)
    foreach(_comp ${${CMAKE_FIND_PACKAGE_NAME}_FIND_COMPONENTS})
        list(FIND _AVAILABLE_LIBS ${_comp} _INDEX)
        if(_INDEX GREATER -1)
            list(APPEND _EVENT_COMPONENTS ${_comp})
        else()
            no_component_msg(${_comp})
        endif()
    endforeach()
else()
    set(_EVENT_COMPONENTS core extra openssl)
    if(NOT WIN32)
        list(APPEND _EVENT_COMPONENTS pthreads)
    endif()
endif()

foreach(_libevent_comp ${_EVENT_COMPONENTS})
    list(APPEND _libevent_comps libevent_${_libevent_comp})
endforeach()

find_package(PkgConfig)
pkg_check_modules(PC_Libevent QUIET ${_libevent_comps})
if(PC_Libevent_FOUND)
    set(Libevent_VERSION ${PC_Libevent_VERSION})
else()
    foreach(_libevent_comp ${_EVENT_COMPONENTS})
        list(APPEND PC_Libevent_LIBRARIES event_${_libevent_comp})
    endforeach()
endif()

find_path(Libevent_INCLUDE_DIR
    NAMES event2/event.h
    HINTS ${Libevent_ROOT} ${PC_Libevent_INCLUDEDIR} ${PC_Libevent_INCLUDE_DIRS} /usr
    PATHS $ENV{Libevent_DIR} ${Libevent_DIR}
    PATH_SUFFIXES include
    )

foreach(Libevent_var ${PC_Libevent_LIBRARIES})
    unset(Libevent_lib CACHE)
    find_library(
        Libevent_lib
        NAMES
            ${Libevent_var}
        HINTS ${Libevent_ROOT} ${PC_Libevent_LIBDIR} ${PC_Libevent_LIBRARY_DIRS}
        PATHS $ENV{Libevent_DIR} ${Libevent_DIR}
        PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR} lib)
    if(Libevent_lib)
        string(REPLACE event_ "" _name ${Libevent_var})
        add_library(Libevent::${_name} UNKNOWN IMPORTED)
        set_target_properties(Libevent::${_name} PROPERTIES
            IMPORTED_LOCATION "${Libevent_lib}"
            INTERFACE_INCLUDE_DIRECTORIES "${Libevent_INCLUDE_DIR}")
        list(APPEND Libevent_LIBRARY ${Libevent_lib})
    endif()
endforeach()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libevent
    REQUIRED_VARS Libevent_LIBRARY Libevent_INCLUDE_DIR)

mark_as_advanced(Libevent_FOUND Libevent_INCLUDE_DIR Libevent_LIBRARY Libevent_lib)

set(Libevent_INCLUDE_DIRS ${Libevent_INCLUDE_DIR})
set(Libevent_LIBRARIES ${Libevent_LIBRARY})
unset(Libevent_INCLUDE_DIR)
unset(Libevent_LIBRARY)
