# Find SQLite.
#
# Set this variable to any additional path you want the module to search:
#  SQLite_DIR
#
# Imported targets defined by this module:
#  SQLite::sqlite        - shared library if available, or static if that's all there is
#  SQLite::sqlite_shared - shared library
#  SQLite::sqlite_static - static library
#
# Informational variables:
#  SQLite_FOUND          - sqlite (or all requested components of sqlite) was found.
#  SQLite_VERSION        - the version of sqlite that was found
#

include(CacheLog)
include(FindPackageHandleStandardArgs)

# If SQLite_DIR has changed since the last invocation, wipe internal cache variables so we can search for everything
# again.
if (NOT "${SQLite_DIR}" STREQUAL "${_internal_old_sqlite_dir}")
	unset_cachelog_entries()
endif ()
reset_cachelog()

set(_old_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
	PKG_CHECK_MODULES(PC_SQLite QUIET sqlite)
endif ()

if (CMAKE_HOST_WIN32)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(archdir    "$ENV{ProgramFiles}")
		set(notarchdir "$ENV{ProgramFiles\(x86\)}")
	else ()
		set(archdir    "$ENV{ProgramFiles\(x86\)}")
		set(notarchdir "$ENV{ProgramFiles}")
	endif ()
	set(_paths
		"${archdir}/sqlite"
		"${archdir}/sqlite3"
		"${notarchdir}/sqlite"
		"${notarchdir}/sqlite3"
	)
else ()
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(arch 64)
	else ()
		set(arch 32)
	endif ()
	set(_paths
		/usr/local/sqlite${arch}
		/usr/locla/sqlite
		/usr/local/sqlite3
	)
endif ()

find_path(SQLite_INCLUDE_DIR
	NAMES         sqlite3.h
	HINTS         ${SQLite_DIR}
	              $ENV{SQLite_DIR}
	              ${SQLITE_ROOT_DIR}
	              ${PC_SQLite_INCLUDE_DIRS}
	PATHS         ${_paths}
	PATH_SUFFIXES include
)
add_to_cachelog(SQLite_INCLUDE_DIR)

if (SQLite_INCLUDE_DIR)
	# Calculate root directory of installation from include directory.
	string(REGEX REPLACE "(/)*include(/)*$" "" _root_dir "${SQLite_INCLUDE_DIR}")
	set(SQLite_DIR "${_root_dir}" CACHE PATH "Root directory of SQLite installation" FORCE)
	set(_internal_old_sqlite_dir "${SQLite_DIR}" CACHE INTERNAL "" FORCE)
	mark_as_advanced(FORCE SQLite_DIR)

	# Find version by parsing SQLite header.
	if (EXISTS "${SQLite_INCLUDE_DIR}/sqlite3.h")
		file(STRINGS "${SQLite_INCLUDE_DIR}/sqlite3.h" sqlite_version_str
			REGEX "^[ \t]*#[ \t]*define[\t ]+SQLITE_VERSION[ \t]+\".*\"")
		if (sqlite_version_str MATCHES "^[ \t]*#[ \t]*define[\t ]+SQLITE_VERSION[ \t]+\"([^\"]*)\"")
			set(SQLite_VERSION "${CMAKE_MATCH_1}")
		endif ()
	endif ()

	# Find static library.
	set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
	foreach(defpath "NO_DEFAULT_PATH" "")
		find_library(SQLite_STATIC_LIBRARY
			NAMES         sqlite_static sqlite3_static sqlitestatic sqlite3static sqlite sqlite3
			NAMES_PER_DIR
			HINTS         ${SQLite_DIR} ${PC_SQLite_LIBRARY_DIRS}
			PATH_SUFFIXES lib ""
			${defpath}
		)
		if (SQLite_STATIC_LIBRARY)
			break()
		endif ()
	endforeach()
	add_to_cachelog(SQLite_STATIC_LIBRARY)
	if (SQLite_STATIC_LIBRARY)
		set(SQLite_sqlite_static_FOUND TRUE)
		set(SQLite_sqlite_FOUND TRUE)
	endif ()

	# Find shared library (will pick up static lib if shared not found).
	set(CMAKE_FIND_LIBRARY_SUFFIXES "${_old_suffixes}")
	foreach(defpath "NO_DEFAULT_PATH" "")
		find_library(SQLite_LIBRARY
			NAMES         sqlite sqlite3 sqlite_satic sqlite3_static sqlitestatic sqlite3static
			NAMES_PER_DIR
			HINTS         ${SQLite_DIR} ${PC_SQLite_LIBRARY_DIRS}
			PATH_SUFFIXES lib ""
			${defpath}
		)
		if (SQLite_LIBRARY)
			break()
		endif ()
	endforeach()
	add_to_cachelog(SQLite_LIBRARY)
	if (SQLite_LIBRARY AND NOT SQLite_LIBRARY STREQUAL SQLite_STATIC_LIBRARY)
		set(SQLite_sqlite_shared_FOUND TRUE)
		set(SQLite_sqlite_FOUND TRUE)
	endif ()
	
	# Look for the DLL.
	if (WIN32)
		set(CMAKE_FIND_LIBRARY_SUFFIXES .dll)
		foreach(defpath "NO_DEFAULT_PATH" "")
			find_library(SQLite_DLL_LIBRARY
				NAMES         sqlite sqlite3
				NAMES_PER_DIR
				HINTS         ${SQLite_DIR}
				PATH_SUFFIXES bin lib ""
				${defpath}
			)
			if (SQLite_DLL_LIBRARY)
				break()
			endif ()
		endforeach()
		add_to_cachelog(SQLite_DLL_LIBRARY)
	endif ()
endif ()

set(_reqs SQLite_INCLUDE_DIR)
if (NOT SQLite_FIND_COMPONENTS) # If user didn't request any particular component explicitly:
	list(APPEND _reqs SQLite_LIBRARY) # Will contain shared lib, or static lib if no shared lib present
endif ()

find_package_handle_standard_args(SQLite
	REQUIRED_VARS     ${_reqs}
	VERSION_VAR       SQLite_VERSION
	HANDLE_COMPONENTS
	FAIL_MESSAGE      "SQLite not found, try -DSQLite_DIR=<path>"
)

# Static library.
if (SQLite_sqlite_static_FOUND AND NOT TARGET SQLite::sqlite_static)
	add_library(SQLite::sqlite_static STATIC IMPORTED)
	set_target_properties(SQLite::sqlite_static PROPERTIES
		IMPORTED_LOCATION                 "${SQLite_STATIC_LIBRARY}"
		IMPORTED_LINK_INTERFACE_LANGUAGES "C"
		INTERFACE_INCLUDE_DIRECTORIES     "${SQLite_INCLUDE_DIR}"
	)
	set(_sqlite_any SQLite::sqlite_static)
endif ()

# Shared library.
if (SQLite_sqlite_shared_FOUND AND NOT TARGET SQLite::sqlite_shared)
	add_library(SQLite::sqlite_shared SHARED IMPORTED)
	set_target_properties(SQLite::sqlite_shared PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			INTERFACE_INCLUDE_DIRECTORIES     "${SQLite_INCLUDE_DIR}"
	)
	if (WIN32)
		set_target_properties(SQLite::sqlite_shared PROPERTIES
			IMPORTED_IMPLIB "${SQLite_LIBRARY}"
		)
		if (SQLite_DLL_LIBRARY)
			set_target_properties(SQLite::sqlite_shared PROPERTIES
				IMPORTED_LOCATION "${SQLite_DLL_LIBRARY}"
			)
		endif ()
	else ()
		set_target_properties(SQLite::sqlite_shared PROPERTIES
			IMPORTED_LOCATION "${SQLite_LIBRARY}"
		)
	endif ()
	set(_sqlite_any SQLite::sqlite_shared)
endif ()

# I-don't-care library (shared, or static if shared not available).
if (SQLite_sqlite_FOUND AND NOT TARGET SQLite::sqlite)
	add_library(SQLite::sqlite INTERFACE IMPORTED)
	set_target_properties(SQLite::sqlite PROPERTIES
		INTERFACE_LINK_LIBRARIES ${_sqlite_any}
	)
endif ()

set(CMAKE_FIND_LIBRARY_SUFFIXES "${_old_suffixes}")

# From https://github.com/Monetra/mstdlib/blob/master/CMakeModules
# The MIT License (MIT)

# Copyright (c) 2015-2017 Main Street Softworks, Inc.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
