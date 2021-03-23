# Find PostgreSQL.
#
# Specifically, this finds the C client library (libpq) that can be used to talk to PostgreSQL databases.
#
# Set this variable to any additional path you want the module to search:
#  PostgreSQL_DIR
#
# Imported targets defined by this module:
#  PostgreSQL::pq        - shared library if available, or static if that's all there is
#  PostgreSQL::pq_shared - shared library
#  PostgreSQL::pq_static - static library
#
# Informational variables:
#  PostgreSQL_FOUND      - PostgreSQL (or all requested components of PostgreSQL) was found.
#  PostgreSQL_VERSION    - the version of PostgreSQL that was found
#

include(CacheLog)
include(FindPackageHandleStandardArgs)

# Helper function for globbing for directories.
function(append_glob_dirs list_name glob_path)
	file(TO_CMAKE_PATH "${glob_path}" glob_path)
	file(GLOB dirs LIST_DIRECTORIES true "${glob_path}")
	if (dirs)
		list(APPEND ${list_name} "${dirs}")
		set(${list_name} "${${list_name}}" PARENT_SCOPE)
	endif ()
endfunction()

# If PostgreSQL_DIR has changed since the last invocation, wipe internal cache variables so we can search for everything
# again.
if (NOT "${PostgreSQL_DIR}" STREQUAL "${_internal_old_postgresql_dir}")
	unset_cachelog_entries()
endif ()
reset_cachelog()

set(_old_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")

# Set path guesses.
set(_paths)
if (CMAKE_HOST_WIN32)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(archdir    "$ENV{ProgramFiles}")
		set(notarchdir "$ENV{ProgramFiles\(x86\)}")
		set(arch       64)
	else ()
		set(archdir    "$ENV{ProgramFiles\(x86\)}")
		set(notarchdir "$ENV{ProgramFiles}")
		set(arch       32)
	endif ()
	# This should find installations from either the BigSQL or EDB Postgres installers.
	# (Note: I'd recommend BigSQL, it's built with MinGW, so it's easier to package)
	list(APPEND _paths /PostgreSQL${arch})
	append_glob_dirs(_paths "/PostgreSQL${arch}/pg*/")
	list(APPEND _paths /PostgreSQL)
	append_glob_dirs(_paths "/PostgreSQL/pg*/")
	list(APPEND _paths "${archdir}/PostgreSQL")
	append_glob_dirs(_paths "${archdir}/PostgreSQL/*/")
	list(APPEND _paths "${notarchdir}/PostgreSQL")
	append_glob_dirs(_paths "${notarchdir}/PostgreSQL/*/")
else ()
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(arch 64)
	else ()
		set(arch 32)
	endif ()
	list(APPEND _paths
		/usr/local/postgresql${arch}
		/usr/local/pgsql${arch}
		/usr/local/postgresql
		/usr/local/pgsql
	)
	append_glob_dirs(_paths "/usr/pgsql-*")
endif ()

# Find include directory.
find_path(PostgreSQL_INCLUDE_DIR
	NAMES         libpq-fe.h
	HINTS         ${PostgreSQL_DIR}
	              $ENV{PostgreSQL_DIR}
	              ${POSTGRESQL_ROOT_DIR}
	PATHS         ${_paths}
	PATH_SUFFIXES include include/postgresql postgresql
)
add_to_cachelog(PostgreSQL_INCLUDE_DIR)

if (PostgreSQL_INCLUDE_DIR)
	# Calculate root directory of installation from include directory.
	string(REGEX REPLACE "(/)*include(/)*.*$" "" _root_dir "${PostgreSQL_INCLUDE_DIR}")
	set(PostgreSQL_DIR "${_root_dir}" CACHE PATH "Root directory of PostgreSQL installation" FORCE)
	set(_internal_old_postgresql_dir "${PostgreSQL_DIR}" CACHE INTERNAL "" FORCE)
	mark_as_advanced(FORCE PostgreSQL_DIR)
	
	# Find version by parsing the pg_config.h header.
	set(header "${PostgreSQL_INCLUDE_DIR}/pg_config_x86_64.h")
	if (NOT EXISTS "${header}")
		set(header "${PostgreSQL_INCLUDE_DIR}/pg_config_x86.h")
		if (NOT EXISTS "${header}")
			set(header "${PostgreSQL_INCLUDE_DIR}/pg_config.h")
			if (NOT EXISTS "${header}")
				set(header)
			endif ()
		endif ()
	endif ()

	if (header)
		file(STRINGS "${header}" _ver_str
			REGEX "^[ \t]*#[ \t]*define[\t ]+PG_VERSION[ \t]+\".*\"")
		if (_ver_str MATCHES "^[ \t]*#[ \t]*define[\t ]+PG_VERSION[ \t]+\"([^\"]*)\"")
			set(PostgreSQL_VERSION "${CMAKE_MATCH_1}")
		endif ()
	endif ()
	
	# Find static library (if not on Windows, none of the installers I could find there had a static libpq)).
	if (WIN32)
		set(PostgreSQL_STATIC_LIBRARY "PostgreSQL_STATIC_LIBRARY-NOTFOUND" CACHE PATH "Path to libpq static lib")
	else ()
		set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
		foreach(defpath "NO_DEFAULT_PATH" "")
			find_library(PostgreSQL_STATIC_LIBRARY
				NAMES         pq libpq
				NAMES_PER_DIR
				HINTS         ${PostgreSQL_DIR}
				PATH_SUFFIXES lib
				${defpath}
			)
			if (PostgreSQL_STATIC_LIBRARY)
				break()
			endif ()
		endforeach()
	endif ()
	add_to_cachelog(PostgreSQL_STATIC_LIBRARY)
	if (PostgreSQL_STATIC_LIBRARY)
		set(PostgreSQL_pq_static_FOUND TRUE)
		set(PostgreSQL_pq_FOUND TRUE)
	endif ()
	
	# Find shared library (will pick up static lib if shared not found).
	set(CMAKE_FIND_LIBRARY_SUFFIXES "${_old_suffixes}")
	if (WIN32)
		list(APPEND CMAKE_FIND_LIBRARY_SUFFIXES ".a") #BigSQL installer names the import lib with a .a extension
	endif ()
	foreach(defpath "NO_DEFAULT_PATH" "")
		find_library(PostgreSQL_LIBRARY
			NAMES         pq libpq
			NAMES_PER_DIR
			HINTS         ${PostgreSQL_DIR}
			PATH_SUFFIXES lib
			${defpath}
		)
		if (PostgreSQL_LIBRARY)
			break()
		endif ()
	endforeach()
	add_to_cachelog(PostgreSQL_LIBRARY)
	if (PostgreSQL_LIBRARY AND NOT PostgreSQL_LIBRARY STREQUAL PostgreSQL_STATIC_LIBRARY)
		set(PostgreSQL_pq_shared_FOUND TRUE)
		set(PostgreSQL_pq_FOUND TRUE)
	endif ()
	
	# Find the DLL (if any).
	if (WIN32)
		set(CMAKE_FIND_LIBRARY_SUFFIXES .dll)
		foreach(defpath "NO_DEFAULT_PATH" "")
			find_library(PostgreSQL_DLL_LIBRARY
				NAMES         pq libpq
				NAMES_PER_DIR
				HINTS         ${PostgreSQL_DIR}
				PATH_SUFFIXES bin lib ""
				${defpath}
			)
			if (PostgreSQL_DLL_LIBRARY)
				break()
			endif ()
		endforeach()
		add_to_cachelog(PostgreSQL_DLL_LIBRARY)
	endif ()
endif ()

set(_reqs PostgreSQL_INCLUDE_DIR)
if (NOT PostgreSQL_FIND_COMPONENTS) # If user didn't request any particular component explicitly:
	list(APPEND _reqs PostgreSQL_LIBRARY) # Will contain shared lib, or static lib if no shared lib present
endif ()

find_package_handle_standard_args(PostgreSQL
	REQUIRED_VARS     ${_reqs}
	VERSION_VAR       PostgreSQL_VERSION
	HANDLE_COMPONENTS
	FAIL_MESSAGE      "PostgreSQL not found, try -DPostgreSQL_DIR=<path>"
)
add_to_cachelog(FIND_PACKAGE_MESSAGE_DETAILS_PostgreSQL)

# Static library.
if (PostgreSQL_pq_static_FOUND AND NOT TARGET PostgreSQL::pq_static)
	add_library(PostgreSQL::pq_static STATIC IMPORTED)
	set_target_properties(PostgreSQL::pq_static PROPERTIES
		IMPORTED_LOCATION                 "${PostgreSQL_STATIC_LIBRARY}"
		IMPORTED_LINK_INTERFACE_LANGUAGES "C"
		INTERFACE_INCLUDE_DIRECTORIES     "${PostgreSQL_INCLUDE_DIR}"
	)
	set(_pq_any PostgreSQL::pq_static)
endif ()

# Shared library.
if (PostgreSQL_pq_shared_FOUND AND NOT TARGET PostgreSQL::pq_shared)
	add_library(PostgreSQL::pq_shared SHARED IMPORTED)
	set_target_properties(PostgreSQL::pq_shared PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			INTERFACE_INCLUDE_DIRECTORIES     "${PostgreSQL_INCLUDE_DIR}"
	)
	if (WIN32)
		set_target_properties(PostgreSQL::pq_shared PROPERTIES
			IMPORTED_IMPLIB "${PostgreSQL_LIBRARY}"
		)
		if (PostgreSQL_DLL_LIBRARY)
			set_target_properties(PostgreSQL::pq_shared PROPERTIES
				IMPORTED_LOCATION "${PostgreSQL_DLL_LIBRARY}"
			)
		endif ()
	else ()
		set_target_properties(PostgreSQL::pq_shared PROPERTIES
			IMPORTED_LOCATION "${PostgreSQL_LIBRARY}"
		)
	endif ()
	set(_pq_any PostgreSQL::pq_shared)
endif ()

# I-don't-care library (shared, or static if shared not available).
if (PostgreSQL_pq_FOUND AND NOT TARGET PostgreSQL::pq)
	add_library(PostgreSQL::pq INTERFACE IMPORTED)
	set_target_properties(PostgreSQL::pq PROPERTIES
		INTERFACE_LINK_LIBRARIES ${_pq_any}
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
