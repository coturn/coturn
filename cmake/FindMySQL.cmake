# Find MySQL.
#
# This module prefers the MariaDB implementation of MySQL (it works better, especially on Windows). It will
# only look for standard MySQL if MariaDB is not found.
#
# Set this variable to any additional path you want the module to search:
#  MySQL_DIR
#
# Imported targets defined by this module:
#  MySQL::mysql        - shared library if available, or static if that's all there is
#  MySQL::mysql_shared - shared library
#  MySQL::mysql_static - static library
#
# Informational variables:
#  MySQL_FOUND      - MySQL (or all requested components of MySQL) was found.
#  MySQL_VERSION    - the version of MySQL that was found
#  MySQL_IS_MARIADB - TRUE if the MySQL that was found is MariaDB
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

# If MySQL_DIR has changed since the last invocation, wipe internal cache variables so we can search for everything
# again.
if (NOT "${MySQL_DIR}" STREQUAL "${_internal_old_mysql_dir}")
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
	else ()
		set(archdir    "$ENV{ProgramFiles\(x86\)}")
		set(notarchdir "$ENV{ProgramFiles}")
	endif ()
	# MariaDB
	append_glob_dirs(_paths "${archdir}/MariaDB*/")
	append_glob_dirs(_paths "${notarchdir}/MariaDB*/")
	# MySQL
	append_glob_dirs(_paths "${archdir}/MySQL/MySQL Connector.C*/")
	append_glob_dirs(_paths "${notarchdir}/MySQL/MySQL Connector.C*/")
else ()
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(arch 64)
	else ()
		set(arch 32)
	endif ()
	list(APPEND _paths
		/usr/local/mariadb${arch}
		/usr/local/mysql${arch}
		/usr/local/mariadb
		/usr/local/mysql
	)
	if (APPLE)
		list(APPEND _paths /usr/local/opt/mariadb-connector-c)
		append_glob_dirs(_paths "/usr/local/Cellar/mariadb-connector-c/*/")
		list(APPEND _paths /usr/local/opt/mysql-connector-c)
		append_glob_dirs(_paths "/usr/local/Cellar/mysql-connector-c/*/")
	endif ()
endif ()

# Find include directory. Try hints set by variable and stuff from _paths, first.
set(_suffixes
	mariadb
	include/mariadb
	mariadb/include
	mysql
	include/mysql include
)
find_path(MySQL_INCLUDE_DIR
	NAMES           mysql.h
	HINTS           ${MySQL_DIR}
	                $ENV{MySQL_DIR}
	                ${MYSQL_ROOT_DIR}
	PATHS           ${_paths}
	PATH_SUFFIXES   ${_suffixes}
	NO_DEFAULT_PATH
)
if (NOT MySQL_INCLUDE_DIR)
	# If we didn't find anything using those hints, proceed to checking system paths. We need
	# to do this in two steps in order to prevent a MySQL installation installed in system paths
	# from being found before a MariaDB installation in /usr/local.
	find_path(MySQL_INCLUDE_DIR
		NAMES         mysql.h
		PATH_SUFFIXES ${_suffixes}
	)
endif ()
add_to_cachelog(MySQL_INCLUDE_DIR)

if (MySQL_INCLUDE_DIR)
	# Figure out if these headers belong to MariaDB or not.
	if (MySQL_INCLUDE_DIR MATCHES "[Mm][Aa][Rr][Ii][Aa][Dd][Bb]")
		set(MySQL_IS_MARIADB TRUE)
	else ()
		set(MySQL_IS_MARIADB FALSE)
	endif ()

	# Calculate root directory of installation from include directory.
	string(REGEX REPLACE "(/)*include(/)*.*$" "" _root_dir "${MySQL_INCLUDE_DIR}")
	set(MySQL_DIR "${_root_dir}" CACHE PATH "Root directory of MySQL installation" FORCE)
	set(_internal_old_mysql_dir "${MySQL_DIR}" CACHE INTERNAL "" FORCE)
	mark_as_advanced(FORCE MySQL_DIR)
	
	# Find version by parsing the mysql_version.h or mariadb_version.h header.
	set(ver_file "${MySQL_INCLUDE_DIR}/mysql_version.h")
	if (NOT EXISTS "${ver_file}")
		# Note: some (but not all) mariadb installations in the wild have mariadb_version.h instead of mysql_version.h
		set(ver_file "${MySQL_INCLUDE_DIR}/mariadb_version.h")
		if (EXISTS "${ver_file}")
			set(MySQL_IS_MARIADB TRUE)
		else ()
			set(ver_file)
		endif ()
	endif ()
	if (ver_file)
		file(STRINGS "${ver_file}" _id_str REGEX "^[ \t]*#[ \t]*define[\t ]+MYSQL_VERSION_ID[ \t]+[0-9]+")
		if (_id_str MATCHES "^[ \t]*#[ \t]*define[\t ]+MYSQL_VERSION_ID[ \t]+([0-9]+)")
			math(EXPR _major "${CMAKE_MATCH_1} / 10000")
			math(EXPR _minor "( ${CMAKE_MATCH_1} % 10000 ) / 100")
			math(EXPR _patch "${CMAKE_MATCH_1} % 100")
			set(MySQL_VERSION "${_major}.${_minor}.${_patch}")
		endif ()
		
		# If we haven't detected mariadb yet, try scanning the version file for mentions.
		if (NOT MySQL_IS_MARIADB)
			file(STRINGS "${MySQL_INCLUDE_DIR}/mysql_version.h" _mariadb REGEX [Mm][Aa][Rr][Ii][Aa][Dd][Bb])
			if (_mariadb)
				set(MySQL_IS_MARIADB TRUE)
			endif ()
		endif ()
	endif ()
	
	# Set library names, based on which mysql we found.
	if (MySQL_IS_MARIADB)
		set(_static_names mariadbclient mariadb)
		set(_shared_names libmariadb mariadb)
		set(_dll_names libmariadb)
	else ()
		set(_static_names mysqlclient)
		set(_shared_names libmysql mysqlclient)
		set(_dll_names libmysql)
	endif ()
	
	# Find static library.
	set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
	foreach(defpath "NO_DEFAULT_PATH" "")
		find_library(MySQL_STATIC_LIBRARY
			NAMES         ${_static_names}
			NAMES_PER_DIR
			HINTS         ${MySQL_DIR}
			PATH_SUFFIXES lib lib/mariadb
			${defpath}
		)
		if (MySQL_STATIC_LIBRARY)
			break()
		endif ()
	endforeach()
	add_to_cachelog(MySQL_STATIC_LIBRARY)
	if (MySQL_STATIC_LIBRARY)
		set(MySQL_mysql_static_FOUND TRUE)
		set(MySQL_mysql_FOUND TRUE)
	endif ()
	
	# Find shared library (will pick up static lib if shared not found).
	set(CMAKE_FIND_LIBRARY_SUFFIXES "${_old_suffixes}")
	foreach(defpath "NO_DEFAULT_PATH" "")
		find_library(MySQL_LIBRARY
			NAMES         ${_shared_names}
			NAMES_PER_DIR
			HINTS         ${MySQL_DIR}
			PATH_SUFFIXES lib lib/mariadb
			${defpath}
		)
		if (MySQL_LIBRARY)
			break()
		endif ()
	endforeach()
	add_to_cachelog(MySQL_LIBRARY)
	if (MySQL_LIBRARY AND NOT MySQL_LIBRARY STREQUAL MySQL_STATIC_LIBRARY)
		set(MySQL_mysql_shared_FOUND TRUE)
		set(MySQL_mysql_FOUND TRUE)
	endif ()
	
	# Find the DLL (if any).
	if (WIN32)
		set(CMAKE_FIND_LIBRARY_SUFFIXES .dll)
		foreach(defpath "NO_DEFAULT_PATH" "")
			find_library(MySQL_DLL_LIBRARY
				NAMES         ${_dll_names}
				NAMES_PER_DIR
				HINTS         ${MySQL_DIR}
				PATH_SUFFIXES bin lib bin/mariadb lib/mariadb ""
				${defpath}
			)
			if (MySQL_DLL_LIBRARY)
				break()
			endif ()
		endforeach()
		add_to_cachelog(MySQL_DLL_LIBRARY)
	endif ()
endif ()

set(_reqs MySQL_INCLUDE_DIR)
if (NOT MySQL_FIND_COMPONENTS) # If user didn't request any particular component explicitly:
	if (NOT MySQL_mysql_FOUND)
		list(APPEND _reqs MySQL_LIBRARY)
	endif ()
endif ()

find_package_handle_standard_args(MySQL
	REQUIRED_VARS     ${_reqs}
	VERSION_VAR       MySQL_VERSION
	HANDLE_COMPONENTS
	FAIL_MESSAGE      "MySQL not found, try -DMySQL_DIR=<path>"
)
add_to_cachelog(FIND_PACKAGE_MESSAGE_DETAILS_MySQL)

# Static library.
if (MySQL_mysql_static_FOUND AND NOT TARGET MySQL::mysql_static)
	add_library(MySQL::mysql_static STATIC IMPORTED)
	set_target_properties(MySQL::mysql_static PROPERTIES
		IMPORTED_LOCATION                 "${MySQL_STATIC_LIBRARY}"
		IMPORTED_LINK_INTERFACE_LANGUAGES "C"
		INTERFACE_INCLUDE_DIRECTORIES     "${MySQL_INCLUDE_DIR}"
	)
	set(_mysql_any MySQL::mysql_static)
endif ()

# Shared library.
if (MySQL_mysql_shared_FOUND AND NOT TARGET MySQL::mysql_shared)
	add_library(MySQL::mysql_shared SHARED IMPORTED)
	set_target_properties(MySQL::mysql_shared PROPERTIES
			IMPORTED_LINK_INTERFACE_LANGUAGES "C"
			INTERFACE_INCLUDE_DIRECTORIES     "${MySQL_INCLUDE_DIR}"
	)
	if (WIN32)
		set_target_properties(MySQL::mysql_shared PROPERTIES
			IMPORTED_IMPLIB "${MySQL_LIBRARY}"
		)
		if (MySQL_DLL_LIBRARY)
			set_target_properties(MySQL::mysql_shared PROPERTIES
				IMPORTED_LOCATION "${MySQL_DLL_LIBRARY}"
			)
		endif ()
	else ()
		set_target_properties(MySQL::mysql_shared PROPERTIES
			IMPORTED_LOCATION "${MySQL_LIBRARY}"
		)
	endif ()
	set(_mysql_any MySQL::mysql_shared)
endif ()

# I-don't-care library (shared, or static if shared not available).
if (MySQL_mysql_FOUND AND NOT TARGET MySQL::mysql)
	add_library(MySQL::mysql INTERFACE IMPORTED)
	set_target_properties(MySQL::mysql PROPERTIES
		INTERFACE_LINK_LIBRARIES ${_mysql_any}
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
