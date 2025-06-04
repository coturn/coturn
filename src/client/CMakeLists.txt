##
# SPDX-License-Identifier: BSD-3-Clause
#
# https://opensource.org/license/bsd-3-clause
#
# Copyright (C) 2021 Kang Lin <kl222@126.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
##

project(turnclient)

set(HEADER_FILES
    ${CMAKE_SOURCE_DIR}/src/ns_turn_defs.h
    ${CMAKE_SOURCE_DIR}/src/client++/TurnMsgLib.h
    ns_turn_ioaddr.h
    ns_turn_msg.h
    ns_turn_msg_defs.h
    ns_turn_msg_defs_experimental.h
    ns_turn_msg_addr.h
    )

set(SOURCE_FILES
    ns_turn_ioaddr.c
    ns_turn_msg_addr.c
    ns_turn_msg.c
    )

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(${PROJECT_NAME} PUBLIC turncommon)

# Install head files
set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/
    PUBLIC_HEADER "${HEADER_FILES}"  # Install head files
    VERSION ${VERSION}
    )

INSTALL(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Config
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT Runtime
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT Runtime
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        COMPONENT Development
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/turn/client
		COMPONENT Development
    INCLUDES DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/turn
        ${CMAKE_INSTALL_INCLUDEDIR}/turn/client
        COMPONENT Development
    )

export(TARGETS ${PROJECT_NAME}
    APPEND FILE ${CMAKE_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    NAMESPACE coturn::
    )

# Install cmake configure files
install(EXPORT ${PROJECT_NAME}Config
    NAMESPACE coturn::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/coturn"
    COMPONENT Development
    )

# Install cmake version configure file
if(DEFINED VERSION)
    write_basic_package_version_file(
        "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        VERSION ${VERSION}
        COMPATIBILITY AnyNewerVersion)
    install(FILES "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/coturn"
		    COMPONENT Development)
endif()
