# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Copyright (c) 2019 Intel Corporation
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
#

cmake_minimum_required (VERSION 3.0)
project(DWPAL VERSION 1.0 LANGUAGES C)
message("${BoldWhite}Preparing ${BoldGreen}${PROJECT_NAME}${BoldWhite}")

include(GNUInstallDirs)

list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_SOURCE_DIR}/cmake)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(NL3 libnl-genl-3.0)
find_package(safec REQUIRED)

set(compile_definitions CONFIG_CTRL_IFACE CONFIG_CTRL_IFACE_UNIX)
set(hostap_dir ${CMAKE_CURRENT_SOURCE_DIR}/../)
set(hostap_sources ${hostap_dir}/src/common/wpa_ctrl.c
                   ${hostap_dir}/src/utils/os_unix.c)
set(hostap_includes ${hostap_dir}/src/common ${hostap_dir}/src/utils ${hostap_dir}/src/drivers)
file(COPY ${hostap_dir}/src/drivers/nl80211_copy.h ${hostap_dir}/src/common/wpa_ctrl.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include)
set(dwpal_sources dwpal.c dwpal_ext.c)
add_library(dwpal SHARED ${hostap_sources} ${dwpal_sources})

target_link_libraries(dwpal PRIVATE safec ${NL3_LIBRARIES})
target_compile_definitions(dwpal PRIVATE ${compile_definitions})
target_include_directories(dwpal PRIVATE ${hostap_includes} ${NL3_INCLUDE_DIRS})
target_include_directories(dwpal
	PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )

install(TARGETS dwpal EXPORT dwpalConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dwpal)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dwpal)
install(EXPORT dwpalConfig NAMESPACE dwpal:: DESTINATION lib/cmake/dwpal)

add_executable(dwpal_cli dwpal_cli.c stats.c ${hostap_sources})
target_compile_definitions(dwpal_cli PRIVATE ${compile_definitions})
target_link_libraries(dwpal_cli PRIVATE dwpal curses readline rt pthread safec)
target_include_directories(dwpal_cli PRIVATE ${hostap_includes} ${CMAKE_CURRECNT_SOURCE_DIR}/include)
install(TARGETS dwpal_cli DESTINATION ${CMAKE_INSTALL_BINDIR})
