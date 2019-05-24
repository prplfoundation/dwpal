# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Copyright (c) 2019 Intel Corporation
#
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
#

# Note - The generated .pc provided by safec package doesn't work -
# It points to <prefix>/safec-3.0 instead of <prefix>/libsafec which
# it is actually installed.

find_library(SAFEC_LIBRARY "libsafec-3.0.so")
find_path(SAFEC_INCLUDE_DIRS libsafec/safe_str_lib.h)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(safec DEFAULT_MSG 
    SAFEC_LIBRARY
    SAFEC_INCLUDE_DIRS)
message("SAFEC_LIBRARY: " ${SAFEC_LIBRARY})
message("SAFEC_INCLUDE_DIRS: " ${SAFEC_INCLUDE_DIRS}/libsafec)

if (safec_FOUND)
    message("safec found")
    add_library(safec UNKNOWN IMPORTED)

    set_target_properties(safec PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SAFEC_INCLUDE_DIRS}/libsafec"
        )

    # Library
    set_target_properties(safec PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${SAFEC_LIBRARY}" 
    )

endif()
