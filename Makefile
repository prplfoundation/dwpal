# SPDX-License-Identifier: BSD-2-Clause-Patent
# Copyright (c) 2016-2019 Intel Corporation
# This code is subject to the terms of the BSD+Patent license.
# See LICENSE file for more details.
#

# fapi_wlan source Makefile

PKG_NAME := dwpal
#IWLWAV_HOSTAP_DIR := ../iwlwav-hostap-2.6

opt_no_flags := -Werror -Wcast-qual

LOG_CFLAGS := -DPACKAGE_ID=\"DWPALWLAN\" -DLOGGING_ID="dwpal_6x" -DLOG_LEVEL=7 -DLOG_TYPE=1

dwpal_defines := -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX
dwpal_includes := -I./include
hostap_dir ?= ../hostap
hostap_sources := $(hostap_dir)/src/common/wpa_ctrl.c $(hostap_dir)/src/utils/os_unix.c
hostap_includes := -I$(hostap_dir)/src/common -I$(hostap_dir)/src/utils -I$(hostap_dir)/src/drivers

libnl3_cflags ?= `pkg-config --cflags libnl-genl-3.0`
libnl3_libs ?= `pkg-config --libs libnl-genl-3.0`
safec_cflags ?= `pkg-config --cflags safec-3.3`
safec_libs ?= `pkg-config --libs safec-3.3`

bins := libdwpal.so dwpal_cli
libdwpal.so_sources := dwpal.c dwpal_ext.c $(hostap_sources)
libdwpal.so_cflags  := $(dwpal_defines) $(dwpal_includes) $(hostap_includes) $(libnl3_cflags) $(safec_cflags)
libdwpal.so_ldflags := $(libnl3_libs) $(safec_libs)

dwpal_cli_sources := dwpal_cli.c stats.c $(hostap_sources)
dwpal_cli_cflags  := $(dwpal_defines) $(dwpal_includes) $(hostap_includes)  $(safec_cflags)
dwpal_cli_ldflags := -L./ -ldwpal -lcurses -lreadline -lrt -lpthread $(safec_libs)

include make.inc
