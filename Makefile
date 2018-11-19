# fapi_wlan source Makefile

PKG_NAME := dwpal
IWLWAV_HOSTAP_DIR := ../iwlwav-hostap-2.6
IWLWAV_IW_DIR := ../iwlwav-iw-4.14

opt_no_flags := -Werror -Wcast-qual

LOG_CFLAGS := -DPACKAGE_ID=\"FAPIWLAN\" -DLOGGING_ID="dwpal" -DLOG_LEVEL=7 -DLOG_TYPE=1

bins := libdwpal.so dwpal_debug_cli
libdwpal.so_sources := dwpal.c dwpal_ext.c $(IWLWAV_HOSTAP_DIR)/src/common/wpa_ctrl.c $(IWLWAV_HOSTAP_DIR)/src/utils/os_unix.c
libdwpal.so_cflags  := -I./include -I$(IWLWAV_HOSTAP_DIR)/src/common/ -I$(IWLWAV_HOSTAP_DIR)/src/utils/ -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX -I$(STAGING_DIR)/usr/include/libnl3/ -I$(IWLWAV_HOSTAP_DIR)/src/drivers/ -I$(IWLWAV_IW_DIR)
libdwpal.so_ldflags := -L./ -L$(STAGING_DIR)/opt/lantiq/lib/ -lsafec-1.0 -lnl-genl-3

dwpal_debug_cli_sources := $(IWLWAV_HOSTAP_DIR)/src/common/wpa_ctrl.c $(IWLWAV_HOSTAP_DIR)/src/utils/os_unix.c dwpal_debug_cli.c
dwpal_debug_cli_ldflags := -L./ -ldwpal -ldl -lcurses -lreadline -lrt -L$(STAGING_DIR)/usr/sbin/ -lsafec-1.0 -lpthread
dwpal_debug_cli_cflags  := -I./include -I$(IWLWAV_HOSTAP_DIR)/src/common/ -I$(IWLWAV_HOSTAP_DIR)/src/utils/ -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX -I$(STAGING_DIR)/usr/include/ -I$(IWLWAV_HOSTAP_DIR)/src/drivers/ -I$(IWLWAV_IW_DIR)

include make.inc
