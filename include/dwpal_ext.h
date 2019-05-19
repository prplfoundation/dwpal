/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef __DWPAL_EXT_H_
#define __DWPAL_EXT_H_


#include "dwpal.h"


typedef int (*DwpalExtHostapEventCallback)(char *VAPName, char *opCode, char *msg, size_t msgStringLen);
typedef DWPAL_nlEventCallback DwpalExtNlEventCallback;  /* DWPAL_Ret DWPAL_nlEventCallback(size_t len, unsigned char *data); */


/* APIs */
DWPAL_Ret dwpal_ext_driver_nl_get(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize, size_t *outLen, unsigned char *outData);
DWPAL_Ret dwpal_ext_driver_nl_cmd_send(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize);
DWPAL_Ret dwpal_ext_driver_nl_detach(void);
DWPAL_Ret dwpal_ext_driver_nl_attach(DwpalExtNlEventCallback nlEventCallback);

DWPAL_Ret dwpal_ext_hostap_cmd_send(char *VAPName, char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply /*OUT*/, size_t *replyLen /*IN/OUT*/);
DWPAL_Ret dwpal_ext_hostap_interface_detach(char *VAPName);
DWPAL_Ret dwpal_ext_hostap_interface_attach(char *VAPName, DwpalExtHostapEventCallback eventCallback);

#endif  //__DWPAL_EXT_H_
