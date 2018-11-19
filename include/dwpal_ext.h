/*##################################################################################################
# "Copyright (c) 2013 Intel Corporation                                                            #
# DISTRIBUTABLE AS SAMPLE SOURCE SOFTWARE                                                          #
# This Distributable As Sample Source Software is subject to the terms and conditions              #
# of the Intel Software License Agreement for the Intel(R) Cable and GW Software Development Kit"  #
##################################################################################################*/

#ifndef __DWPAL_EXT_H_
#define __DWPAL_EXT_H_


#include "dwpal.h"


typedef int (*DwpalExtHostapEventCallback)(char *radioName, char *opCode, char *msg, size_t msgStringLen);
typedef DWPAL_nlEventCallback DwpalExtNlEventCallback;  /* DWPAL_Ret DWPAL_nlEventCallback(size_t len, unsigned char *data); */


/* APIs */
DWPAL_Ret dwpal_ext_driver_nl_cmd_send(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize);
DWPAL_Ret dwpal_ext_driver_nl_detach(void);
DWPAL_Ret dwpal_ext_driver_nl_attach(DwpalExtNlEventCallback nlEventCallback);

DWPAL_Ret dwpal_ext_hostap_cmd_send(char *radioName, char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply, size_t *replyLen);
DWPAL_Ret dwpal_ext_hostap_interface_detach(char *radioName);
DWPAL_Ret dwpal_ext_hostap_interface_attach(char *radioName, DwpalExtHostapEventCallback eventCallback);

#endif  //__DWPAL_EXT_H_
