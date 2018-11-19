/*##################################################################################################
# "Copyright (c) 2013 Intel Corporation                                                            #
# DISTRIBUTABLE AS SAMPLE SOURCE SOFTWARE                                                          #
# This Distributable As Sample Source Software is subject to the terms and conditions              #
# of the Intel Software License Agreement for the Intel(R) Cable and GW Software Development Kit"  #
##################################################################################################*/

#ifndef __DWPAL_H_
#define __DWPAL_H_

#include "nl80211_copy.h"
#include "vendor_cmds_copy.h"


#define HOSTAPD_TO_DWPAL_MSG_LENGTH            (4096 * 3)
#define DWPAL_TO_HOSTAPD_MSG_LENGTH            512
#define DWPAL_CLI_LINE_STRING_LENGTH           4096
#define DWPAL_RADIO_NAME_STRING_LENGTH         6
#define DWPAL_OPERATING_MODE_STRING_LENGTH     8
#define DWPAL_WPA_CTRL_STRING_LENGTH           32
#define DWPAL_GENERAL_STRING_LENGTH            64
#define DWPAL_OPCODE_STRING_LENGTH             64
#define DRIVER_NL_TO_DWPAL_MSG_LENGTH          4096
#define DWPAL_FIELD_NAME_LENGTH                128
#define HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH   512


typedef enum
{
	DWPAL_FAILURE = -1,
	DWPAL_SUCCESS = 0,
	DWPAL_NO_PENDING_MESSAGES,
	DWPAL_MISSING_PARAM
} DWPAL_Ret;

typedef void (*DWPAL_wpaCtrlEventCallback)(char *msg, size_t len);  /* callback function for hostapd received events while command is being sent; can be NULL */
typedef DWPAL_Ret (*DWPAL_nlEventCallback)(size_t len, unsigned char *data);  /* callback function for Driver (via nl) events */

typedef enum
{
	DWPAL_STR_PARAM = 0,
	DWPAL_STR_ARRAY_PARAM,  /* Note: the output param for this type MUST be an array of strings with a length of HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH, i.e. "char non_pref_chan[32][HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH];" */
	DWPAL_CHAR_PARAM,
	DWPAL_SHORT_INT_PARAM,
	DWPAL_INT_PARAM,
	DWPAL_LONG_LONG_INT_PARAM,
	DWPAL_INT_ARRAY_PARAM,
	DWPAL_INT_HEX_PARAM,
	DWPAL_INT_HEX_ARRAY_PARAM,
	DWPAL_BOOL_PARAM,

	/* Must be at the end */
	DWPAL_NUM_OF_PARSING_TYPES
} ParamParsingType;

typedef struct
{
	void             *field;  /*OUT*/
	size_t           *numOfValidArgs;  /*OUT*/
	ParamParsingType parsingType;
	const char       *stringToSearch;
	size_t           numOfArrayArgs;
} FieldsToParse;

typedef struct
{
	void             *field;
	ParamParsingType parsingType;
	const char       *preParamString;
} FieldsToCmdParse;

typedef enum
{
	DWPAL_NETDEV_ID = 0,
	DWPAL_PHY_ID,
	DWPAL_WDEV_ID,

	/* Must be at the end */
	DWPAL_NUM_OF_IDs
} CmdIdType;


/* APIs */
DWPAL_Ret dwpal_driver_nl_cmd_send(void *context, char *ifname, enum nl80211_commands nl80211Command, CmdIdType cmdIdType, enum ltq_nl80211_vendor_subcmds subCommand, unsigned char *vendorData, size_t vendorDataSize);
DWPAL_Ret dwpal_driver_nl_msg_get(void *context, DWPAL_nlEventCallback nlEventCallback);
DWPAL_Ret dwpal_driver_nl_fd_get(void *context, int *fd /*OUT*/);
DWPAL_Ret dwpal_driver_nl_detach(void *context);
DWPAL_Ret dwpal_driver_nl_attach(void **context /*OUT*/);

DWPAL_Ret dwpal_string_to_struct_parse(char *msg, size_t msgLen, FieldsToParse fieldsToParse[]);
DWPAL_Ret dwpal_hostap_cmd_send(void *context, const char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply, size_t *replyLen);
DWPAL_Ret dwpal_hostap_event_get(void *context, char *msg /*OUT*/, size_t *msgLen /*IN/OUT*/, char *opCode /*OUT*/);
DWPAL_Ret dwpal_hostap_event_fd_get(void *context, int *fd /*OUT*/);
DWPAL_Ret dwpal_hostap_is_interface_exist(void *context, bool *isExist /*OUT*/);
DWPAL_Ret dwpal_hostap_interface_detach(void *context);
DWPAL_Ret dwpal_hostap_interface_attach(void **context /*OUT*/, const char *radioName, DWPAL_wpaCtrlEventCallback wpaCtrlEventCallback);

#endif  //__DWPAL_H_