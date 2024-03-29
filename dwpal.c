/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

/*  *****************************************************************************
 *         File Name    : dwpal.c                             	                *
 *         Description  : D-WPAL control interface 		                        *
 *                                                                              *
 *  *****************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <linux/types.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>  /* for "struct nl_msg" */
#include <netlink/genl/ctrl.h>
#include <linux/netlink.h>

#include <net/if.h>

#if defined YOCTO
#include <slibc/string.h>
#else
#include "safe_str_lib.h"
#endif

#include "dwpal.h"
#include "dwpal_log.h"	//Logging

#define DWPAL_MAX_NUM_OF_ELEMENTS 512

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif

#define OUI_LTQ 0xAC9A96



typedef struct
{
	union
	{
		struct
		{
			char   VAPName[DWPAL_VAP_NAME_STRING_LENGTH]; /* "wlan0", "wlan0.1", "wlan1", "wlan2.2", ..., "wlan5", ... */
			char   operationMode[DWPAL_OPERATING_MODE_STRING_LENGTH];
			char   wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];
			struct wpa_ctrl *wpaCtrlPtr;
			struct wpa_ctrl *listenerWpaCtrlPtr;   /*needed when closing it*/
			int    fd;
			DWPAL_wpaCtrlEventCallback wpaCtrlEventCallback;  /* callback function for hostapd received events while command is being sent; can be NULL */
		} hostapd;

		struct
		{
			struct nl_sock *nlSocketEvent, *nlSocketCmdGet;
			int    fd, fdCmdGet, nl80211_id;
			DWPAL_nlEventCallback nlEventCallback, nlCmdGetCallback;
		} driver;
	} interface;
} DWPAL_Context;


/* Local static functions */

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	(void)msg;
	(void)arg;
	return NL_OK;
}


static DWPAL_Ret command_get_ended_msg_send(void)
{
    int                fd = -1, byte;
	struct sockaddr_un un;
	size_t             len;
	char               socketName[SOCKET_NAME_LENGTH] = "\0";
	pid_t              pid = getpid();

	console_printf("%s Entry\n", __FUNCTION__);

	/* create a UNIX domain stream socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		console_printf("%s; create socket fail; pid= %d; errno= %d ('%s')\n", __FUNCTION__, pid, errno, strerror(errno));
		return DWPAL_FAILURE;
    }

	/* fill socket address structure with server's address */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;

	snprintf(socketName, sizeof(socketName) - 1, "%s_%d", COMMAND_ENDED_SOCKET, pid);
	strcpy_s(un.sun_path, SOCKET_NAME_LENGTH, socketName);
	len = offsetof(struct sockaddr_un, sun_path) + strnlen_s(socketName, sizeof(socketName));

	if (connect(fd, (struct sockaddr *)&un, len) < 0)
	{
		console_printf("%s; connect() fail; pid= %d; errno= %d ('%s')\n",
		       __FUNCTION__, pid, errno, strerror(errno));

		if (close(fd) == (-1))
		{
			console_printf("%s; close() fail; pid= %d; errno= %d ('%s')\n",
				   __FUNCTION__, pid, errno, strerror(errno));
		}

		return DWPAL_FAILURE;
	}

	if ((byte = write(fd, NULL, 0)) == -1)
	{
		console_printf("%s; write() fail; pid= %d; errno= %d ('%s')\n",
		       __FUNCTION__, pid, errno, strerror(errno));

		if (close(fd) == (-1))
		{
			console_printf("%s; close() fail; pid= %d; errno= %d ('%s')\n",
				   __FUNCTION__, pid, errno, strerror(errno));
		}

		return DWPAL_FAILURE;
	}

	if (close(fd) == (-1))
	{
		console_printf("%s; close() fail; pid= %d; errno= %d ('%s')\n",
		       __FUNCTION__, pid, errno, strerror(errno));
	}

	return DWPAL_SUCCESS;
}


static DWPAL_Ret nlInternalNlCallback(DWPAL_NlEventType nlEventType, struct nl_msg *msg, void *arg)
{
	DWPAL_Context     *localContext = (DWPAL_Context *)(arg);
	struct nlattr     *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr     *tb[NL80211_ATTR_MAX + 1];
	unsigned char     *data;
	int               len, vendor_subcmd = -1;
	char              ifname[DWPAL_VAP_NAME_STRING_LENGTH] = "\0";

	console_printf("%s Entry; nlEventType= %d (DWPAL_NL_EVENT_GET=0, DWPAL_NL_CMD_GET=1)\n", __FUNCTION__, nlEventType);

	if ( (nlEventType == DWPAL_NL_EVENT_GET) && (localContext->interface.driver.nlEventCallback == NULL) )
	{
		console_printf("%s; 'DWPAL_NL_EVENT_GET' and nlEventCallback=NULL ==> exit\n", __FUNCTION__);
		return (int)DWPAL_SUCCESS;
	}

	nla_parse(tb,
			  NL80211_ATTR_MAX,
			  genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0),
			  NULL);

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
					genlmsg_attrlen(gnlh, 0),
					NL80211_ATTR_VENDOR_DATA);

	if (!attr)
	{
		console_printf("%s; vendor data attribute missing ==> Abort!\n", __FUNCTION__);
		return (int)DWPAL_FAILURE;
	}

	data = (unsigned char *)nla_data(attr);
	len = nla_len(attr);

	if ( (gnlh->cmd == NL80211_CMD_VENDOR) && (tb[NL80211_ATTR_VENDOR_SUBCMD] != NULL) )
	{
		vendor_subcmd = nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]);
	}

	if (tb[NL80211_ATTR_IFINDEX] != NULL)
	{
		if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname);
	}

	if (nlEventType == DWPAL_NL_CMD_GET)
	{
		/* Call the NL 'get command' callback function */
		localContext->interface.driver.nlCmdGetCallback(ifname, gnlh->cmd, vendor_subcmd, (size_t)len, data);

		console_printf("%s; 'get command' received ==> notify dwpal_ext\n", __FUNCTION__);
		if (command_get_ended_msg_send() == DWPAL_FAILURE)
		{
			console_printf("%s; command_get_ended_msg_send failed ==> cont...\n", __FUNCTION__);
		}
	}
	else if (nlEventType == DWPAL_NL_EVENT_GET)
	{
		/* Call the NL callback function */
		localContext->interface.driver.nlEventCallback(ifname, gnlh->cmd, vendor_subcmd, (size_t)len, data);
	}
	else
	{
		console_printf("%s; invalid nlEventType (%d) ==> Abort!\n", __FUNCTION__, nlEventType);
		return DWPAL_FAILURE;
	}

	return (int)DWPAL_SUCCESS;
}


static int nlInternalCmdGetCallback(struct nl_msg *msg, void *arg)
{
	console_printf("%s Entry\n", __FUNCTION__);

	if (nlInternalNlCallback(DWPAL_NL_CMD_GET, msg, arg) == DWPAL_FAILURE)
	{
		console_printf("%s; nlInternalNlCallback ERROR ==> Abort!\n", __FUNCTION__);
		return (int)DWPAL_FAILURE;
	}

	return (int)DWPAL_SUCCESS;
}


static int nlInternalEventCallback(struct nl_msg *msg, void *arg)
{
	console_printf("%s Entry\n", __FUNCTION__);

	if (nlInternalNlCallback(DWPAL_NL_EVENT_GET, msg, arg) == DWPAL_FAILURE)
	{
		console_printf("%s; nlInternalNlCallback ERROR ==> Abort!\n", __FUNCTION__);
		return (int)DWPAL_FAILURE;
	}

	return (int)DWPAL_SUCCESS;
}


static DWPAL_Ret nlSocketCreate(struct nl_sock **nlSocket, int *fd)
{
	int res = 1;

	*nlSocket = nl_socket_alloc();
	if (*nlSocket == NULL)
	{
		console_printf("%s; nl_socket_alloc ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Connect to generic netlink socket on kernel side */
	if (genl_connect(*nlSocket) < 0)
	{
		console_printf("%s; genl_connect ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(*nlSocket);
		return DWPAL_FAILURE;
	}

	if (nl_socket_set_buffer_size(*nlSocket, 8192, 8192) != 0)
	{
		console_printf("%s; nl_socket_set_buffer_size ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(*nlSocket);
		return DWPAL_FAILURE;
	}

	*fd = nl_socket_get_fd(*nlSocket);
	if (*fd == -1)
	{
		console_printf("%s; nl_socket_get_fd ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(*nlSocket);
		return DWPAL_FAILURE;
	}
	console_printf("%s; driver.fd= %d\n", __FUNCTION__, *fd);

	/* manipulate options for the socket referred to by the file descriptor - driver.fd */
	setsockopt(*fd, SOL_NETLINK /*option level argument*/,
		   NETLINK_EXT_ACK, &res, sizeof(res));

	return DWPAL_SUCCESS;
}


static bool mandatoryFieldValueGet(char *buf, size_t *bufLen, char **p2str, int totalSizeOfArg, char fieldValue[] /*OUT*/)
{
	char *param = strtok_s(buf, bufLen, " ", p2str);

	if (param == NULL)
	{
		console_printf("%s; param is NULL ==> Abort!\n", __FUNCTION__);
		return false;
	}

	if (fieldValue != NULL)
	{
		if (strnlen_s(param, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) > (size_t)(totalSizeOfArg - 1))
		{
			console_printf("%s; param ('%s') length (%d) is higher than allocated size (%d) ==> Abort!\n", __FUNCTION__, param, strnlen_s(param, totalSizeOfArg), totalSizeOfArg-1);
			return false;
		}

		strcpy_s(fieldValue, strnlen_s(param, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1, param);
	}

	return true;
}


static bool arrayValuesGet(char *stringOfValues, size_t totalSizeOfArg, ParamParsingType paramParsingType, size_t *numOfValidArgs /*OUT*/, void *array /*OUT*/)
{
	/* fill in the output array with list of integer elements (from decimal/hex base), for example:
	   "SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108" or "HT_MCS=FF FF FF 00 00 00 00 00 00 00 C2 01 01 00 00 00"
	   also, in case of "DWPAL_STR_ARRAY_PARAM", handle multiple repetitive field, for example:
	   "... non_pref_chan=81:200:1:5 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 ..." or
	   "... non_pref_chan=81:200:1:5 81:100:2:9 81:200:1:7 81:100:2:5 ..." */

	int     idx = 0;
	char    *p2str, *param, *tokenString;
	rsize_t dmaxLen = strnlen_s(stringOfValues, DWPAL_TO_HOSTAPD_MSG_LENGTH);

	tokenString = stringOfValues;

	do
	{
		param = strtok_s(tokenString, &dmaxLen, " ", &p2str);
		if (param == NULL)
		{
			((int *)array)[idx] = 0;
			break;
		}

		if (idx < (int)totalSizeOfArg)
		{
			if (numOfValidArgs != NULL)
			{
				(*numOfValidArgs)++;
			}

			if (paramParsingType == DWPAL_INT_HEX_ARRAY_PARAM)
			{
				((int *)array)[idx] = strtol(param, NULL, 16);
			}
			else if (paramParsingType == DWPAL_INT_ARRAY_PARAM)
			{
				((int *)array)[idx] = atoi(param);
			}
			else if (paramParsingType == DWPAL_STR_ARRAY_PARAM)
			{
				strcpy_s(&(((char *)array)[idx * HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH]), strnlen_s(param, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1, param);
			}
		}

		tokenString = NULL;

		idx++;
	} while (idx < DWPAL_MAX_NUM_OF_ELEMENTS);  /* allow up to 512 elements per field (array) */

	if (idx >= (int)totalSizeOfArg)
	{
		console_printf("%s; actual number of arguments (%d) is bigger/equal then totalSizeOfArg (%d) ==> Abort!\n", __FUNCTION__, idx, totalSizeOfArg);
		return false;
	}

	return true;
}


static bool fieldValuesGet(char *buf, size_t bufLen, const char *stringToSearch, char *endFieldName[], char *stringOfValues /*OUT*/)
{
	/* handles list of fields, one by one in the same row, for example: "... btm_supported=1 ..." or
	   "... SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108 ..." */

	char    *stringStart, *stringEnd, *restOfStringStart, *closerStringEnd = NULL;
	char    *localBuf = NULL;
	char    *localStringToSearch = NULL;
	int     i, idx=0, numOfCharacters = 0, numOfCharactersToCopy = 0;
	bool    isFirstEndOfString = true, ret = false;
	char    tempStringOfValues[HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH], localEndFieldName[HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH];

	localBuf = (char *)malloc(bufLen + 2 /* '\0' & 'blank' */);
	if (localBuf == NULL)
	{
		console_printf("%s; malloc failed ==> Abort!\n", __FUNCTION__);
		return false;
	}

	/* Add ' ' at the beginning of a string - to handle a case in which the buf starts with the
	   value of stringToSearch, like buf= 'candidate=d8:fe:e3:3e:bd:14,2178,83,5,7,255 candidate=...' */
	snprintf(localBuf, bufLen + 2, " %s", buf);

	/* localStringToSearch set to stringToSearch with addition of " " at the beginning -
	   it is a MUST in order to differentiate between "ssid" and "bssid" */
	localStringToSearch = (char *)malloc(strnlen_s(stringToSearch, DWPAL_FIELD_NAME_LENGTH) + 2 /*'\0' & 'blank' */);
	if (localStringToSearch == NULL)
	{
		console_printf("%s; localStringToSearch is NULL ==> Abort!\n", __FUNCTION__);
		free((void *)localBuf);
		return false;
	}

	snprintf(localStringToSearch, DWPAL_FIELD_NAME_LENGTH, " %s", stringToSearch);

	restOfStringStart = localBuf;

	while ( (stringStart = strstr(restOfStringStart, localStringToSearch)) != NULL )
	{
		ret = true;  /* mark that at least one fiels was found */

		/* move the string pointer to the beginning of the field's value */
		restOfStringStart = stringStart + strnlen_s(localStringToSearch, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH);
		//console_printf("%s; stringStart= 0x%x, strlen of ('%s')= %d ==> restOfStringStart= 0x%x\n",
			   //__FUNCTION__, (unsigned int)stringStart, localStringToSearch, strnlen_s(localStringToSearch, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH), (unsigned int)restOfStringStart);

		/* find all beginning of all other fields (and get the closest to the current field) in order to know where the field's value ends */
		i = 0;
		while (strncmp(endFieldName[i], "\n", 1))
		{  /* run over all field names in the string */
			snprintf(localEndFieldName, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH, " %s", endFieldName[i]);  /* in order to differentiate between VHT_MCS and HT_MCS */
			stringEnd = strstr(restOfStringStart, localEndFieldName);
			if (stringEnd != NULL)
			{
				stringEnd++;  /* move one character ahead due to the ' ' at the beginning of localEndFieldName */
				//console_printf("%s; localEndFieldName= '%s' FOUND! (i= %d)\n", __FUNCTION__, localEndFieldName, i);
				if (isFirstEndOfString)
				{
					isFirstEndOfString = false;
					closerStringEnd = stringEnd;
				}
				else
				{  /* Make sure that closerStringEnd will point to the closest field ahead */
					closerStringEnd = (stringEnd < closerStringEnd)? stringEnd : closerStringEnd;
				}

				//console_printf("%s; [0] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);
			}

			i++;
		}

		//console_printf("%s; [1] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);

		if (closerStringEnd == NULL)
		{  /* Meaning, this is the last parameter in the string */
			//console_printf("%s; closerStringEnd is NULL; restOfStringStart= '%s'\n", __FUNCTION__, restOfStringStart);
			closerStringEnd = restOfStringStart + strnlen_s(restOfStringStart, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1 /* for '\0' */;
			//console_printf("%s; [2] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);

			//console_printf("%s; String end did NOT found ==> set closerStringEnd to the end of buf; closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);
		}

		//console_printf("%s; stringToSearch= '%s'; restOfStringStart= '%s'; buf= '%s'\n", __FUNCTION__, stringToSearch, restOfStringStart, buf);
		//console_printf("%s; restOfStringStart= 0x%x, closerStringEnd= 0x%x ==> characters to copy = %d\n", __FUNCTION__, (unsigned int)restOfStringStart, (unsigned int)closerStringEnd, closerStringEnd - restOfStringStart);

		/* set 'numOfCharacters' with the number of characters to copy (including the blank or end-of-string at the end) */
		numOfCharacters = closerStringEnd - restOfStringStart;
		if (numOfCharacters <= 0)
		{
			console_printf("%s; numOfCharacters= %d ==> Abort!\n", __FUNCTION__, numOfCharacters);
			free((void *)localBuf);
			free((void *)localStringToSearch);
			return false;
		}

		/* Copy the characters of the value, and set the last one to '\0' */
		strncpy_s(tempStringOfValues, sizeof(tempStringOfValues), restOfStringStart, numOfCharacters);
		tempStringOfValues[numOfCharacters - 1] = '\0';
		//console_printf("%s; stringToSearch= '%s'; tempStringOfValues= '%s'\n", __FUNCTION__, stringToSearch, tempStringOfValues);

		/* Check if all elements are valid; if an element contains "=", it is NOT valid ==> do NOT copy it! */
		for (i=0; i < numOfCharacters; i++)
		{
			if ( (tempStringOfValues[i] == ' ') || (tempStringOfValues[i] == '\0') )
			{
				numOfCharactersToCopy = i + 1 /* convert index to number-of */;
			}
			else if (tempStringOfValues[i] == '=')
			{
				break;
			}
		}

		strncpy(&stringOfValues[idx], restOfStringStart, numOfCharactersToCopy);
		idx += numOfCharactersToCopy;
		stringOfValues[idx] = '\0';

		//console_printf("%s; stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, stringToSearch, stringOfValues);

		closerStringEnd = NULL;
	}

	/* Remove all ' ' from the end of the string */
	for (i= idx-1; i > 0; i--)
	{
		if (stringOfValues[i] != ' ')
		{
			break;  /* Stop removing the ' ' characters when the first non-blank character was found! */
		}
		else if (stringOfValues[i] == ' ')
		{  /* stringOfValues[i] == ' ' */
			stringOfValues[i] = '\0';
		}
	}

	//console_printf("%s; stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, stringToSearch, stringOfValues);

	free((void *)localBuf);
	free((void *)localStringToSearch);

	//console_printf("%s; ret= %d, stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, ret, stringToSearch, stringOfValues);

	return ret;
}


static bool isColumnOfFields(char *msg, char *endFieldName[])
{
	int i = 0, numOfFieldsInLine = 0;

	//console_printf("%s; line= '%s'\n", __FUNCTION__, msg);

	if (endFieldName == NULL)
	{
		console_printf("%s; endFieldName= 'NULL' ==> not a column!\n", __FUNCTION__);
		return false;
	}

	while (strncmp(endFieldName[i], "\n", 1))
	{  /* run over all field names in the string */
		if (strstr(msg, endFieldName[i]) != NULL)
		{
			numOfFieldsInLine++;

			if (numOfFieldsInLine > 1)
			{
				//console_printf("%s; Not a column (numOfFieldsInLine= %d) ==> return!\n", __FUNCTION__, numOfFieldsInLine);
				return false;
			}

			/* Move ahead inside the line, to avoid double recognition (like "PacketsSent" and "DiscardPacketsSent") */
			msg += strnlen_s(endFieldName[i], HOSTAPD_TO_DWPAL_MSG_LENGTH);
		}

		i++;
	}

	//console_printf("%s; It is a column (numOfFieldsInLine= %d)\n", __FUNCTION__, numOfFieldsInLine);

	return true;
}


static bool columnOfParamsToRowConvert(char *msg, size_t msgLen, char *endFieldName[])
{
	char    *localMsg = strdup(msg), *lineMsg, *p2str;
	rsize_t dmaxLen = (rsize_t)msgLen;
	bool    isColumn = true;
	int     i;

	if (localMsg == NULL)
	{
		console_printf("%s; strdup error ==> Abort!\n", __FUNCTION__);
		return false;
	}

	lineMsg = strtok_s(localMsg, (rsize_t *)&dmaxLen, "\n", &p2str);

	while (lineMsg != NULL)
	{
		isColumn = isColumnOfFields(lineMsg, endFieldName);

		if (isColumn == false)
		{
			//console_printf("%s; Not a column ==> break!\n", __FUNCTION__);
			break;
		}

		lineMsg = strtok_s(NULL, (rsize_t *)&dmaxLen, "\n", &p2str);
	}

	free ((void *)localMsg);

	if (isColumn)
	{
		/* Modify the column string to be in ONE raw  */
		for (i=0; i < (int)msgLen; i++)
		{
			if (msg[i] == '\n')
			{
				msg[i] = ' ';
			}
		}

		msg[msgLen] = '\0';
	}

	return true;
}



/* Low Level APIs */

DWPAL_Ret dwpal_driver_nl_cmd_send(void *context,
                                   DWPAL_NlEventType nlEventType,
								   char *ifname,
								   enum nl80211_commands nl80211Command,
								   CmdIdType cmdIdType,
								   enum ltq_nl80211_vendor_subcmds subCommand,
								   unsigned char *vendorData,
								   size_t vendorDataSize)
{
	int              i, res;
	struct nl_msg    *msg;
	DWPAL_Context    *localContext = (DWPAL_Context *)(context);
	signed long long devidx = 0;
	struct nl_sock   *nlSocket = NULL;

	console_printf("%s Entry\n", __FUNCTION__);

	if (nl80211Command != NL80211_CMD_VENDOR /*0x67*/)
	{
		console_printf("%s; non supported command (0x%x); currently we support ONLY NL80211_CMD_VENDOR (0x67) ==> Abort!\n", __FUNCTION__, (unsigned int)nl80211Command);
		return DWPAL_FAILURE;
	}

	for (i=0; i < (int)vendorDataSize; i++)
	{
		console_printf("%s; vendorData[%d]= 0x%x\n", __FUNCTION__, i, vendorData[i]);
	}

	if (nlEventType == DWPAL_NL_EVENT_GET)
	{
		nlSocket = localContext->interface.driver.nlSocketEvent;
	}
	else if (nlEventType == DWPAL_NL_CMD_GET)
	{
		nlSocket = localContext->interface.driver.nlSocketCmdGet;
	}
	else
	{
		console_printf("%s; invalid nlEventType (%d) ==> Abort!\n", __FUNCTION__, nlEventType);
		return DWPAL_FAILURE;
	}

	if (localContext == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (nlSocket == NULL)
	{
		console_printf("%s; nlSocket is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		console_printf("%s; nlmsg_alloc returned NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	console_printf("%s; nl80211_id= %d\n", __FUNCTION__, localContext->interface.driver.nl80211_id);

	/* calling genlmsg_put() is a must! without it, the callback won't be called! */
	genlmsg_put(msg, 0, 0, localContext->interface.driver.nl80211_id, 0,0, nl80211Command /* NL80211_CMD_VENDOR=0x67*/, 0);

	//iw dev wlan0 vendor recv 0xAC9A96 0x69 0x00 ==> send "0xAC9A96 0x69 0x00"
	devidx = if_nametoindex(ifname);
	if (devidx < 0)
	{
		console_printf("%s; devidx ERROR (devidx= %lld) ==> Abort!\n", __FUNCTION__, devidx);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	switch (cmdIdType)
	{
		case DWPAL_NETDEV_ID:
			res = nla_put_u32(msg, NL80211_ATTR_IFINDEX, devidx);
			//NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
			break;

		case DWPAL_PHY_ID:
			res = nla_put_u32(msg, NL80211_ATTR_WIPHY, devidx);
			//NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
			break;

		case DWPAL_WDEV_ID:
			res = nla_put_u64(msg, NL80211_ATTR_WDEV, devidx);
			//NLA_PUT_U64(msg, NL80211_ATTR_WDEV, devidx);
			break;

		default:
			console_printf("%s; cmdIdType ERROR (cmdIdType= %d) ==> Abort!\n", __FUNCTION__, cmdIdType);
			nlmsg_free(msg);
			return DWPAL_FAILURE;
	}

	if (res < 0)
	{
		console_printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	res = nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_LTQ /*0xAC9A96*/);
	//NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, OUI_LTQ /*0xAC9A96*/);
	if (res < 0)
	{
		console_printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	res = nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subCommand);
	//NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, subCommand);
	if (res < 0)
	{
		console_printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	if ( (vendorDataSize > 0) && (vendorData != NULL) )
	{
		//NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, count, buf);
		res = nla_put(msg, NL80211_ATTR_VENDOR_DATA, (int)vendorDataSize, (void *)vendorData);
		if (res < 0)
		{
			console_printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
			nlmsg_free(msg);
			return DWPAL_FAILURE;
		}
	}

	/* will trigger nlEventCallback() function call */
	res = nl_send_auto(nlSocket, msg);  // can use nl_send_auto_complete(nlSocket, msg) instead
	if (res < 0)
	{
		console_printf("%s; nl_send_auto returned ERROR (res= %d) ==> Abort!\n", __FUNCTION__, res);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	nlmsg_free(msg);

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_msg_get(void *context, DWPAL_NlEventType nlEventType, DWPAL_nlEventCallback nlEventCallback)
{
	int           res;
	struct nl_cb  *cb;
	DWPAL_Context *localContext = (DWPAL_Context *)(context);

	console_printf("%s Entry; nlEventType= %d (DWPAL_NL_EVENT_GET=0, DWPAL_NL_CMD_GET=1)\n", __FUNCTION__, nlEventType);

	if (localContext == NULL)
	{
		console_printf("%s; localContext is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if ( ( (nlEventType == DWPAL_NL_EVENT_GET) && (localContext->interface.driver.nlSocketEvent == NULL) ) ||
	     ( (nlEventType == DWPAL_NL_CMD_GET) && (localContext->interface.driver.nlSocketCmdGet == NULL) ) )
	{
		console_printf("%s; nlSocket is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Connect the nl socket to its message callback function */
	cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (cb == NULL)
	{
		console_printf("%s; failed to allocate netlink callbacks ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	if (nlEventType == DWPAL_NL_EVENT_GET)
	{
		/* nlEventCallback can be NULL; in that case, the D-WPAL client's callback function won't be called */
		localContext->interface.driver.nlEventCallback = nlEventCallback;

		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nlInternalEventCallback, context);

		/* will trigger nlEventCallback() function call */
		res = nl_recvmsgs(localContext->interface.driver.nlSocketEvent, cb);
	}
	else if (nlEventType == DWPAL_NL_CMD_GET)
	{
		/* nlEventCallback can be NULL; in that case, the D-WPAL client's callback function won't be called */
		localContext->interface.driver.nlCmdGetCallback = nlEventCallback;

		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nlInternalCmdGetCallback, context);

		/* will trigger nlEventCallback() function call */
		res = nl_recvmsgs(localContext->interface.driver.nlSocketCmdGet, cb);
	}
	else
	{
		console_printf("%s; invalid nlEventType (%d) ==> Abort!\n", __FUNCTION__, nlEventType);
		return DWPAL_FAILURE;
	}

	if (res < 0)
	{
		console_printf("%s; nl_recvmsgs_default returned ERROR (res= %d) ==> Abort!\n", __FUNCTION__, res);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_fd_get(void *context, int *fd /*OUT*/, int *fdCmdGet /*OUT*/)
{
	if ( (context == NULL) || (fd == NULL) || (fdCmdGet == NULL) )
	{
		console_printf("%s; context and/or fd, fdCmdGet is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*fd = ((DWPAL_Context *)context)->interface.driver.fd;
	if (*fd == (-1))
	{
		console_printf("%s; fd value is (-1) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*fdCmdGet = ((DWPAL_Context *)context)->interface.driver.fdCmdGet;
	if (*fdCmdGet == (-1))
	{
		console_printf("%s; fdCmdGet value is (-1) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_detach(void **context /*IN/OUT*/)
{
	DWPAL_Context *localContext;

	if (context == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);
	if (localContext == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.driver.nlSocketEvent == NULL)
	{
		console_printf("%s; nlSocketEvent is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Note: calling nl_close() is NOT needed - The socket is closed automatically when using nl_socket_free() */
	nl_socket_free(localContext->interface.driver.nlSocketEvent);
	nl_socket_free(localContext->interface.driver.nlSocketCmdGet);

	localContext->interface.driver.nlSocketEvent = NULL;
	localContext->interface.driver.nlSocketCmdGet = NULL;
	localContext->interface.driver.fd = -1;
	localContext->interface.driver.fdCmdGet = -1;
	localContext->interface.driver.nlEventCallback = NULL;
	localContext->interface.driver.nlCmdGetCallback = NULL;

	*context = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_attach(void **context /*OUT*/)
{
	int           mcid;
	DWPAL_Context *localContext;

	console_printf("%s Entry\n", __FUNCTION__);

	if (context == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*context = malloc(sizeof(DWPAL_Context));
	if (*context == NULL)
	{
		console_printf("%s; malloc for context failed ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);

	/* Create the NL socket for the events (unsolicited events) */
	if (nlSocketCreate(&localContext->interface.driver.nlSocketEvent, &localContext->interface.driver.fd) == DWPAL_FAILURE)
	{
		console_printf("%s; nlSocketCreate failed ==> Abort!\n", __FUNCTION__);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	mcid = genl_ctrl_resolve_grp(localContext->interface.driver.nlSocketEvent, "nl80211", "vendor");

	console_printf("%s; mcid= %d\n", __FUNCTION__, mcid);

	if (nl_socket_add_membership(localContext->interface.driver.nlSocketEvent, mcid) < 0)
	{
		console_printf("%s; nl_socket_add_membership ERROR ==> Abort!\n", __FUNCTION__);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	/* Create the NL socket for the 'get commands' (solicited events) */
	if (nlSocketCreate(&localContext->interface.driver.nlSocketCmdGet, &localContext->interface.driver.fdCmdGet) == DWPAL_FAILURE)
	{
		console_printf("%s; nlSocketCreate failed ==> Abort!\n", __FUNCTION__);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	/* Ask kernel to resolve nl80211_id name to nl80211_id id; nl80211_id is being used only for command send */
	localContext->interface.driver.nl80211_id = genl_ctrl_resolve(localContext->interface.driver.nlSocketCmdGet, "nl80211");
	if (localContext->interface.driver.nl80211_id < 0)
	{
		console_printf("%s; genl_ctrl_resolve ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(localContext->interface.driver.nlSocketEvent);
		nl_socket_free(localContext->interface.driver.nlSocketCmdGet);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}
	console_printf("%s; driver.nl80211_id= %d\n", __FUNCTION__, localContext->interface.driver.nl80211_id);

	console_printf("%s; driver.nlSocketEvent= 0x%x, fd= %d, driver.nlEventCallback= 0x%x, driver.nl80211_id= %d; nlSocketCmdGet= 0x%x, fdCmdGet= %d\n",
	       __FUNCTION__, (unsigned int)localContext->interface.driver.nlSocketEvent, localContext->interface.driver.fd,
		   (unsigned int)localContext->interface.driver.nlEventCallback, localContext->interface.driver.nl80211_id,
		   (unsigned int)localContext->interface.driver.nlSocketCmdGet, localContext->interface.driver.fdCmdGet);

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_string_to_struct_parse(char *msg, size_t msgLen, FieldsToParse fieldsToParse[])
{
	DWPAL_Ret ret = DWPAL_SUCCESS;
	int       i = 0, idx = 0, numOfNameArrayArgs = 0, lineIdx = 0;
	bool      isEndFieldNameAllocated = false, isMissingParam = false;
	char      stringOfValues[HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH];
	char      *lineMsg, *localMsg, *p2str = NULL, *p2strMandatory = NULL;
	rsize_t   dmaxLen, dmaxLenMandatory;
	size_t    sizeOfStruct = 0, msgStringLen;
	char      **endFieldName = NULL;

	if ( (msg == NULL) || (msgLen == 0) || (fieldsToParse == NULL) )
	{
		console_printf("%s; input params error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if ( (msgStringLen = strnlen_s(msg, HOSTAPD_TO_DWPAL_MSG_LENGTH)) > msgLen )
	{
		console_printf("%s; msgStringLen (%d) is bigger than msgLen (%d) ==> Abort!\n", __FUNCTION__, msgStringLen, msgLen);
		return DWPAL_FAILURE;
	}

	//console_printf("%s; [0] msgLen= %d\n", __FUNCTION__, msgLen);

	/* Convert msgLen to string length format (without the '\0' character) */
	msgLen = dmaxLen = msgStringLen;
	//console_printf("%s; [1] msgLen= %d\n", __FUNCTION__, msgLen);

	//console_printf("%s; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);

	/* Set values for 'numOfNameArrayArgs' and 'sizeOfStruct' */
	while (fieldsToParse[i].parsingType != DWPAL_NUM_OF_PARSING_TYPES)
	{
		/* Set numOfNameArrayArgs with the number of endFieldName arguments - needed for the dynamic allocation */
		if (fieldsToParse[i].stringToSearch != NULL)
		{
			numOfNameArrayArgs++;
		}

		/* Set sizeOfStruct with the structure size of the output parameter - needed for advancing the output array index (in case of many lines) */
		if (fieldsToParse[i].field != NULL)
		{
			switch (fieldsToParse[i].parsingType)
			{
				case DWPAL_STR_PARAM:
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].totalSizeOfArg == 0) )
					{
						console_printf("%s; Error; DWPAL_STR_PARAM must have positive value for totalSizeOfArg ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += sizeof(char) * fieldsToParse[i].totalSizeOfArg;  /* array of characters (string) */
					//console_printf("%s; DWPAL_STR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_STR_ARRAY_PARAM:
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].totalSizeOfArg == 0) )
					{
						console_printf("%s; Error; DWPAL_STR_ARRAY_PARAM must have positive value for totalSizeOfArg ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += fieldsToParse[i].totalSizeOfArg;
					//console_printf("%s; DWPAL_STR_ARRAY_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_CHAR_PARAM:
					sizeOfStruct += sizeof(char);
					//console_printf("%s; DWPAL_CHAR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_UNSIGNED_CHAR_PARAM:
					sizeOfStruct += sizeof(unsigned char);
					//console_printf("%s; DWPAL_UNSIGNED_CHAR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_SHORT_INT_PARAM:
					sizeOfStruct += sizeof(short int);
					//console_printf("%s; DWPAL_SHORT_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_INT_PARAM:
				case DWPAL_INT_HEX_PARAM:
					sizeOfStruct += sizeof(int);
					//console_printf("%s; DWPAL_INT_PARAM/DWPAL_INT_HEX_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_UNSIGNED_INT_PARAM:
					sizeOfStruct += sizeof(unsigned int);
					//console_printf("%s; DWPAL_UNSIGNED_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_LONG_LONG_INT_PARAM:
					sizeOfStruct += sizeof(long long int);
					//console_printf("%s; DWPAL_LONG_LONG_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_UNSIGNED_LONG_LONG_INT_PARAM:
					sizeOfStruct += sizeof(unsigned long long int);
					//console_printf("%s; DWPAL_UNSIGNED_LONG_LONG_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_INT_ARRAY_PARAM:
				case DWPAL_INT_HEX_ARRAY_PARAM:
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].totalSizeOfArg == 0) )
					{
						console_printf("%s; Error; DWPAL_INT_ARRAY_PARAM/DWPAL_INT_HEX_ARRAY_PARAM must have positive value for totalSizeOfArg ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += sizeof(int) * fieldsToParse[i].totalSizeOfArg;
					//console_printf("%s; DWPAL_INT_ARRAY_PARAM/DWPAL_INT_HEX_ARRAY_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_BOOL_PARAM:
					sizeOfStruct += sizeof(bool);
					//console_printf("%s; DWPAL_BOOL_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				default:
					console_printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].parsingType);
					ret = DWPAL_FAILURE;
					break;
			}
		}

		i++;
	}

	/* Allocate and set the value for each endFieldName[] string */
	if (numOfNameArrayArgs > 0)
	{
		numOfNameArrayArgs++;  /* for the last allocated argument */

		endFieldName = (char **)malloc(sizeof(*endFieldName) * numOfNameArrayArgs);
		if (endFieldName == NULL)
		{
			console_printf("%s; malloc endFieldName failed ==> Abort!\n", __FUNCTION__);
			ret = DWPAL_FAILURE;
		}
		else
		{
			memset((void *)endFieldName, (int)NULL, sizeof(*endFieldName) * numOfNameArrayArgs);
		}

		i = idx = 0;
		while ( (fieldsToParse[i].parsingType != DWPAL_NUM_OF_PARSING_TYPES) && (idx < (numOfNameArrayArgs-1)) && (ret == DWPAL_SUCCESS) )
		{
			if (fieldsToParse[i].numOfValidArgs != NULL)
			{
				*(fieldsToParse[i].numOfValidArgs) = 0;
			}

			if (fieldsToParse[i].stringToSearch != NULL)
			{
				endFieldName[idx] =  (char *)malloc(DWPAL_FIELD_NAME_LENGTH);
				if (endFieldName[idx] == NULL)
				{
					console_printf("%s; malloc endFieldName[%d] failed ==> Abort!\n", __FUNCTION__, i);
					ret = DWPAL_FAILURE;
					break;
				}

				memset((void *)endFieldName[idx], '\0', DWPAL_FIELD_NAME_LENGTH);  /* Clear the field name */
				strcpy_s(endFieldName[idx], strnlen_s(fieldsToParse[i].stringToSearch, DWPAL_FIELD_NAME_LENGTH) + 1, fieldsToParse[i].stringToSearch);

				idx++;
			}

			i++;
		}

		if (ret == DWPAL_SUCCESS)
		{
			endFieldName[idx] =  (char *)malloc(DWPAL_FIELD_NAME_LENGTH);
			if (endFieldName[idx] == NULL)
			{
				console_printf("%s; malloc endFieldName[%d] failed ==> Abort!\n", __FUNCTION__, idx);
				ret = DWPAL_FAILURE;
			}
			else
			{
				memset((void *)endFieldName[idx], '\0', DWPAL_FIELD_NAME_LENGTH);  /* Clear the field name */
				strcpy_s(endFieldName[idx], 2, "\n");
				isEndFieldNameAllocated = true;
			}
		}
	}

	//console_printf("%s; [0] msg= '%s'\n", __FUNCTION__, msg);

	/* In case of a column, convert it to one raw */
	if ( (ret == DWPAL_SUCCESS) && (isEndFieldNameAllocated) )
	{
		if (columnOfParamsToRowConvert(msg, msgLen , endFieldName) == false)
		{
			console_printf("%s; columnOfParamsToRowConvert error ==> Abort!\n", __FUNCTION__);
			ret = DWPAL_FAILURE;
		}
	}

	//console_printf("%s; [1] msg= '%s'\n", __FUNCTION__, msg);

	/* Perform the actual parsing */
	//console_printf("%s; [1.1] dmaxLen= %d, p2str= '%s'\n", __FUNCTION__, dmaxLen, p2str);
	lineMsg = strtok_s(msg, &dmaxLen, "\n", &p2str);
	localMsg = lineMsg;
	lineIdx = 0;

	while ( (lineMsg != NULL) && (ret == DWPAL_SUCCESS) )
	{
		void *field;
		char *localMsgDup = NULL;

		//console_printf("%s; [2] lineMsg= '%s'\n", __FUNCTION__, lineMsg);

		i = 0;
		while ( (fieldsToParse[i].parsingType != DWPAL_NUM_OF_PARSING_TYPES) && (ret == DWPAL_SUCCESS) )
		{
			if (fieldsToParse[i].field == NULL)
			{
				field = NULL;
			}
			else
			{
				/* set the output parameter - move it to the next array index (needed when parsing many lines) */
				field = (void *)((unsigned long)fieldsToParse[i].field + lineIdx * sizeOfStruct);
				//console_printf("%s; lineIdx= %d, sizeOfStruct= %d, field= 0x%x\n", __FUNCTION__, lineIdx, sizeOfStruct, (unsigned int)field);
			}

			switch (fieldsToParse[i].parsingType)
			{
				case DWPAL_STR_PARAM:
					if (fieldsToParse[i].stringToSearch == NULL)
					{  /* Handle mandatory parameters WITHOUT any string-prefix */
						if (localMsg != NULL)
						{
							localMsgDup = strdup(localMsg);
							if (localMsgDup == NULL)
							{
								console_printf("%s; localMsgDup is NULL, Failed strdup ==> Abort!\n", __FUNCTION__);
								ret = DWPAL_FAILURE;
								break;
							}
						}

						dmaxLenMandatory = (rsize_t)strnlen_s(lineMsg, HOSTAPD_TO_DWPAL_MSG_LENGTH);
						if (mandatoryFieldValueGet(((localMsg != NULL)? localMsgDup : NULL) /*will be NULL starting from 2nd param*/,
						                           &dmaxLenMandatory,
						                           &p2strMandatory,
						                           (int)fieldsToParse[i].totalSizeOfArg,
						                           (char *)field /*OUT*/) == false)
						{
							console_printf("%s; mandatory is NULL ==> Abort!\n", __FUNCTION__);
							ret = DWPAL_FAILURE;  /* mandatory parameter is missing ==> Abort! */
						}
						else
						{
							(*(fieldsToParse[i].numOfValidArgs))++;
						}

						localMsg = NULL;  /* for 2nd, 3rd, ... parameter */
					}
					else
					{
						if (isEndFieldNameAllocated == false)
						{
							console_printf("%s; DWPAL_STR_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
							ret = DWPAL_FAILURE;
							break;
						}

						if (field == NULL)
						{
							console_printf("%s; DWPAL_STR_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
						}
						else
						{
							memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
							if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								if ((strnlen_s(stringOfValues, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1) > fieldsToParse[i].totalSizeOfArg)
								{
									console_printf("%s; string length (%d) is bigger the allocated string size (%d)\n",
												__FUNCTION__, strnlen_s(stringOfValues, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1, fieldsToParse[i].totalSizeOfArg);
									ret = DWPAL_FAILURE;  /* longer string then allocated ==> Abort! */
								}
								else
								{
									strcpy_s((char *)field, strnlen_s(stringOfValues, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1, stringOfValues);
								}
							}
							else
							{
								isMissingParam = true;
							}
						}
					}
					break;

				case DWPAL_STR_ARRAY_PARAM:
				/* handle multiple repetitive field, for example:
				   "... non_pref_chan=81:200:1:5 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 ..." or
				   "... non_pref_chan=81:200:1:5 81:100:2:9 81:200:1:7 81:100:2:5 ..." */
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_STR_ARRAY_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_STR_ARRAY_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (arrayValuesGet(stringOfValues, fieldsToParse[i].totalSizeOfArg, DWPAL_STR_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, (char *)field) == false)
							{
								console_printf("%s; arrayValuesGet ERROR\n", __FUNCTION__);
							}
						}
						else
						{
							isMissingParam = true;
						}

						if ( (fieldsToParse[i].numOfValidArgs != NULL) && (*(fieldsToParse[i].numOfValidArgs) == 0) )
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_CHAR_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_CHAR_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_CHAR_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(char *)field = (char)atoi(stringOfValues);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(char *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_UNSIGNED_CHAR_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_UNSIGNED_CHAR_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_UNSIGNED_CHAR_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(unsigned char *)field = (unsigned char)atoi(stringOfValues);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(unsigned char *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_SHORT_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_SHORT_INT_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_SHORT_INT_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(short int *)field = (short int)atoi(stringOfValues);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(short int *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_INT_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_INT_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(int *)field = atoi(stringOfValues);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(int *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_UNSIGNED_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_UNSIGNED_INT_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_UNSIGNED_INT_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(unsigned int *)field = strtoul(stringOfValues, NULL, 10);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(unsigned int *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_LONG_LONG_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_LONG_LONG_INT_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_LONG_LONG_INT_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(long long int *)field = atoll(stringOfValues);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(long long int *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_UNSIGNED_LONG_LONG_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_UNSIGNED_LONG_LONG_INT_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_UNSIGNED_LONG_LONG_INT_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (strncmp(stringOfValues, "UNKNOWN", 8))
							{
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									(*(fieldsToParse[i].numOfValidArgs))++;
								}

								*(unsigned long long int *)field = strtoull(stringOfValues, NULL, 10);
							}
							else
							{  /* In case that the return value is "UNKNOWN", set isValid to 'false' and value to '0' */
								if (fieldsToParse[i].numOfValidArgs != NULL)
								{
									*(fieldsToParse[i].numOfValidArgs) = 0;
								}

								*(unsigned long long int *)field = 0;
								isMissingParam = true;
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_INT_ARRAY_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_INT_ARRAY_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_INT_ARRAY_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							//console_printf("%s; [1] fieldsToParse[%d].numOfValidArgs= %d, stringOfValues= '%s'\n", __FUNCTION__, i, *(fieldsToParse[i].numOfValidArgs), stringOfValues);
							if (arrayValuesGet(stringOfValues, fieldsToParse[i].totalSizeOfArg, DWPAL_INT_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, field) == false)
							{
								console_printf("%s; arrayValuesGet ERROR\n", __FUNCTION__);
							}
							//console_printf("%s; [2] fieldsToParse[%d].numOfValidArgs= %d\n", __FUNCTION__, i, *(fieldsToParse[i].numOfValidArgs));
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_INT_HEX_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_INT_HEX_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_INT_HEX_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (fieldsToParse[i].numOfValidArgs != NULL)
							{
								(*(fieldsToParse[i].numOfValidArgs))++;
							}

							*((int *)field) = strtol(stringOfValues, NULL, 16);
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_INT_HEX_ARRAY_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_INT_HEX_ARRAY_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_INT_HEX_ARRAY_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (arrayValuesGet(stringOfValues, fieldsToParse[i].totalSizeOfArg, DWPAL_INT_HEX_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, field) == false)
							{
								console_printf("%s; arrayValuesGet (stringToSearch= '%s') ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].stringToSearch);
								ret = DWPAL_FAILURE; /* array of string detected, but getting its arguments failed ==> Abort! */
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_BOOL_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						console_printf("%s; DWPAL_BOOL_PARAM; isEndFieldNameAllocated=false ==> Abort!\n", __FUNCTION__);
						ret = DWPAL_FAILURE;
						break;
					}

					if (field == NULL)
					{
						console_printf("%s; DWPAL_BOOL_PARAM; fieldsToParse[%d].field=NULL ==> cont...\n", __FUNCTION__, i);
					}
					else
					{
						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (fieldsToParse[i].numOfValidArgs != NULL)
							{
								(*(fieldsToParse[i].numOfValidArgs))++;
							}

							*((bool *)field) = atoi(stringOfValues);
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				default:
					console_printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].parsingType);
					ret = DWPAL_FAILURE;
					break;
			}

			i++;
		}

		if (localMsgDup != NULL)
		{
			free((void *)localMsgDup);
		}

		lineMsg = strtok_s(NULL, &dmaxLen, "\n", &p2str);
		lineIdx++;
		localMsg = lineMsg;
	}

	/* free the allocated string array (if needed) */
	for (i=0; i < numOfNameArrayArgs; i++)
	{
		if ( (endFieldName != NULL) && (isEndFieldNameAllocated) && (endFieldName[i] != NULL) )
			free((void *)endFieldName[i]);
	}

	if (endFieldName != NULL)
	{
		free((void *)endFieldName);
	}

	if (ret != DWPAL_FAILURE)
	{
		if (isMissingParam)
		{
			ret = DWPAL_MISSING_PARAM;
		}
	}

	return ret;
}


DWPAL_Ret dwpal_hostap_cmd_send(void *context, const char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply /*OUT*/, size_t *replyLen /*IN/OUT*/)
{
	int       i;
	DWPAL_Ret ret = DWPAL_SUCCESS;
	char      cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

	if ( (context == NULL) || (cmdHeader == NULL) || (reply == NULL) || (replyLen == NULL) )
	{
		console_printf("%s; input params error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if ( ((DWPAL_Context *)context)->interface.hostapd.wpaCtrlPtr == NULL )
	{
		console_printf("%s; input params error (wpaCtrlPtr = NULL) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	//console_printf("%s Entry; VAPName= '%s', cmdHeader= '%s', replyLen= %d\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName, cmdHeader, *replyLen);

	snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s", cmdHeader);

	if (fieldsToCmdParse != NULL)
	{
		i = 0;
		while (fieldsToCmdParse[i].parsingType != DWPAL_NUM_OF_PARSING_TYPES)
		{
			if (fieldsToCmdParse[i].field != NULL)
			{
				switch (fieldsToCmdParse[i].parsingType)
				{
					case DWPAL_STR_PARAM:
						//console_printf("%s; fieldsToCmdParse[%d].field= '%s'\n", __FUNCTION__, i, (char *)fieldsToCmdParse[i].field);
						if (fieldsToCmdParse[i].preParamString == NULL)
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %s", cmd, (char *)fieldsToCmdParse[i].field);
						}
						else
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %s%s", cmd, fieldsToCmdParse[i].preParamString, (char *)fieldsToCmdParse[i].field);
						}
						break;

					case DWPAL_STR_ARRAY_PARAM:
						break;

					case DWPAL_INT_PARAM:
						//console_printf("%s; fieldsToCmdParse[%d].field= %d\n", __FUNCTION__, i, *((int *)fieldsToCmdParse[i].field));
						if (fieldsToCmdParse[i].preParamString == NULL)
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %d", cmd, *((int *)fieldsToCmdParse[i].field));
						}
						else
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %s%d", cmd, fieldsToCmdParse[i].preParamString, *((int *)fieldsToCmdParse[i].field));
						}
						break;

					case DWPAL_UNSIGNED_INT_PARAM:
						//console_printf("%s; fieldsToCmdParse[%d].field= %u\n", __FUNCTION__, i, *((unsigned int *)fieldsToCmdParse[i].field));
						if (fieldsToCmdParse[i].preParamString == NULL)
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %u", cmd, *((unsigned int *)fieldsToCmdParse[i].field));
						}
						else
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %s%u", cmd, fieldsToCmdParse[i].preParamString, *((unsigned int *)fieldsToCmdParse[i].field));
						}
						break;

					case DWPAL_CHAR_PARAM:
					case DWPAL_UNSIGNED_CHAR_PARAM:
					case DWPAL_SHORT_INT_PARAM:
					case DWPAL_LONG_LONG_INT_PARAM:
					case DWPAL_UNSIGNED_LONG_LONG_INT_PARAM:
					case DWPAL_INT_ARRAY_PARAM:
					case DWPAL_INT_HEX_ARRAY_PARAM:
						break;

					case DWPAL_BOOL_PARAM:
						break;

					default:
						console_printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToCmdParse[i].parsingType);
						ret = DWPAL_FAILURE;
						break;
				}
			}

			i++;
		}
	}

	//console_printf("%s; cmd= '%s'\n", __FUNCTION__, cmd);

	memset((void *)reply, '\0', *replyLen);  /* Clear the output buffer */

	ret = wpa_ctrl_request(((DWPAL_Context *)context)->interface.hostapd.wpaCtrlPtr,
	                       cmd,
						   strnlen_s(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH),
						   reply,
						   replyLen /* should be msg-len in/out param */,
						   ((DWPAL_Context *)context)->interface.hostapd.wpaCtrlEventCallback);
	if (ret < 0)
	{
		console_printf("%s; wpa_ctrl_request() returned error (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		return DWPAL_FAILURE;
	}
	reply[*replyLen] = '\0';  /* we need it to clear the "junk" at the end of the string */

	//console_printf("%s; replyLen= %d\nreply=\n%s\n", __FUNCTION__, *replyLen, reply);

	return ret;
}


DWPAL_Ret dwpal_hostap_event_get(void *context, char *msg /*OUT*/, size_t *msgLen /*IN/OUT*/, char *opCode /*OUT*/)
{
	int     ret;
	char    *localOpCode;
	rsize_t dmaxLen;
	char    *localMsg, *p2str;
	struct  wpa_ctrl *wpaCtrlPtr = NULL;

	if ( (context == NULL) || (msg == NULL) || (msgLen == NULL) || (opCode == NULL) )
	{
		console_printf("%s; context/msg/msgLen/opCode is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	wpaCtrlPtr = (((DWPAL_Context *)context)->interface.hostapd.wpaCtrlEventCallback == NULL)?
	             /* one-way*/ ((DWPAL_Context *)context)->interface.hostapd.listenerWpaCtrlPtr :
	             /* two-way*/ ((DWPAL_Context *)context)->interface.hostapd.wpaCtrlPtr;

	if (wpaCtrlPtr == NULL)
	{
		console_printf("%s; wpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* In order to get ALL pending messages (and return the last one), all of the below should be inside "while" loop */
	ret = wpa_ctrl_pending(wpaCtrlPtr);
	switch (ret)
	{
		case -1:  /* error */
			console_printf("%s; wpa_ctrl_pending() returned ERROR ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
			break;

		case 0:  /* there are no pending messages */
			return DWPAL_NO_PENDING_MESSAGES;
			break;

		case 1:  /* there are pending messages */
			break;

		default:
			console_printf("%s; wpa_ctrl_pending() returned unknown (%d) value ==> Abort!\n", __FUNCTION__, ret);
			return DWPAL_FAILURE;
			break;
	}

	/* There are pending messages */
	if (wpa_ctrl_recv(wpaCtrlPtr, msg, msgLen) == 0)
	{
		//console_printf("%s; msgLen= %d\nmsg= '%s'\n", __FUNCTION__, *msgLen, msg);
		msg[*msgLen] = '\0';
		if (*msgLen <= 5)
		{
			console_printf("%s; '%s' is NOT a report ==> Abort!\n", __FUNCTION__, msg);
			return DWPAL_FAILURE;
		}
		else
		{
			dmaxLen = (rsize_t)*msgLen;
			localMsg = strdup(msg);
			localOpCode = strtok_s(localMsg, &dmaxLen, ">", &p2str);
			localOpCode = strtok_s(NULL, &dmaxLen, " ", &p2str);
			strcpy_s(opCode, strnlen_s(localOpCode, DWPAL_OPCODE_STRING_LENGTH) + 1, localOpCode);
			free((void *)localMsg);
		}
	}
	else
	{
		console_printf("%s; wpa_ctrl_recv() returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_event_fd_get(void *context, int *fd /*OUT*/)
{
	if ( (context == NULL) || (fd == NULL) )
	{
		//console_printf("%s; context and/or fd is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*fd = ((DWPAL_Context *)context)->interface.hostapd.fd;

	if (*fd == (-1))
	{
		//console_printf("%s; fd value is (-1) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_is_interface_exist(void *context, bool *isExist /*OUT*/)
{
	char wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];

	if ( (context == NULL) || (isExist == NULL) )
	{
		console_printf("%s; context and/or isExist is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	//console_printf("%s; VAPName= '%s'\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName);

	*isExist = false;

	if (((DWPAL_Context *)context)->interface.hostapd.VAPName[0] == '\0')
	{
		console_printf("%s; invalid radio name ('%s') ==> Abort!\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName);
		return DWPAL_FAILURE;
	}

	/* check if '/var/run/hostapd/wlanX' or '/var/run/wpa_supplicant/wlanX' exists */
	snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/hostapd/", ((DWPAL_Context *)context)->interface.hostapd.VAPName);
	if (access(wpaCtrlName, F_OK) == 0)
	{
		//console_printf("%s; Radio '%s' exists - AP Mode\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName);
		*isExist = true;
	}
	else
	{
		snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/wpa_supplicant/", ((DWPAL_Context *)context)->interface.hostapd.VAPName);
		if (access(wpaCtrlName, F_OK) == 0)
		{
			//console_printf("%s; Radio '%s' exists - STA Mode\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName);
			*isExist = true;
		}
		else
		{
			console_printf("%s; radio interface '%s' not present\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.VAPName);
		}
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_interface_detach(void **context /*IN/OUT*/)
{
	DWPAL_Context *localContext;
	int           ret;

	if (context == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);
	if (localContext == NULL)
	{
		console_printf("%s; localContext is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlPtr == NULL)
	{
		console_printf("%s; wpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		if ((ret = wpa_ctrl_detach(localContext->interface.hostapd.wpaCtrlPtr)) != 0)
		{
			console_printf("%s; wpa_ctrl_detach (VAPName= '%s') returned ERROR (ret= %d) ==> Abort!\n",
			            __FUNCTION__, localContext->interface.hostapd.VAPName, ret);
			return DWPAL_FAILURE;
		}
	}
	else
	{  /* non-valid wpaCtrlEventCallback states that this is a one-way connection */
		/* Close & reset 'listenerWpaCtrlPtr' */
		if (localContext->interface.hostapd.listenerWpaCtrlPtr == NULL)
		{
			console_printf("%s; listenerWpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
		}

		if ((ret = wpa_ctrl_detach(localContext->interface.hostapd.listenerWpaCtrlPtr)) != 0)
		{
			console_printf("%s; wpa_ctrl_detach of listener (VAPName= '%s') returned ERROR (ret= %d) ==> Abort!\n",
			            __FUNCTION__, localContext->interface.hostapd.VAPName, ret);
			return DWPAL_FAILURE;
		}
		wpa_ctrl_close(localContext->interface.hostapd.listenerWpaCtrlPtr);
	}

	/* Close 'wpaCtrlPtr' */
	wpa_ctrl_close(localContext->interface.hostapd.wpaCtrlPtr);

	localContext->interface.hostapd.wpaCtrlPtr = NULL;
	localContext->interface.hostapd.listenerWpaCtrlPtr = NULL;
	localContext->interface.hostapd.operationMode[0] = '\0';
	localContext->interface.hostapd.wpaCtrlName[0] = '\0';

	localContext->interface.hostapd.fd = -1;

	free(*context);
	*context = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_interface_attach(void **context /*OUT*/, const char *VAPName, DWPAL_wpaCtrlEventCallback wpaCtrlEventCallback)
{
	DWPAL_Context *localContext;
	char          wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];

	//console_printf("%s; VAPName= '%s', wpaCtrlEventCallback= 0x%x\n", __FUNCTION__, VAPName, (unsigned int)wpaCtrlEventCallback);

	if (context == NULL)
	{
		console_printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (VAPName == NULL)
	{
		console_printf("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Temporary due to two-way socket hostapd bug */
	if (wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		console_printf("%s; currently, two-way connection (for '%s') is NOT supported - use one-way connection ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_FAILURE;
	}

	*context = malloc(sizeof(DWPAL_Context));
	if (*context == NULL)
	{
		console_printf("%s; malloc for context failed ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);

	strncpy((void *)(localContext->interface.hostapd.VAPName), VAPName, DWPAL_VAP_NAME_STRING_LENGTH);
	localContext->interface.hostapd.VAPName[sizeof(localContext->interface.hostapd.VAPName) - 1] = '\0';
	localContext->interface.hostapd.fd = -1;
	localContext->interface.hostapd.wpaCtrlPtr = NULL;
	localContext->interface.hostapd.wpaCtrlEventCallback = wpaCtrlEventCallback;

	/* check if '/var/run/hostapd/wlanX' or '/var/run/wpa_supplicant/wlanX' exists, and update context's database */
	snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/hostapd/", localContext->interface.hostapd.VAPName);
	if (access(wpaCtrlName, F_OK) == 0)
	{
		//console_printf("%s; Radio '%s' exists - AP Mode\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
		strcpy_s(localContext->interface.hostapd.operationMode, 3, "AP");
		strcpy_s(localContext->interface.hostapd.wpaCtrlName, strnlen_s(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH) + 1, wpaCtrlName);
	}
	else
	{
		snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/wpa_supplicant/", localContext->interface.hostapd.VAPName);
		if (access(wpaCtrlName, F_OK) == 0)
		{
			//console_printf("%s; Radio '%s' exists - STA Mode\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
			strcpy_s(localContext->interface.hostapd.operationMode, 4, "STA");
			strcpy_s(localContext->interface.hostapd.wpaCtrlName, strnlen_s(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH) + 1, wpaCtrlName);
		}
		else
		{
			localContext->interface.hostapd.operationMode[0] = '\0';
			localContext->interface.hostapd.wpaCtrlName[0] = '\0';

			//console_printf("%s; radio interface '%s' not present ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
			return DWPAL_FAILURE;
		}
	}

	localContext->interface.hostapd.wpaCtrlPtr = wpa_ctrl_open(localContext->interface.hostapd.wpaCtrlName);
	if (localContext->interface.hostapd.wpaCtrlPtr == NULL)
	{
		console_printf("%s; wpaCtrlPtr (for interface '%s') is NULL! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		console_printf("%s; set up two-way connection for '%s'\n", __FUNCTION__, localContext->interface.hostapd.VAPName);

		/* Reset listenerWpaCtrlPtr which used only in one-way connection */
		localContext->interface.hostapd.listenerWpaCtrlPtr = NULL;

		if (wpa_ctrl_attach(localContext->interface.hostapd.wpaCtrlPtr) != 0)
		{
			console_printf("%s; wpa_ctrl_attach for '%s' failed! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
			return DWPAL_FAILURE;
		}

		localContext->interface.hostapd.fd = wpa_ctrl_get_fd(localContext->interface.hostapd.wpaCtrlPtr);
	}
	else
	{  /* wpaCtrlEventCallback is NULL ==> turn on the event listener in an additional socket */
		localContext->interface.hostapd.listenerWpaCtrlPtr = wpa_ctrl_open(localContext->interface.hostapd.wpaCtrlName);
		console_printf("%s; set up one-way connection for '%s'\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
		if (localContext->interface.hostapd.listenerWpaCtrlPtr == NULL)
		{
			console_printf("%s; listenerWpaCtrlPtr (for interface '%s') is NULL! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
			return DWPAL_FAILURE;
		}

		if (wpa_ctrl_attach(localContext->interface.hostapd.listenerWpaCtrlPtr) != 0)
		{
			console_printf("%s; wpa_ctrl_attach for '%s' listener failed! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.VAPName);
			return DWPAL_FAILURE;
		}

		localContext->interface.hostapd.fd = wpa_ctrl_get_fd(localContext->interface.hostapd.listenerWpaCtrlPtr);
	}

	return DWPAL_SUCCESS;
}
