/*  ***************************************************************************** 
 *         File Name    : dwpal.c                             	                *
 *         Description  : D-WPAL control interface 		                        * 
 *                                                                              *
 *  *****************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <linux/types.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>  /* for "struct nl_msg" */
#include <libnl3/netlink/genl/ctrl.h>
#include <linux/netlink.h>

#include <net/if.h>

#include "safe_str_lib.h"
#include "dwpal.h"
#include "wpa_ctrl.h"

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
			char   radioName[DWPAL_RADIO_NAME_STRING_LENGTH]; /* "wlan0", "wlan1", ..., "wlan5" */
			char   operationMode[DWPAL_OPERATING_MODE_STRING_LENGTH];
			char   wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];
			struct wpa_ctrl *wpaCtrlPtr;
			struct wpa_ctrl *listenerWpaCtrlPtr;   /*needed when closing it*/
			int    fd;
			DWPAL_wpaCtrlEventCallback wpaCtrlEventCallback;  /* callback function for hostapd received events while command is being sent; can be NULL */
		} hostapd;

		struct
		{
			struct nl_sock *nlSocket;
			int    fd, nl80211_id;
			DWPAL_nlEventCallback nlEventCallback;
		} driver;
	} interface;
} DWPAL_Context;


static int nlInternalEventCallback(struct nl_msg *msg, void *arg)
{
	DWPAL_Context *localContext = (DWPAL_Context *)(arg);

	printf("%s Entry\n", __FUNCTION__);

	if (localContext->interface.driver.nlEventCallback != NULL)
	{
		struct nlattr *attr;
		struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
		unsigned char *data;
		int len;

		attr = nla_find(genlmsg_attrdata(gnlh, 0),
		                genlmsg_attrlen(gnlh, 0),
		                NL80211_ATTR_VENDOR_DATA);

		if (!attr)
		{
			printf("%s; vendor data attribute missing ==> Abort!\n", __FUNCTION__);
			return (int)DWPAL_FAILURE;
		}

		data = (unsigned char *) nla_data(attr);
		len = nla_len(attr);

		/* Call the NL callback function */
		localContext->interface.driver.nlEventCallback((size_t)len, data);
	}

	return (int)DWPAL_SUCCESS;
}

static bool mandatoryFieldValueGet(char *buf, size_t *bufLen, char **p2str, int numOfArrayArgs, char fieldValue[] /*OUT*/)
{
	char *param;
	char *localBuf = NULL;

	if (buf != NULL)
	{
		localBuf = strdup(buf);
		if (localBuf == NULL)
		{
			printf("%s; localBuf is NULL ==> Abort!\n", __FUNCTION__);
			return false;
		}
	}

	param = strtok_s(localBuf, bufLen, " ", p2str);
	if (param == NULL)
	{
		printf("%s; param is NULL ==> Abort!\n", __FUNCTION__);
		if (localBuf != NULL)
			free((void *)localBuf);
		return false;
	}

	if (fieldValue != NULL)
	{
		if (strnlen_s(param, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) > (size_t)(numOfArrayArgs - 1))
		{
			if (localBuf != NULL)
			{
				free((void *)localBuf);
			}

			printf("%s; param ('%s') length (%d) is higher than allocated size (%d) ==> Abort!\n", __FUNCTION__, param, strnlen_s(param, numOfArrayArgs), numOfArrayArgs-1);
			return false;
		}

		strcpy_s(fieldValue, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH, param);
	}

	if (localBuf != NULL)
	{
		free((void *)localBuf);
	}

	return true;
}


static bool arrayValuesGet(char *stringOfValues, size_t numOfArrayArgs, ParamParsingType paramParsingType, size_t *numOfValidArgs /*OUT*/, void *array /*OUT*/)
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

		if (idx < (int)numOfArrayArgs)
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

	if (idx >= (int)numOfArrayArgs)
	{
		printf("%s; actual number of arguments (%d) is bigger/equal then numOfArrayArgs (%d) ==> Abort!\n", __FUNCTION__, idx, numOfArrayArgs);
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
		printf("%s; malloc failed ==> Abort!\n", __FUNCTION__);
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
		printf("%s; localStringToSearch is NULL ==> Abort!\n", __FUNCTION__);
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
		//printf("%s; stringStart= 0x%x, strlen of ('%s')= %d ==> restOfStringStart= 0x%x\n",
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
				//printf("%s; localEndFieldName= '%s' FOUND! (i= %d)\n", __FUNCTION__, localEndFieldName, i);
				if (isFirstEndOfString)
				{
					isFirstEndOfString = false;
					closerStringEnd = stringEnd;
				}
				else
				{  /* Make sure that closerStringEnd will point to the closest field ahead */
					closerStringEnd = (stringEnd < closerStringEnd)? stringEnd : closerStringEnd;
				}

				//printf("%s; [0] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);
			}

			i++;
		}

		//printf("%s; [1] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);

		if (closerStringEnd == NULL)
		{  /* Meaning, this is the last parameter in the string */
			//printf("%s; closerStringEnd is NULL; restOfStringStart= '%s'\n", __FUNCTION__, restOfStringStart);
			closerStringEnd = restOfStringStart + strnlen_s(restOfStringStart, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH) + 1 /* for '\0' */;
			//printf("%s; [2] closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);

			//printf("%s; String end did NOT found ==> set closerStringEnd to the end of buf; closerStringEnd= 0x%x\n", __FUNCTION__, (unsigned int)closerStringEnd);
		}

		//printf("%s; stringToSearch= '%s'; restOfStringStart= '%s'; buf= '%s'\n", __FUNCTION__, stringToSearch, restOfStringStart, buf);
		//printf("%s; restOfStringStart= 0x%x, closerStringEnd= 0x%x ==> characters to copy = %d\n", __FUNCTION__, (unsigned int)restOfStringStart, (unsigned int)closerStringEnd, closerStringEnd - restOfStringStart);

		/* set 'numOfCharacters' with the number of characters to copy (including the blank or end-of-string at the end) */
		numOfCharacters = closerStringEnd - restOfStringStart;
		if (numOfCharacters <= 0)
		{
			printf("%s; numOfCharacters= %d ==> Abort!\n", __FUNCTION__, numOfCharacters);
			free((void *)localBuf);
			free((void *)localStringToSearch);
			return false;
		}

		/* Copy the characters of the value, and set the last one to '\0' */
		strncpy_s(tempStringOfValues, sizeof(tempStringOfValues), restOfStringStart, numOfCharacters);
		tempStringOfValues[numOfCharacters - 1] = '\0';
		//printf("%s; stringToSearch= '%s'; tempStringOfValues= '%s'\n", __FUNCTION__, stringToSearch, tempStringOfValues);

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

		//printf("%s; stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, stringToSearch, stringOfValues);

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

	//printf("%s; stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, stringToSearch, stringOfValues);

	free((void *)localBuf);
	free((void *)localStringToSearch);

	//printf("%s; ret= %d, stringToSearch= '%s'; stringOfValues= '%s'\n", __FUNCTION__, ret, stringToSearch, stringOfValues);

	return ret;
}


static bool isColumnOfFields(char *msg, char *endFieldName[])
{
	int i = 0, numOfFieldsInLine = 0;

	//printf("%s; line= '%s'\n", __FUNCTION__, msg);

	if (endFieldName == NULL)
	{
		printf("%s; endFieldName= 'NULL' ==> not a column!\n", __FUNCTION__);
		return false;
	}

	while (strncmp(endFieldName[i], "\n", 1))
	{  /* run over all field names in the string */
		if (strstr(msg, endFieldName[i]) != NULL)
		{
			numOfFieldsInLine++;

			if (numOfFieldsInLine > 1)
			{
				//printf("%s; Not a column (numOfFieldsInLine= %d) ==> return!\n", __FUNCTION__, numOfFieldsInLine);
				return false;
			}

			/* Move ahead inside the line, to avoid double recognition (like "PacketsSent" and "DiscardPacketsSent") */
			msg += strnlen_s(endFieldName[i], HOSTAPD_TO_DWPAL_MSG_LENGTH);
		}

		i++;
	}

	//printf("%s; It is a column (numOfFieldsInLine= %d)\n", __FUNCTION__, numOfFieldsInLine);

	return true;
}


static bool columnOfParamsToRawConvert(char *msg, size_t msgLen, char *endFieldName[])
{
	char    *localMsg = strdup(msg), *lineMsg, *p2str;
	rsize_t dmaxLen = (rsize_t)msgLen;
	bool    isColumn = true;
	int     i;

	if (localMsg == NULL)
	{
		printf("%s; strdup error ==> Abort!\n", __FUNCTION__);
		return false;
	}

	lineMsg = strtok_s(localMsg, (rsize_t *)&dmaxLen, "\n", &p2str);

	while (lineMsg != NULL)
	{
		isColumn = isColumnOfFields(lineMsg, endFieldName);

		if (isColumn == false)
		{
			//printf("%s; Not a column ==> break!\n", __FUNCTION__);
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


/* Command APIs */


/* Low Level APIs */

DWPAL_Ret dwpal_driver_nl_cmd_send(void *context, char *ifname, enum nl80211_commands nl80211Command, CmdIdType cmdIdType, enum ltq_nl80211_vendor_subcmds subCommand, unsigned char *vendorData, size_t vendorDataSize)
{
	int i, res;
	struct nl_msg *msg;
	DWPAL_Context *localContext = (DWPAL_Context *)(context);
	signed long long devidx = 0;

	printf("%s Entry!\n", __FUNCTION__);

	if (nl80211Command != 0x67 /*NL80211_CMD_VENDOR*/)
	{
		printf("%s; non supported command (0x%x); currently we support ONLY NL80211_CMD_VENDOR (0x67) ==> Abort!\n", __FUNCTION__, (unsigned int)nl80211Command);
		return DWPAL_FAILURE;
	}

	for (i=0; i < (int)vendorDataSize; i++)
	{
		printf("%s; vendorData[%d]= 0x%x\n", __FUNCTION__, i, vendorData[i]);
	}

	if (localContext == NULL)
	{
		printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.driver.nlSocket == NULL)
	{
		printf("%s; nlSocket is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		printf("%s; nlmsg_alloc returned NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	printf("%s; nl80211_id= %d\n", __FUNCTION__, localContext->interface.driver.nl80211_id);

	/* calling genlmsg_put() is a must! without it, the callback won't be called! */
	genlmsg_put(msg, 0, 0, localContext->interface.driver.nl80211_id, 0,0, nl80211Command /* NL80211_CMD_VENDOR=0x67*/, 0);

	//iw dev wlan0 vendor recv 0xAC9A96 0x69 0x00 ==> send "0xAC9A96 0x69 0x00"
	devidx = if_nametoindex(ifname);
	if (devidx < 0)
	{
		printf("%s; devidx ERROR (devidx= %lld) ==> Abort!\n", __FUNCTION__, devidx);
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
			printf("%s; cmdIdType ERROR (cmdIdType= %d) ==> Abort!\n", __FUNCTION__, cmdIdType);
			nlmsg_free(msg);
			return DWPAL_FAILURE;
	}

	if (res < 0)
	{
		printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	res = nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_LTQ /*0xAC9A96*/);
	//NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, OUI_LTQ /*0xAC9A96*/);
	if (res < 0)
	{
		printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	res = nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subCommand);
	//NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, subCommand);
	if (res < 0)
	{
		printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	if ( (vendorDataSize > 0) && (vendorData != NULL) )
	{
		//NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, count, buf);
		res = nla_put(msg, NL80211_ATTR_VENDOR_DATA, (int)vendorDataSize, (void *)vendorData);
		if (res < 0)
		{
			printf("%s; building message failed ==> Abort!\n", __FUNCTION__);
			nlmsg_free(msg);
			return DWPAL_FAILURE;
		}
	}

	/* will trigger nlEventCallback() function call */
	res = nl_send_auto(localContext->interface.driver.nlSocket, msg);  // can use nl_send_auto_complete(localContext->interface.driver.nlSocket, msg) instead
	if (res < 0)
	{
		printf("%s; nl_send_auto returned ERROR (res= %d) ==> Abort!\n", __FUNCTION__, res);
		nlmsg_free(msg);
		return DWPAL_FAILURE;
	}

	nlmsg_free(msg);

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_msg_get(void *context, DWPAL_nlEventCallback nlEventCallback)
{
	int res;
	DWPAL_Context *localContext = (DWPAL_Context *)(context);

	printf("%s Entry\n", __FUNCTION__);

	if (localContext == NULL)
	{
		printf("%s; localContext is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.driver.nlSocket == NULL)
	{
		printf("%s; nlSocket is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* nlEventCallback can be NULL; in that case, the D-WPAL client's callback function won't be called */
	localContext->interface.driver.nlEventCallback = nlEventCallback;

	/* Connect the nl socket to its message callback function */
	if (nl_socket_modify_cb(localContext->interface.driver.nlSocket,
	                        NL_CB_VALID, NL_CB_CUSTOM,
	                        nlInternalEventCallback,
	                        context /* will be used in "arg" param of nlInternalEventCallback */) < 0)
	{
		printf("%s; nl_socket_modify_cb ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* will trigger nlEventCallback() function call */
	res = nl_recvmsgs_default(localContext->interface.driver.nlSocket);
	if (res < 0)
	{
		printf("%s; nl_recvmsgs_default returned ERROR (res= %d) ==> Abort!\n", __FUNCTION__, res);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_fd_get(void *context, int *fd /*OUT*/)
{
	if ( (context == NULL) || (fd == NULL) )
	{
		//printf("%s; context and/or fd is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*fd = ((DWPAL_Context *)context)->interface.driver.fd;

	if (*fd == (-1))
	{
		printf("%s; fd value is (-1) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_detach(void *context)
{
	DWPAL_Context *localContext = (DWPAL_Context *)(context);

	if (localContext == NULL)
	{
		printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.driver.nlSocket == NULL)
	{
		printf("%s; nlSocket is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Note: calling nl_close() is NOT needed - The socket is closed automatically when using nl_socket_free() */
	nl_socket_free(localContext->interface.driver.nlSocket);

	localContext->interface.driver.nlSocket = NULL;
	localContext->interface.driver.fd = -1;
	localContext->interface.driver.nlEventCallback = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_driver_nl_attach(void **context /*OUT*/)
{
	int res = 1;
	DWPAL_Context *localContext;
#if 0
	int family, bcast_group;
#endif

	printf("%s Entry\n", __FUNCTION__);

	if (context == NULL)
	{
		printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*context = malloc(sizeof(DWPAL_Context));
	if (*context == NULL)
	{
		printf("%s; malloc for context failed ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);

	localContext->interface.driver.nlSocket = nl_socket_alloc();
	if (localContext->interface.driver.nlSocket == NULL)
	{
		printf("%s; nl_socket_alloc ERROR ==> Abort!\n", __FUNCTION__);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	/* Connect to generic netlink socket on kernel side */
	if (genl_connect(localContext->interface.driver.nlSocket) < 0)
	{
		printf("%s; genl_connect ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(localContext->interface.driver.nlSocket);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	if (nl_socket_set_buffer_size(localContext->interface.driver.nlSocket, 8192, 8192) != 0)
	{
		printf("%s; nl_socket_set_buffer_size ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(localContext->interface.driver.nlSocket);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}

	//nl_socket_disable_seq_check(localContext->interface.driver.nlSocket);
	//nl_socket_disable_auto_ack(localContext->interface.driver.nlSocket);
	//nl_socket_enable_msg_peek(localContext->interface.driver.nlSocket);

	localContext->interface.driver.fd = nl_socket_get_fd(localContext->interface.driver.nlSocket);
	if (localContext->interface.driver.fd == -1)
	{
		printf("%s; nl_socket_get_fd ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(localContext->interface.driver.nlSocket);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}
	printf("%s; driver.fd= %d\n", __FUNCTION__, localContext->interface.driver.fd);

	/* manipulate options for the socket referred to by the file descriptor - driver.fd */
	setsockopt(localContext->interface.driver.fd, SOL_NETLINK /*option level argument*/,
		   NETLINK_EXT_ACK, &res, sizeof(res));

	/* Ask kernel to resolve nl80211_id name to nl80211_id id */
	localContext->interface.driver.nl80211_id = genl_ctrl_resolve(localContext->interface.driver.nlSocket, "nl80211");
	if (localContext->interface.driver.nl80211_id < 0)
	{
		printf("%s; genl_ctrl_resolve ERROR ==> Abort!\n", __FUNCTION__);
		nl_socket_free(localContext->interface.driver.nlSocket);
		free(*context);
		*context = NULL;
		return DWPAL_FAILURE;
	}
	printf("%s; driver.nl80211_id= %d\n", __FUNCTION__, localContext->interface.driver.nl80211_id);

#if 0
	/* Ask kernel to resolve family name to family id */
	family = genl_ctrl_resolve(localContext->interface.driver.nlSocket, MTLK_GENL_FAMILY_NAME);

	bcast_group = family + (NETLINK_FAPI_GROUP - 1);
	if (nl_socket_add_membership(localContext->interface.driver.nlSocket, bcast_group) < 0)
	{
		printf("%s; nl_socket_add_membership ERROR ==> Abort!\n", __FUNCTION__);
	}
#endif

	printf("%s; driver.nlSocket= 0x%x, driver.nlEventCallback= 0x%x, driver.nl80211_id= %d\n",
	       __FUNCTION__, (unsigned int)localContext->interface.driver.nlSocket, (unsigned int)localContext->interface.driver.nlEventCallback, localContext->interface.driver.nl80211_id);

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
		printf("%s; input params error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if ( (msgStringLen = strnlen_s(msg, HOSTAPD_TO_DWPAL_MSG_LENGTH)) > msgLen )
	{
		printf("%s; msgStringLen (%d) is bigger than msgLen (%d) ==> Abort!\n", __FUNCTION__, msgStringLen, msgLen);
		return DWPAL_FAILURE;
	}

	//printf("%s; [0] msgLen= %d\n", __FUNCTION__, msgLen);

	/* Convert msgLen to string length format (without the '\0' character) */
	msgLen = dmaxLen = msgStringLen;
	//printf("%s; [1] msgLen= %d\n", __FUNCTION__, msgLen);

	//printf("%s; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);

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
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].numOfArrayArgs == 0) )
					{
						printf("%s; Error; DWPAL_STR_PARAM must have positive value for numOfArrayArgs ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += sizeof(char) * fieldsToParse[i].numOfArrayArgs;  /* array of characters (string) */
					//printf("%s; DWPAL_STR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_STR_ARRAY_PARAM:
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].numOfArrayArgs == 0) )
					{
						printf("%s; Error; DWPAL_STR_ARRAY_PARAM must have positive value for numOfArrayArgs ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += fieldsToParse[i].numOfArrayArgs;
					//printf("%s; DWPAL_STR_ARRAY_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_CHAR_PARAM:
					sizeOfStruct += sizeof(char);
					//printf("%s; DWPAL_CHAR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_UNSIGNED_CHAR_PARAM:
					sizeOfStruct += sizeof(unsigned char);
					//printf("%s; DWPAL_UNSIGNED_CHAR_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_SHORT_INT_PARAM:
					sizeOfStruct += sizeof(short int);
					//printf("%s; DWPAL_SHORT_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_INT_PARAM:
				case DWPAL_INT_HEX_PARAM:
					sizeOfStruct += sizeof(int);
					//printf("%s; DWPAL_INT_PARAM/DWPAL_INT_HEX_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_LONG_LONG_INT_PARAM:
					sizeOfStruct += sizeof(long long int);
					//printf("%s; DWPAL_LONG_LONG_INT_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_INT_ARRAY_PARAM:
				case DWPAL_INT_HEX_ARRAY_PARAM:
					if ( (fieldsToParse[i].field != NULL) && (fieldsToParse[i].numOfArrayArgs == 0) )
					{
						printf("%s; Error; DWPAL_INT_ARRAY_PARAM/DWPAL_INT_HEX_ARRAY_PARAM must have positive value for numOfArrayArgs ==> Abort!\n", __FUNCTION__);
						return DWPAL_FAILURE;
					}

					sizeOfStruct += sizeof(int) * fieldsToParse[i].numOfArrayArgs;
					//printf("%s; DWPAL_INT_ARRAY_PARAM/DWPAL_INT_HEX_ARRAY_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				case DWPAL_BOOL_PARAM:
					sizeOfStruct += sizeof(bool);
					//printf("%s; DWPAL_BOOL_PARAM; sizeOfStruct= %d\n", __FUNCTION__, sizeOfStruct);
					break;

				default:
					printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].parsingType);
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
			printf("%s; malloc endFieldName failed ==> Abort!\n", __FUNCTION__);
			ret = DWPAL_FAILURE;
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
					printf("%s; malloc endFieldName[%d] failed ==> Abort!\n", __FUNCTION__, i);
					ret = DWPAL_FAILURE;
					break;
				}

				memset((void *)endFieldName[idx], '\0', DWPAL_FIELD_NAME_LENGTH);  /* Clear the field name */
				strcpy_s(endFieldName[idx], DWPAL_FIELD_NAME_LENGTH, fieldsToParse[i].stringToSearch);

				idx++;
			}

			i++;
		}

		if (ret == DWPAL_SUCCESS)
		{
			endFieldName[idx] =  (char *)malloc(DWPAL_FIELD_NAME_LENGTH);
			if (endFieldName[idx] == NULL)
			{
				printf("%s; malloc endFieldName[%d] failed ==> Abort!\n", __FUNCTION__, idx);
				ret = DWPAL_FAILURE;
			}
			else
			{
				memset((void *)endFieldName[idx], '\0', DWPAL_FIELD_NAME_LENGTH);  /* Clear the field name */
				strcpy_s(endFieldName[idx], DWPAL_FIELD_NAME_LENGTH, "\n");
				isEndFieldNameAllocated = true;
			}
		}
	}

	//printf("%s; [0] msg= '%s'\n", __FUNCTION__, msg);

	/* In case of a column, convert it to one raw */
	if ( (ret == DWPAL_SUCCESS) && (isEndFieldNameAllocated) )
	{
		if (columnOfParamsToRawConvert(msg, msgLen , endFieldName) == false)
		{
			printf("%s; columnOfParamsToRawConvert error ==> Abort!\n", __FUNCTION__);
			ret = DWPAL_FAILURE;
		}
	}

	//printf("%s; [1] msg= '%s'\n", __FUNCTION__, msg);

	/* Perform the actual parsing */
	//printf("%s; [1.1] dmaxLen= %d, p2str= '%s'\n", __FUNCTION__, dmaxLen, p2str);
	lineMsg = strtok_s(msg, &dmaxLen, "\n", &p2str);
	localMsg = lineMsg;
	lineIdx = 0;

	while ( (lineMsg != NULL) && (ret == DWPAL_SUCCESS) )
	{
		void *field;

		//printf("%s; [2] lineMsg= '%s'\n", __FUNCTION__, lineMsg);

		i = 0;
		while ( (fieldsToParse[i].parsingType != DWPAL_NUM_OF_PARSING_TYPES) && (ret == DWPAL_SUCCESS) )
		{
			/* set the output parameter - move it to the next array index (needed when parsing many lines) */
			field = (void *)((unsigned int)fieldsToParse[i].field + lineIdx * sizeOfStruct);
			//printf("%s; lineIdx= %d, sizeOfStruct= %d, field= 0x%x\n", __FUNCTION__, lineIdx, sizeOfStruct, (unsigned int)field);

			switch (fieldsToParse[i].parsingType)
			{
				case DWPAL_STR_PARAM:
					if (fieldsToParse[i].stringToSearch == NULL)
					{  /* Handle mandatory parameters WITHOUT any string-prefix */
						dmaxLenMandatory = (rsize_t)strnlen_s(lineMsg, HOSTAPD_TO_DWPAL_MSG_LENGTH);
						if (mandatoryFieldValueGet(localMsg /*will be NULL starting from 2nd param*/,
						                           &dmaxLenMandatory,
						                           &p2strMandatory,
						                           (int)fieldsToParse[i].numOfArrayArgs,
						                           (char *)field /*OUT*/) == false)
						{
							printf("%s; mandatory is NULL ==> Abort!\n", __FUNCTION__);
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
							ret = DWPAL_FAILURE;
							break;
						}

						memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
						if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
						{
							if (fieldsToParse[i].numOfValidArgs != NULL)
							{
								(*(fieldsToParse[i].numOfValidArgs))++;
							}

							if ((strnlen_s(stringOfValues, DWPAL_TO_HOSTAPD_MSG_LENGTH) + 1) > fieldsToParse[i].numOfArrayArgs)
							{
								printf("%s; string length (%d) is bigger the allocated string size (%d)\n", __FUNCTION__, strnlen_s(stringOfValues, DWPAL_TO_HOSTAPD_MSG_LENGTH) + 1, fieldsToParse[i].numOfArrayArgs);
								ret = DWPAL_FAILURE;  /* longer string then allocated ==> Abort! */
							}
							else
							{
								strcpy_s((char *)field, HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH, stringOfValues);
							}
						}
						else
						{
							isMissingParam = true;
						}
					}
					break;

				case DWPAL_STR_ARRAY_PARAM:
				/* handle multiple repetitive field, for example:
				   "... non_pref_chan=81:200:1:5 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 ..." or
				   "... non_pref_chan=81:200:1:5 81:100:2:9 81:200:1:7 81:100:2:5 ..." */
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

					memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
					if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
					{
						if (arrayValuesGet(stringOfValues, fieldsToParse[i].numOfArrayArgs, DWPAL_STR_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, (char *)field) == false)
						{
							printf("%s; arrayValuesGet ERROR\n", __FUNCTION__);
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
					break;

				case DWPAL_CHAR_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_UNSIGNED_CHAR_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_SHORT_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_LONG_LONG_INT_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_INT_ARRAY_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

					memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
					if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
					{
						//printf("%s; [1] fieldsToParse[%d].numOfValidArgs= %d, stringOfValues= '%s'\n", __FUNCTION__, i, *(fieldsToParse[i].numOfValidArgs), stringOfValues);
						if (arrayValuesGet(stringOfValues, fieldsToParse[i].numOfArrayArgs, DWPAL_INT_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, field) == false)
						{
							printf("%s; arrayValuesGet ERROR\n", __FUNCTION__);
						}
						//printf("%s; [2] fieldsToParse[%d].numOfValidArgs= %d\n", __FUNCTION__, i, *(fieldsToParse[i].numOfValidArgs));
					}
					else
					{
						isMissingParam = true;
					}
					break;

				case DWPAL_INT_HEX_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				case DWPAL_INT_HEX_ARRAY_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

					memset(stringOfValues, 0, sizeof(stringOfValues));  /* reset the string value array */
					if (fieldValuesGet(lineMsg, msgLen, fieldsToParse[i].stringToSearch, endFieldName, stringOfValues) == true)
					{
						if (arrayValuesGet(stringOfValues, fieldsToParse[i].numOfArrayArgs, DWPAL_INT_HEX_ARRAY_PARAM, fieldsToParse[i].numOfValidArgs, field) == false)
						{
							printf("%s; arrayValuesGet (stringToSearch= '%s') ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].stringToSearch);
							ret = DWPAL_FAILURE; /* array of string detected, but getting its arguments failed ==> Abort! */
						}
					}
					else
					{
						isMissingParam = true;
					}
					break;

				case DWPAL_BOOL_PARAM:
					if (isEndFieldNameAllocated == false)
					{
						ret = DWPAL_FAILURE;
						break;
					}

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
					break;

				default:
					printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToParse[i].parsingType);
					ret = DWPAL_FAILURE;
					break;
			}

			i++;
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


DWPAL_Ret dwpal_hostap_cmd_send(void *context, const char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply, size_t *replyLen)
{
	int       i;
	DWPAL_Ret ret = DWPAL_SUCCESS;
	char      cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

	if ( (context == NULL) || (cmdHeader == NULL) || (reply == NULL) || (replyLen == NULL) )
	{
		printf("%s; input params error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	//printf("%s Entry; radioName= '%s', cmdHeader= '%s', replyLen= %d\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName, cmdHeader, *replyLen);

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
						//printf("%s; fieldsToCmdParse[%d].field= '%s'\n", __FUNCTION__, i, (char *)fieldsToCmdParse[i].field);
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
						//printf("%s; fieldsToCmdParse[%d].field= %d\n", __FUNCTION__, i, *((int *)fieldsToCmdParse[i].field));
						if (fieldsToCmdParse[i].preParamString == NULL)
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %d", cmd, *((int *)fieldsToCmdParse[i].field));
						}
						else
						{
							snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "%s %s%d", cmd, fieldsToCmdParse[i].preParamString, *((int *)fieldsToCmdParse[i].field));
						}
						break;

					case DWPAL_CHAR_PARAM:
					case DWPAL_UNSIGNED_CHAR_PARAM:
					case DWPAL_SHORT_INT_PARAM:
					case DWPAL_LONG_LONG_INT_PARAM:
					case DWPAL_INT_ARRAY_PARAM:
					case DWPAL_INT_HEX_ARRAY_PARAM:
						break;

					case DWPAL_BOOL_PARAM:
						break;

					default:
						printf("%s; (parsingType= %d) ERROR ==> Abort!\n", __FUNCTION__, fieldsToCmdParse[i].parsingType);
						ret = DWPAL_FAILURE;
						break;
				}
			}

			i++;
		}
	}

	//printf("%s; cmd= '%s'\n", __FUNCTION__, cmd);

	ret = wpa_ctrl_request(((DWPAL_Context *)context)->interface.hostapd.wpaCtrlPtr,
	                       cmd,
						   strnlen_s(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH),
						   reply,
						   replyLen /* should be msg-len in/out param */,
						   ((DWPAL_Context *)context)->interface.hostapd.wpaCtrlEventCallback);
	if (ret < 0)
	{
		printf("%s; wpa_ctrl_request() returned error (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		return DWPAL_FAILURE;
	}
	reply[*replyLen] = '\0';  /* we need it to clear the "junk" at the end of the string */  //reply[*replyLen - 1] = '\0';  /* we need it to clear the "junk" at the end of the string */

	//printf("%s; replyLen= %d\nreply=\n%s\n", __FUNCTION__, *replyLen, reply);

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
		printf("%s; context/msg/msgLen/opCode is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	wpaCtrlPtr = (((DWPAL_Context *)context)->interface.hostapd.wpaCtrlEventCallback == NULL)?
	             /* one-way*/ ((DWPAL_Context *)context)->interface.hostapd.listenerWpaCtrlPtr :
	             /* two-way*/ ((DWPAL_Context *)context)->interface.hostapd.wpaCtrlPtr;

	if (wpaCtrlPtr == NULL)
	{
		printf("%s; wpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* In order to get ALL pending messages (and return the last one), all of the below should be inside "while" loop */
	ret = wpa_ctrl_pending(wpaCtrlPtr);
	switch (ret)
	{
		case -1:  /* error */
			printf("%s; wpa_ctrl_pending() returned ERROR ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
			break;

		case 0:  /* there are no pending messages */
			return DWPAL_NO_PENDING_MESSAGES;
			break;

		case 1:  /* there are pending messages */
			break;

		default:
			printf("%s; wpa_ctrl_pending() returned unknown (%d) value ==> Abort!\n", __FUNCTION__, ret);
			return DWPAL_FAILURE;
			break;
	}

	/* There are pending messages */
	if (wpa_ctrl_recv(wpaCtrlPtr, msg, msgLen) == 0)
	{
		//printf("%s; msgLen= %d\nmsg= '%s'\n", __FUNCTION__, *msgLen, msg);
		msg[*msgLen] = '\0';
		if (*msgLen <= 5)
		{
			printf("%s; '%s' is NOT a report ==> Abort!\n", __FUNCTION__, msg);
			return DWPAL_FAILURE;
		}
		else
		{
			dmaxLen = (rsize_t)*msgLen;
			localMsg = strdup(msg);
			localOpCode = strtok_s(localMsg, &dmaxLen, ">", &p2str);
			localOpCode = strtok_s(NULL, &dmaxLen, " ", &p2str);
			strcpy_s(opCode, DWPAL_OPCODE_STRING_LENGTH, localOpCode);
			free((void *)localMsg);
		}
	}
	else
	{
		printf("%s; wpa_ctrl_recv() returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_event_fd_get(void *context, int *fd /*OUT*/)
{
	if ( (context == NULL) || (fd == NULL) )
	{
		//printf("%s; context and/or fd is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	*fd = ((DWPAL_Context *)context)->interface.hostapd.fd;

	if (*fd == (-1))
	{
		//printf("%s; fd value is (-1) ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_is_interface_exist(void *context, bool *isExist /*OUT*/)
{
	char wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];

	if ( (context == NULL) || (isExist == NULL) )
	{
		printf("%s; context and/or isExist is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	//printf("%s; radioName= '%s'\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName);

	*isExist = false;

	if (((DWPAL_Context *)context)->interface.hostapd.radioName[0] == '\0')
	{
		printf("%s; invalid radio name ('%s') ==> Abort!\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName);
		return DWPAL_FAILURE;
	}

	/* check if '/var/run/hostapd/wlanX' or '/var/run/wpa_supplicant/wlanX' exists */
	snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/hostapd/", ((DWPAL_Context *)context)->interface.hostapd.radioName);
	if (access(wpaCtrlName, F_OK) == 0)
	{
		//printf("%s; Radio '%s' exists - AP Mode\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName);
		*isExist = true;
	}
	else
	{
		snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/wpa_supplicant/", ((DWPAL_Context *)context)->interface.hostapd.radioName);
		if (access(wpaCtrlName, F_OK) == 0)
		{
			//printf("%s; Radio '%s' exists - STA Mode\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName);
			*isExist = true;
		}
		else
		{
			printf("%s; radio interface '%s' not present\n", __FUNCTION__, ((DWPAL_Context *)context)->interface.hostapd.radioName);
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
		printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);
	if (localContext == NULL)
	{
		printf("%s; localContext is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlPtr == NULL)
	{
		printf("%s; wpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		if ((ret = wpa_ctrl_detach(localContext->interface.hostapd.wpaCtrlPtr)) != 0)
		{
			printf("%s; wpa_ctrl_detach (radioName= '%s') returned ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName, ret);
			return DWPAL_FAILURE;
		}
	}
	else
	{  /* non-valid wpaCtrlEventCallback states that this is a one-way connection */
		/* Close & reset 'listenerWpaCtrlPtr' */
		if (localContext->interface.hostapd.listenerWpaCtrlPtr == NULL)
		{
			printf("%s; listenerWpaCtrlPtr= NULL ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
		}

		if ((ret = wpa_ctrl_detach(localContext->interface.hostapd.listenerWpaCtrlPtr)) != 0)
		{
			printf("%s; wpa_ctrl_detach of listener (radioName= '%s') returned ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName, ret);
			return DWPAL_FAILURE;
		}
		wpa_ctrl_close(localContext->interface.hostapd.listenerWpaCtrlPtr);
	}

	/* Close 'wpaCtrlPtr' */
	wpa_ctrl_close(localContext->interface.hostapd.wpaCtrlPtr);

	localContext->interface.hostapd.wpaCtrlPtr = NULL;
	localContext->interface.hostapd.listenerWpaCtrlPtr = NULL;
	strcpy_s(localContext->interface.hostapd.operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "\0");
	strcpy_s(localContext->interface.hostapd.wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "\0");

	localContext->interface.hostapd.fd = -1;

	free(*context);
	*context = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_hostap_interface_attach(void **context /*OUT*/, const char *radioName, DWPAL_wpaCtrlEventCallback wpaCtrlEventCallback)
{
	DWPAL_Context *localContext;
	char          wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];

	//printf("%s; radioName= '%s', wpaCtrlEventCallback= 0x%x\n", __FUNCTION__, radioName, (unsigned int)wpaCtrlEventCallback);

	if (context == NULL)
	{
		printf("%s; context is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (radioName == NULL)
	{
		printf("%s; radioName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Temporary due to two-way socket hostapd bug */
	if (wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		printf("%s; currently, two-way connection (for '%s') is NOT supported - use one-way connection ==> Abort!\n", __FUNCTION__, radioName);
		return DWPAL_FAILURE;
	}

	*context = malloc(sizeof(DWPAL_Context));
	if (*context == NULL)
	{
		printf("%s; malloc for context failed ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	localContext = (DWPAL_Context *)(*context);

	strncpy((void *)(localContext->interface.hostapd.radioName), radioName, DWPAL_RADIO_NAME_STRING_LENGTH);
	localContext->interface.hostapd.radioName[sizeof(localContext->interface.hostapd.radioName) - 1] = '\0';
	localContext->interface.hostapd.fd = -1;
	localContext->interface.hostapd.wpaCtrlPtr = NULL;
	localContext->interface.hostapd.wpaCtrlEventCallback = wpaCtrlEventCallback;

	/* check if '/var/run/hostapd/wlanX' or '/var/run/wpa_supplicant/wlanX' exists, and update context's database */
	snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/hostapd/", localContext->interface.hostapd.radioName);
	if (access(wpaCtrlName, F_OK) == 0)
	{
		//printf("%s; Radio '%s' exists - AP Mode\n", __FUNCTION__, localContext->interface.hostapd.radioName);
		strcpy_s(localContext->interface.hostapd.operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "AP");
		strcpy_s(localContext->interface.hostapd.wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, wpaCtrlName);
	}
	else
	{
		snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/wpa_supplicant/", localContext->interface.hostapd.radioName);
		if (access(wpaCtrlName, F_OK) == 0)
		{
			//printf("%s; Radio '%s' exists - STA Mode\n", __FUNCTION__, localContext->interface.hostapd.radioName);
			strcpy_s(localContext->interface.hostapd.operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "STA");
			strcpy_s(localContext->interface.hostapd.wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, wpaCtrlName);
		}
		else
		{
			strcpy_s(localContext->interface.hostapd.operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "\0");
			strcpy_s(localContext->interface.hostapd.wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "\0");

			//printf("%s; radio interface '%s' not present ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName);
			return DWPAL_FAILURE;
		}
	}

	localContext->interface.hostapd.wpaCtrlPtr = wpa_ctrl_open(localContext->interface.hostapd.wpaCtrlName);
	if (localContext->interface.hostapd.wpaCtrlPtr == NULL)
	{
		printf("%s; wpaCtrlPtr (for interface '%s') is NULL! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName);
		return DWPAL_FAILURE;
	}

	if (localContext->interface.hostapd.wpaCtrlEventCallback != NULL)
	{  /* Valid wpaCtrlEventCallback states that this is a two-way connection (for both command and events) */
		printf("%s; set up two-way connection for '%s'\n", __FUNCTION__, localContext->interface.hostapd.radioName);

		/* Reset listenerWpaCtrlPtr which used only in one-way connection */
		localContext->interface.hostapd.listenerWpaCtrlPtr = NULL;

		if (wpa_ctrl_attach(localContext->interface.hostapd.wpaCtrlPtr) != 0)
		{
			printf("%s; wpa_ctrl_attach for '%s' failed! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName);
			return DWPAL_FAILURE;
		}

		localContext->interface.hostapd.fd = wpa_ctrl_get_fd(localContext->interface.hostapd.wpaCtrlPtr);
	}
	else
	{  /* wpaCtrlEventCallback is NULL ==> turn on the event listener in an additional socket */
		localContext->interface.hostapd.listenerWpaCtrlPtr = wpa_ctrl_open(localContext->interface.hostapd.wpaCtrlName);
		printf("%s; set up one-way connection for '%s'\n", __FUNCTION__, localContext->interface.hostapd.radioName);
		if (localContext->interface.hostapd.listenerWpaCtrlPtr == NULL)
		{
			printf("%s; listenerWpaCtrlPtr (for interface '%s') is NULL! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName);
			return DWPAL_FAILURE;
		}

		if (wpa_ctrl_attach(localContext->interface.hostapd.listenerWpaCtrlPtr) != 0)
		{
			printf("%s; wpa_ctrl_attach for '%s' listener failed! ==> Abort!\n", __FUNCTION__, localContext->interface.hostapd.radioName);
			return DWPAL_FAILURE;
		}

		localContext->interface.hostapd.fd = wpa_ctrl_get_fd(localContext->interface.hostapd.listenerWpaCtrlPtr);
	}

	return DWPAL_SUCCESS;
}
