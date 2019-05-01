/*  *****************************************************************************
 *        File Name    : dwpal_band_steering_app.c                              *
 *        Description  : app - control band steering via hostapd(with dwpal.so) *
 *                                                                              *
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#if defined YOCTO
#include <errno.h>
#endif

#if defined YOCTO
#include <puma_safe_libc.h>
#else
#include "safe_str_lib.h"
#endif
#include "dwpal.h"
#include "dwpal_ext.h"
#include <pthread.h>

#define MAC_STRING_LEN 17
#define IFNAME_STRING_LENGTH 16
#define FIELD_VALUE_LENGTH 128
#define RSIZE_MAX_STR 256


typedef struct
{
	char BSSID[18];
} DWPAL_get_vap_measurements;

typedef struct
{
	int  Channel;
	int  Freq;
} DWPAL_radio_info_get;

typedef struct
{
	int     SignalStrength;
    char    OperatingStandard[32];
} DWPAL_get_sta_measurements;

typedef struct
{
	char VAPName[16];
	char MACAddress[18];
} DWPAL_sta_disconnected_event;

typedef struct
{
	char VAPName[16];
	char MACAddress[18];
	int  signalStrength;
	int  supportedRates[32];
	int  HT_CAP;
	int  HT_MCS[32];
	int  VHT_CAP;
	int  VHT_MCS[32];
	bool btm_supported;
	bool nr_enabled;
	char non_pref_chan[32][HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH];
	bool cell_capa;
	char assoc_req[HOSTAPD_TO_DWPAL_VALUE_STRING_LENGTH];
} DWPAL_sta_connected_event;

typedef struct
{
	char MACAddress[18];
    char target_bssid[18];
	int  status_code;
} DWPAL_bss_tm_resp_event;

typedef struct StationsInfo
{
	char MACAddress[18];
	char connectedTo[6];
	int  connectionTime;
	int is_5G_supported;
	char ifnameCheckIfConnected[6];
	int  numOfTicks;
	bool btm_supported;
	bool isBandSteeringPossible;
	struct StationsInfo *nextStation;
} StationsInfo_t;

typedef struct
{
	char *interfaceType;
	char *name;
    char operationMode[DWPAL_OPERATING_MODE_STRING_LENGTH];
	char *serviceName;
	int  fd;
    char supportedFrequencyBands[16];
	char ifnameToSteerTo[6];
    char BSSID[24];
	char BSSID_ToSteerTo[24];
} DwpalRadioInterface;

static StationsInfo_t *firstStationInfo = NULL;

static int numOfActiveApInterfaces = 0;
static DwpalRadioInterface radioInterface[] = { { "hostap", "wlan0", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" },
                                                { "hostap", "wlan1", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" },
                                                { "hostap", "wlan2", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" },
                                                { "hostap", "wlan3", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" },
                                                { "hostap", "wlan4", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" },
                                                { "hostap", "wlan5", "NONE", "ONE_WAY", -1, "\0", "\0", "\0", "\0" } };

static pthread_mutex_t bandsteering_mutex;


/* Service APIs */

static DWPAL_Ret dwpal_wlan_sta_allow(char *VAPName, char *MACAddress)
{
    char   		*reply = (char *)malloc((size_t)(32 * sizeof(char)));
	size_t  	replyLen = 32 * sizeof(char) - 1;
	DWPAL_Ret 	ret;
    char     	cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

    snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "STA_ALLOW %s", MACAddress);
    ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

    if (ret == DWPAL_FAILURE)
    {
        console_printf("%s; STA_ALLOW command send error\n", __FUNCTION__);
    }
    else
    {
        console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

        if (replyLen >= 2 && !strncmp(reply, "OK", strnlen_s("OK", RSIZE_MAX_STR)))
        {
            console_printf("%s; Sucessfully Allowed %s on %s\n", __FUNCTION__, MACAddress, VAPName);
        }
        else
        {
            console_printf("%s; STA_ALLOW %s command returned FAIL!\n", __FUNCTION__, MACAddress);
            free((void *)reply);
            return DWPAL_FAILURE;
        }
    }

    free((void *)reply);

    return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_bss_transition_management_req(char *VAPName, char *MACAddress, int pref, int disassoc_imminent, int disassoc_timer, char *neighbor)
{
    char   		*reply = (char *)malloc((size_t)(32 * sizeof(char)));
	size_t  	replyLen = 32 * sizeof(char) - 1;
	DWPAL_Ret 	ret;
    char     	cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

	snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "BSS_TM_REQ %s pref=%d disassoc_imminent=%d disassoc_timer=%d neighbor=%s",
												 MACAddress, pref, disassoc_imminent, disassoc_timer, neighbor);
    ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

    if (ret == DWPAL_FAILURE)
    {
        console_printf("%s; BSS_TM_REQ command send error\n", __FUNCTION__);
    }
    else
    {
        console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

		if (replyLen >= 4 && !strncmp(reply, "FAIL", strnlen_s("FAIL", RSIZE_MAX_STR)))
        {
			console_printf("%s; BSS_TM_REQ %s command returned FAIL!\n", __FUNCTION__, MACAddress);
			free((void *)reply);
            return DWPAL_FAILURE;
		}
        else
        {
            console_printf("%s; Sucessfully made a tm request for %s\n", __FUNCTION__, MACAddress);
        }
    }

	free((void *)reply);

    return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_sta_deny(char *VAPName, char *MACAddress)
{
    char      	*reply = (char *)malloc((size_t)(32 * sizeof(char)));
	size_t  	replyLen = 32 * sizeof(char) - 1;
	DWPAL_Ret 	ret;
    char   		cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

    snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "DENY_MAC %s 0", MACAddress);
    ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

    if (ret == DWPAL_FAILURE)
    {
        console_printf("%s; DENY_MAC command send error\n", __FUNCTION__);
    }
    else
    {
        console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

        if (replyLen >= 2 && !strncmp(reply, "OK", strnlen_s("OK", RSIZE_MAX_STR)))
        {
            console_printf("%s; Sucessfully Blacklisted %s on %s\n", __FUNCTION__, MACAddress, VAPName);
        }
        else
        {
            console_printf("%s; DENY_MAC %s command returned FAIL!\n", __FUNCTION__, MACAddress);
            free((void *)reply);
            return DWPAL_FAILURE;
        }
    }

    free((void *)reply);

    return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_sta_measurement_get(char *VAPName, char *MACAddress, FieldsToParse fieldsToParse[])
{
	char     	*reply = (char *)malloc((size_t)(HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char)));
	size_t    	replyLen = HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char) - 1;
	DWPAL_Ret 	ret;
	char       	cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

	if (reply == NULL)
	{
		console_printf("%s; malloc error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	memset((void *)reply, '\0', HOSTAPD_TO_DWPAL_MSG_LENGTH);  /* Clear the output buffer */
	snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "GET_STA_MEASUREMENTS %s %s", VAPName, MACAddress);
	ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

	if (ret == DWPAL_FAILURE)
	{
		console_printf("%s; GET_STA_MEASUREMENTS command send error\n", __FUNCTION__);
	}
	else
	{
		console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

		if ((ret = dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse)) == DWPAL_FAILURE)
		{
			console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
			free((void *)reply);
			return DWPAL_FAILURE;
		}

		console_printf("%s; dwpal_string_to_struct_parse() ret= %d\n", __FUNCTION__, ret);
	}

	free((void *)reply);

	return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_vap_measurements_get(char *VAPName, FieldsToParse fieldsToParse[])
{
	char     	*reply = (char *)malloc((size_t)(HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char)));
	size_t    	replyLen = HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char) - 1;
	DWPAL_Ret 	ret;
	char       	cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

	if (reply == NULL)
	{
		console_printf("%s; malloc error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	memset((void *)reply, '\0', HOSTAPD_TO_DWPAL_MSG_LENGTH);  /* Clear the output buffer */
	snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "GET_VAP_MEASUREMENTS %s", VAPName);
	ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

	if (ret == DWPAL_FAILURE)
	{
		console_printf("%s; GET_VAP_MEASUREMENTS command send error\n", __FUNCTION__);
	}
	else
	{
		console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

		if ((ret = dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse)) == DWPAL_FAILURE)
		{
			console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
			free((void *)reply);
			return DWPAL_FAILURE;
		}

		console_printf("%s; dwpal_string_to_struct_parse() ret= %d\n", __FUNCTION__, ret);
	}

	free((void *)reply);

	return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_radio_info_get(char *VAPName, FieldsToParse fieldsToParse[])
{
	char    	*reply = (char *)malloc((size_t)(HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char)));
	size_t    	replyLen = HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char) - 1;
	DWPAL_Ret 	ret;

	if (reply == NULL)
	{
		console_printf("%s; malloc error ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	memset((void *)reply, '\0', HOSTAPD_TO_DWPAL_MSG_LENGTH);  /* Clear the output buffer */
	ret = dwpal_ext_hostap_cmd_send(VAPName, "GET_RADIO_INFO", NULL, reply, &replyLen);

	if (ret == DWPAL_FAILURE)
	{
		console_printf("%s; GET_RADIO_INFO command send error\n", __FUNCTION__);
	}
	else
	{
		console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

		if ((ret = dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse)) == DWPAL_FAILURE)
		{
			console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
			free((void *)reply);
			return DWPAL_FAILURE;
		}

		console_printf("%s; dwpal_string_to_struct_parse() ret= %d\n", __FUNCTION__, ret);
	}

	free((void *)reply);

	return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_wlan_sta_disassociate(char *VAPName, char *MACAddress)
{
    char                        *reply = (char *)malloc((size_t)(32 * sizeof(char)));
	size_t                      replyLen = 32 * sizeof(char) - 1;
	DWPAL_Ret                   ret;
    char                        cmd[DWPAL_TO_HOSTAPD_MSG_LENGTH];

    snprintf(cmd, DWPAL_TO_HOSTAPD_MSG_LENGTH, "DISASSOCIATE %s %s", VAPName, MACAddress);
    ret = dwpal_ext_hostap_cmd_send(VAPName, cmd, NULL, reply, &replyLen);

    if (ret == DWPAL_FAILURE)
    {
        console_printf("%s; DISASSOCIATE command send error\n", __FUNCTION__);
    }
    else
    {
        console_printf("%s; replyLen= %d\nresponse=\n%s\n", __FUNCTION__, replyLen, reply);

        if (replyLen >= 2 && !strncmp(reply, "OK", strnlen_s("OK", RSIZE_MAX_STR)))
        {
            console_printf("%s; Sucessfully disconnected %s\n", __FUNCTION__, MACAddress);
        }
        else
        {
            console_printf("%s; DISASSOCIATE %s command returned FAIL!\n", __FUNCTION__, MACAddress);
            free((void *)reply);
            return DWPAL_FAILURE;
        }
    }

    free((void *)reply);

    return DWPAL_SUCCESS;
}


static void stationsInfoListPrint(void)
{
	bool           isPrintEmptyLine = false;
	StationsInfo_t *stationsInfo = firstStationInfo;

	if (stationsInfo != NULL)
	{
		isPrintEmptyLine = true;
	}

	while (stationsInfo != NULL)
	{
		console_printf("=====================================================\n");
		console_printf("MACAddress= '%s'\n", stationsInfo->MACAddress);
		console_printf("-----------------------------------------------------\n");
		console_printf("connectedTo= '%s'\n", stationsInfo->connectedTo);
		console_printf("connectionTime= %d\n", stationsInfo->connectionTime);
		console_printf("is_5G_supported= %d\n", stationsInfo->is_5G_supported);
		console_printf("ifnameCheckIfConnected= '%s'\n", stationsInfo->ifnameCheckIfConnected);
		console_printf("numOfTicks= %d\n", stationsInfo->numOfTicks);
		console_printf("btm_supported= %d\n", stationsInfo->btm_supported);
		console_printf("isBandSteeringPossible= %d\n", stationsInfo->isBandSteeringPossible);
		console_printf("nextStation= 0x%x\n", (unsigned int)stationsInfo->nextStation);
		console_printf("-----------------------------------------------------\n");

		stationsInfo = stationsInfo->nextStation;
	}

	if (isPrintEmptyLine)
	{
		console_printf("\n");
	}
}


static void stationsInfoListClear(void)
{
	StationsInfo_t *stationsInfo = firstStationInfo, *stationsInfoToClear = NULL;

	console_printf("%s Entry\n", __FUNCTION__);

	while (stationsInfo != NULL)
	{
		stationsInfoToClear = stationsInfo;
		stationsInfo = stationsInfo->nextStation;

		console_printf("%s; Clear Record; MACAddress= '%s'; stationsInfoToClear= 0x%x\n", __FUNCTION__, stationsInfo->MACAddress, (unsigned int)stationsInfoToClear);
		free((void *)stationsInfoToClear);
	}

	firstStationInfo = NULL;
}


static StationsInfo_t *stationsInfoGet(char *MACAddress)
{
	StationsInfo_t *stationsInfo = firstStationInfo;

	while (stationsInfo != NULL)
	{
		if (!strncmp(stationsInfo->MACAddress, MACAddress, MAC_STRING_LEN))
		{
			console_printf("%s; MACAddress ('%s') record found!\n", __FUNCTION__, stationsInfo->MACAddress);
			return stationsInfo;
		}

		stationsInfo = stationsInfo->nextStation;
	}

	return stationsInfo;
}


static int interfaceIndexGet(const char *ifname)
{
	int     i = 0;
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
		if (!strncmp(radioInterface[i].name, ifname, strnlen_s(ifname, RSIZE_MAX_STR)))
		{
			return i;
		}
	}
	return -1;
}


static int interfaceChannelNumberGet(char* ifname)
{
    DWPAL_radio_info_get radio_info;
	size_t               numOfValidArgs[1];
	DWPAL_Ret 	         ret;
    int                  ifindex = interfaceIndexGet(ifname);
	FieldsToParse        fieldsToParse[] =
	{
		{ (void *)&radio_info.Channel,     &numOfValidArgs[0],    DWPAL_INT_PARAM, "Channel=",   0 },

		/* Must be at the end */
		{ NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
	};

    if (ifindex < 0)
        return DWPAL_FAILURE;

    ret = dwpal_wlan_radio_info_get(radioInterface[ifindex].name, fieldsToParse);

    if (ret == DWPAL_FAILURE)
    {
        console_printf("%s; GET_RADIO_INFO command send error\n", __FUNCTION__);
        return DWPAL_FAILURE;
    }
    else
    {
        return radio_info.Channel;
    }
}


static int dwpalRadioInterfaceEventCallback(char *ifname, char *opCode, char *msg, size_t msgLen)
{
	time_t         rawtime;
	int            idx;
	StationsInfo_t *stationsInfo = NULL;

	console_printf("%s; ifname= '%s', opCode= '%s'\n", __FUNCTION__, ifname, opCode);

	console_printf("\n%s; database BEFORE event process:\n", __FUNCTION__);
	stationsInfoListPrint();

	if (!strncmp(opCode, "AP-STA-CONNECTED", strnlen_s("AP-STA-CONNECTED", RSIZE_MAX_STR)))
	{
		/* <3>AP-STA-CONNECTED wlan0 24:77:03:80:5d:90 SignalStrength=-49 SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108 HT_CAP=107E HT_MCS=FF FF FF 00 00 00 00 00 00 00 C2 01 01 00 00 00
		   VHT_CAP=03807122 VHT_MCS=FFFA 0000 FFFA 0000 btm_supported=1 nr_enabled=0 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:9 cell_capa=1 */
		/* non_pref_chan = <opClass : channelNumber : pref : reason> */
        DWPAL_sta_connected_event sta_connected_event;
        DWPAL_Ret                 ret;
        size_t                    numOfValidArgs[14];
        FieldsToParse             fieldsToParse[] =
        {
            { NULL /*opCode*/,                             &numOfValidArgs[0],  DWPAL_STR_PARAM,           NULL,              0                                          },
            { (void *)&sta_connected_event.VAPName,        &numOfValidArgs[1],  DWPAL_STR_PARAM,           NULL,              sizeof(sta_connected_event.VAPName)        },
            { (void *)&sta_connected_event.MACAddress,     &numOfValidArgs[2],  DWPAL_STR_PARAM,           NULL,              sizeof(sta_connected_event.MACAddress)     },
            { (void *)&sta_connected_event.signalStrength, &numOfValidArgs[3],  DWPAL_INT_PARAM,           "SignalStrength=", 0                                          },
            { (void *)&sta_connected_event.supportedRates, &numOfValidArgs[4],  DWPAL_INT_ARRAY_PARAM,     "SupportedRates=", sizeof(sta_connected_event.supportedRates) },
            { (void *)&sta_connected_event.HT_CAP,         &numOfValidArgs[5],  DWPAL_INT_HEX_PARAM,       "HT_CAP=",         0                                          },
            { (void *)&sta_connected_event.HT_MCS,         &numOfValidArgs[6],  DWPAL_INT_HEX_ARRAY_PARAM, "HT_MCS=",         sizeof(sta_connected_event.HT_MCS)         },
            { (void *)&sta_connected_event.VHT_CAP,        &numOfValidArgs[7],  DWPAL_INT_HEX_PARAM,       "VHT_CAP=",        0                                          },
            { (void *)&sta_connected_event.VHT_MCS,        &numOfValidArgs[8],  DWPAL_INT_HEX_ARRAY_PARAM, "VHT_MCS=",        sizeof(sta_connected_event.VHT_MCS)        },
            { (void *)&sta_connected_event.btm_supported,  &numOfValidArgs[9],  DWPAL_BOOL_PARAM,          "btm_supported=",  0                                          },
            { (void *)&sta_connected_event.nr_enabled,     &numOfValidArgs[10], DWPAL_BOOL_PARAM,          "nr_enabled=",     0                                          },
            { (void *)&sta_connected_event.non_pref_chan,  &numOfValidArgs[11], DWPAL_STR_ARRAY_PARAM,     "non_pref_chan=",  sizeof(sta_connected_event.non_pref_chan)  },
            { (void *)&sta_connected_event.cell_capa,      &numOfValidArgs[12], DWPAL_BOOL_PARAM,          "cell_capa=",      0                                          },
            { (void *)&sta_connected_event.assoc_req,      &numOfValidArgs[13], DWPAL_STR_PARAM,           "assoc_req=",      sizeof(sta_connected_event.assoc_req)      },

            /* Must be at the end */
            { NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
        };

        if ((ret = dwpal_string_to_struct_parse(msg, msgLen, fieldsToParse)) == DWPAL_FAILURE)
        {
            console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
            return DWPAL_FAILURE;
        }

        stationsInfo = stationsInfoGet(sta_connected_event.MACAddress);

        if (stationsInfo == NULL)
		{
			console_printf("%s; AP-STA-CONNECTED; 'MACAddress' (%s) not found! ==> create new record\n", __FUNCTION__, sta_connected_event.MACAddress);

			/* add a record at the beginning of the list */
			stationsInfo = (StationsInfo_t *)malloc(sizeof(StationsInfo_t));
			if (stationsInfo == NULL)
			{
				console_printf("%s; ERROR! malloc returned NULL ==> Abort!\n", __FUNCTION__);
			}
			else
			{
				stationsInfo->nextStation = firstStationInfo;
				firstStationInfo = stationsInfo;

				/* New object - update */
				idx = interfaceIndexGet(ifname);
				if (idx == (-1))
				{
					console_printf("%s; ERROR: interfaceIdx of '%s' is %d ==> Abort!\n", __FUNCTION__, ifname, idx);
					return DWPAL_FAILURE;
				}

				console_printf("%s; MACAddress= '%s'\n", __FUNCTION__, sta_connected_event.MACAddress);
				STRNCPY_S(stationsInfo->MACAddress, 18, sta_connected_event.MACAddress, 17);
				stationsInfo->MACAddress[17] = '\0';

				if (!strncmp(radioInterface[idx].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR)))
				{
					console_printf("%s; set 'is_5G_supported' to 'true'\n", __FUNCTION__);
					stationsInfo->is_5G_supported = 1;  /*true*/
				}
				else
				{
					console_printf("%s; set 'is_5G_supported' to 'NON_VALID'\n", __FUNCTION__);
					stationsInfo->is_5G_supported = 2;  /* NON_VALID */
				}

				STRCPY_S(stationsInfo->ifnameCheckIfConnected, FIELD_VALUE_LENGTH, "NONE");
				stationsInfo->numOfTicks = 0;
				stationsInfo->isBandSteeringPossible = true;
			}
		}
        else
        {
            console_printf("%s; MACAddress ('%s') found! ==> check if it is already set as connected\n", __FUNCTION__, sta_connected_event.MACAddress);
			console_printf("%s; 'connectedTo' is '%s'\n", __FUNCTION__, stationsInfo->connectedTo);
			if ( (stationsInfo->connectedTo != NULL) && (!strncmp(stationsInfo->connectedTo, ifname, 5)) )
			{
				console_printf("%s; Station ('%s') already connected to the same i/f ('%s') ==> do NOT update the data-base\n", __FUNCTION__, stationsInfo->MACAddress, ifname);
				return DWPAL_SUCCESS;
			}

			/* Getting here means that the station record is present, and it is NOT connected to the same ifname (or no connected at all) */
			if ( strncmp(stationsInfo->connectedTo, "NONE", strnlen_s("NONE", RSIZE_MAX_STR)) && strncmp(stationsInfo->connectedTo, "", 1) )
			{  /* The station record is present, and it is NOT connected to the same ifname */

				if (!strncmp(stationsInfo->connectedTo, stationsInfo->ifnameCheckIfConnected, strnlen_s(stationsInfo->ifnameCheckIfConnected, RSIZE_MAX_STR)))
				{
					console_printf("%s; Steering occurred! (MACAddress= '%s' to '%s')\n", __FUNCTION__, stationsInfo->MACAddress, stationsInfo->connectedTo);
					stationsInfo->numOfTicks = 0;
					STRCPY_S(stationsInfo->ifnameCheckIfConnected, FIELD_VALUE_LENGTH, "NONE");
					stationsInfoListPrint();
				}

				/* Due to the fact that some stations does NOT send DISASSOCIATE when disconnecting, STA-DISCONNECTED won't arrive; the below will force it! */
				if (dwpal_wlan_sta_disassociate(stationsInfo->connectedTo, stationsInfo->MACAddress) == DWPAL_FAILURE)
					console_printf("fapi_wlan_sta_disassociate ERROR\n");
			}

			/* update 'is_5G_supported' ONLY if it is NOT 'true' */
			if (stationsInfo->is_5G_supported != 1 /*true*/)
			{
				idx = interfaceIndexGet(ifname);
				if (idx == (-1))
				{
					console_printf("%s; ERROR: interfaceIdx of '%s' is %d ==> Abort!\n", __FUNCTION__, ifname, idx);
					return DWPAL_FAILURE;
				}

				if (!strncmp(radioInterface[idx].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR)))
				{  /* it means that the band we are connected to is 5 GHz */
					console_printf("%s; connected to 5 GHz ==> update 'is_5G_supported' to 'true'\n", __FUNCTION__);
					stationsInfo->is_5G_supported = 1;  /*true*/
				}
			}
        }

        if (stationsInfo != NULL)
        {
			console_printf("%s; Update 'connectedTo' ('%s')\n", __FUNCTION__, (char *)ifname);
			STRNCPY_S(stationsInfo->connectedTo, 6, (char *)ifname, 5);
			stationsInfo->connectedTo[5] = '\0';

			time(&rawtime);
			console_printf("%s; rawtime= %ld\n", __FUNCTION__, rawtime);

			stationsInfo->connectionTime = rawtime;

			stationsInfo->btm_supported = false;
            console_printf("%s; btm_supported is '%d'\n", __FUNCTION__, sta_connected_event.btm_supported);

            if (sta_connected_event.btm_supported == 1)
            {
                console_printf("%s; btm_supported is 'true' ==> update 'btm_supported' and 'is_5G_supported' to 'true'\n", __FUNCTION__);
                stationsInfo->btm_supported = true;
                stationsInfo->is_5G_supported = 1;  /*true*/
            }
		}
    }
    else if (!strncmp(opCode, "AP-STA-DISCONNECTED", strnlen_s("AP-STA-DISCONNECTED", RSIZE_MAX_STR)))
	{
		/* <3>AP-STA-DISCONNECTED wlan0 14:d6:4d:ac:36:70 */
        DWPAL_sta_disconnected_event sta_disconnected_event;
        DWPAL_Ret                    ret;
        size_t                       numOfValidArgs[3];
        FieldsToParse                fieldsToParse[] =
        {
            { NULL /*opCode*/,                            &numOfValidArgs[0], DWPAL_STR_PARAM, NULL, 0                                         },
            { (void *)&sta_disconnected_event.VAPName,    &numOfValidArgs[1], DWPAL_STR_PARAM, NULL, sizeof(sta_disconnected_event.VAPName)    },
            { (void *)&sta_disconnected_event.MACAddress, &numOfValidArgs[2], DWPAL_STR_PARAM, NULL, sizeof(sta_disconnected_event.MACAddress) },

            /* Must be at the end */
            { NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
        };

        if ((ret = dwpal_string_to_struct_parse(msg, msgLen, fieldsToParse)) == DWPAL_FAILURE)
        {
            console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
            return DWPAL_FAILURE;
        }

        stationsInfo = stationsInfoGet(sta_disconnected_event.MACAddress);

        if (stationsInfo == NULL)
		{
			console_printf("%s; AP-STA-DISCONNECTED; 'MACAddress' (%s) not found! ==> do NOT update the database\n", __FUNCTION__, sta_disconnected_event.MACAddress);
		}
        else
		{
            if (!strncmp(sta_disconnected_event.VAPName, stationsInfo->connectedTo, 5))
            {
                console_printf("%s; AP-STA-DISCONNECTED for the ifname ('%s') it is connected to ==> set 'connectedTo' to 'NONE'\n", __FUNCTION__, sta_disconnected_event.MACAddress);
                STRCPY_S(stationsInfo->connectedTo, FIELD_VALUE_LENGTH, "NONE");
                stationsInfo->connectionTime = 0;
            }
            else
            {
                console_printf("%s; AP-STA-DISCONNECTED for the ifname ('%s') it is NOT connected to ('%s') ==> do NOT update the database\n", __FUNCTION__, sta_disconnected_event.MACAddress, stationsInfo->connectedTo);
            }
		}
    }
    else if (!strncmp(opCode, "BSS-TM-RESP", strnlen_s("BSS-TM-RESP", RSIZE_MAX_STR)))
    {
        /* <3>BSS-TM-RESP wlan2 e4:9a:79:d2:6b:0b dialog_token=5 status_code=6 bss_termination_delay=0 target_bssid=12:ab:34:cd:56:10 */
        DWPAL_bss_tm_resp_event bss_tm_resp_event;
        DWPAL_Ret               ret;
        int                     status_code;
        size_t                  numOfValidArgs[4];
        FieldsToParse           fieldsToParse[] =
        {
            { NULL /*opCode*/,                        &numOfValidArgs[0], DWPAL_STR_PARAM, NULL,           0                                        },
            { NULL /*VAPName*/,                       &numOfValidArgs[1], DWPAL_STR_PARAM, NULL,           0                                        },
            { (void *)&bss_tm_resp_event.MACAddress,  &numOfValidArgs[2], DWPAL_STR_PARAM, NULL,           sizeof(bss_tm_resp_event.MACAddress)     },
            { (void *)&bss_tm_resp_event.status_code, &numOfValidArgs[3], DWPAL_INT_PARAM, "status_code=", 0                                        },
            { (void *)&bss_tm_resp_event.target_bssid,&numOfValidArgs[4], DWPAL_STR_PARAM, "target_bssid=",sizeof(bss_tm_resp_event.target_bssid)   },

            /* Must be at the end */
            { NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
        };

        if ((ret = dwpal_string_to_struct_parse(msg, msgLen, fieldsToParse)) == DWPAL_FAILURE)
        {
            console_printf("%s; dwpal_string_to_struct_parse ERROR ==> Abort!\n", __FUNCTION__);
            return DWPAL_FAILURE;
        }

        console_printf("%s; Steering of MACAddress= '%s' to target_bssid= '%s' returned status_code= '%d'\n", __FUNCTION__,
                                 bss_tm_resp_event.MACAddress, bss_tm_resp_event.target_bssid, bss_tm_resp_event.status_code);

        status_code = bss_tm_resp_event.status_code;
        switch (status_code)
        {
            case 0:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_ACCEPT\n", __FUNCTION__, status_code);
				break;

			case 1:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_UNSPECIFIED\n", __FUNCTION__, status_code);
				break;

			case 2:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_INSUFFICIENT_BEACON\n", __FUNCTION__, status_code);
				break;

			case 3:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_INSUFFICIENT_CAPABITY\n", __FUNCTION__, status_code);
				break;

			case 4:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_UNDESIRED\n", __FUNCTION__, status_code);
				break;

			case 5:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_DELAY_REQUEST\n", __FUNCTION__, status_code);
				break;

			case 6:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_STA_CANDIDATE_LIST_PROVIDED\n", __FUNCTION__, status_code);
				break;

			case 7:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES\n", __FUNCTION__, status_code);
				break;

			case 8:
				console_printf("%s; status_code= '%d' ==> WNM_BSS_TM_REJECT_LEAVING_ESS\n", __FUNCTION__, status_code);
				break;

			default:
				console_printf("%s; Illegal status_code ('%d')\n", __FUNCTION__, status_code);
				break;
        }
    }

	console_printf("\n%s; database AFTER event process:\n", __FUNCTION__);
	stationsInfoListPrint();

	return DWPAL_SUCCESS;
}


static int dwpalThreadSafeRadioInterfaceEventCallback(char *ifname, char *opCode, char *msg, size_t msgLen)
{
	DWPAL_Ret ret;
	pthread_mutex_lock(&bandsteering_mutex);
	ret = dwpalRadioInterfaceEventCallback(ifname, opCode, msg, msgLen);
	pthread_mutex_unlock(&bandsteering_mutex);
	return ret;
}


static void allBandsStationAllowSet(char *MACAddress)
{
	int     i = 0;
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
		if ( (!strncmp(radioInterface[i].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR))) ||
		     (!strncmp(radioInterface[i].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR))) )
		{
			console_printf("%s; Allowing back station (MACAddress= '%s') for interface '%s'\n",
			       __FUNCTION__, MACAddress, radioInterface[i].name);

			if (dwpal_wlan_sta_allow(radioInterface[i].name, MACAddress) == DWPAL_FAILURE)
				console_printf("%s; dwpal_wlan_sta_allow ERROR\n", __FUNCTION__);
		}
	}
}


static void bandSteeringPerform(char *ifname, char *MACAddress, char *ifnameToSteerTo, char *BSSID_ToSteerTo, bool btm_supported)
{
    console_printf("%s Entry; ifname= '%s', MACAddress= '%s', ifnameToSteerTo= '%s', BSSID_ToSteerTo= '%s', btm_supported= %d\n", __FUNCTION__, ifname, MACAddress, ifnameToSteerTo, BSSID_ToSteerTo, btm_supported);

    if (btm_supported == true)
	{
		int  ChannelNumberToSteerTo;
		char neighbor[64];

        console_printf("%s; handle a BTM station (btm_supported= %d)\n", __FUNCTION__, btm_supported);

        ChannelNumberToSteerTo = interfaceChannelNumberGet(ifname);
        if (ChannelNumberToSteerTo == DWPAL_FAILURE)
        {
            console_printf("%s; interfaceChannelNumberGet returned error ==> use '1' for ChannelNumberToSteerTo\n", __FUNCTION__);
			ChannelNumberToSteerTo = 1;
        }
        else
			console_printf("%s; ChannelNumberToSteerTo= '%d'\n", __FUNCTION__, ChannelNumberToSteerTo);

        snprintf(neighbor, sizeof(neighbor) - 1, "%s,0,0,%d,0,255", BSSID_ToSteerTo, ChannelNumberToSteerTo);

        console_printf("%s; send BSS_TM_REQ command; MACAddress= '%s', pref=1, disassoc_imminent=1, disassoc_timer=10, url='%s'\n", __FUNCTION__, MACAddress, neighbor);

        if (dwpal_wlan_bss_transition_management_req(ifname, MACAddress, 1, 1, 10, neighbor) == DWPAL_FAILURE)
		{
			console_printf("dwpal_wlan_bss_transition_management_req ERROR\n");
		}
    }
    else
    {
		console_printf("%s; handle a non-BTM station (btm_supported= %d)\n", __FUNCTION__, btm_supported);

		if (dwpal_wlan_sta_allow(ifnameToSteerTo, MACAddress) == DWPAL_FAILURE)
		{
			console_printf("dwpal_wlan_sta_allow ERROR\n");
			return;
		}

		if (dwpal_wlan_sta_deny(ifname, MACAddress) == DWPAL_FAILURE)
		{
			console_printf("fapi_wlan_sta_deny ERROR\n");
			return;
		}

		if (dwpal_wlan_sta_disassociate(ifname, MACAddress) == DWPAL_FAILURE)
		{
			console_printf("dwpal_wlan_sta_disassociate ERROR\n");
			return;
		}
    }
}


static void bandSteeringIfNeededPerform(char *ifname, char *MACAddress, int signalStrengthThreshold_2_4, int signalStrengthThreshold_5, char *ifnameSteeredTo, bool btm_supported)
{
	int         SignalStrength = 0;
	char        *OperatingStandard = NULL;
	char        ifnameToSteerTo[8] = "\0";
	char        BSSID_ToSteerTo[32] = "\0";
	int         idx;
#if defined BAND_STEERING_TEST_MODE
	static int tempOffset = 0;  // for 'tweaking' the RSSI reports
#endif
    DWPAL_get_sta_measurements  sta_measurements;
    size_t                      numOfValidArgs[2];
    FieldsToParse               fieldsToParse[] =
	{
		{ (void *)&sta_measurements.SignalStrength,     &numOfValidArgs[0], DWPAL_INT_PARAM,    "SignalStrength=",      0 },
        { (void *)&sta_measurements.OperatingStandard,  &numOfValidArgs[1], DWPAL_STR_PARAM,    "OperatingStandard=",   sizeof(sta_measurements.OperatingStandard) },

		/* Must be at the end */
		{ NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
	};

	console_printf("%s; ifname= '%s', MACAddress= '%s', btm_supported= %d\n", __FUNCTION__, ifname, MACAddress, btm_supported);

    STRCPY_S(ifnameSteeredTo, IFNAME_STRING_LENGTH, "NONE");

    if (dwpal_wlan_sta_measurement_get(ifname, MACAddress, fieldsToParse) == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_wlan_sta_measurement_get ERROR\n", __FUNCTION__);

		STRCPY_S(ifnameSteeredTo, IFNAME_STRING_LENGTH, "NON_VALID");
		return;
	}

    SignalStrength = sta_measurements.SignalStrength;
	OperatingStandard = sta_measurements.OperatingStandard;

    if ( (OperatingStandard != NULL) )
	{
		console_printf("%s; SignalStrength= '%d', OperatingStandard= '%s'\n", __FUNCTION__, SignalStrength, OperatingStandard);
		console_printf("%s; SignalStrength= %d, signalStrengthThreshold_2_4= %d, signalStrengthThreshold_5= %d\n",
		       __FUNCTION__, SignalStrength, signalStrengthThreshold_2_4, signalStrengthThreshold_5);

		idx = interfaceIndexGet(ifname);
		if (idx == (-1))
		{
			console_printf("%s; ERROR: interfaceIdx of '%s' is %d ==> Abort!\n", __FUNCTION__, ifname, idx);
			return;
		}

		console_printf("%s; supportedFrequencyBands= %s\n", __FUNCTION__, radioInterface[idx].supportedFrequencyBands);

#if defined BAND_STEERING_TEST_MODE
		tempOffset += 8;
		console_printf("%s; SignalStrength= %d, signalStrengthThreshold_2_4= %d, signalStrengthThreshold_5= %d\n",
		       __FUNCTION__, SignalStrength, signalStrengthThreshold_2_4, signalStrengthThreshold_5);
		console_printf("%s; supportedFrequencyBands= '%s' ==>\n", __FUNCTION__, radioInterface[idx].supportedFrequencyBands);
		console_printf("%s; SignalStrength + %d)= %d, signalStrengthThreshold_2_4= %d\n",
		       __FUNCTION__, tempOffset, (SignalStrength + tempOffset), signalStrengthThreshold_2_4);
		console_printf("%s; SignalStrength - %d)= %d, signalStrengthThreshold_5= %d\n",
		       __FUNCTION__, tempOffset, (SignalStrength - tempOffset), signalStrengthThreshold_5);
		if ( ( (!strncmp(radioInterface[idx].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR))) &&
		       ((SignalStrength + tempOffset) > signalStrengthThreshold_2_4) ) ||
		     ( (!strncmp(radioInterface[idx].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR))) &&
		       ((SignalStrength - tempOffset) < signalStrengthThreshold_5) ) )
#else
		if ( ( (!strncmp(radioInterface[idx].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR))) &&
		       (SignalStrength > signalStrengthThreshold_2_4) ) ||
		     ( (!strncmp(radioInterface[idx].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR))) &&
		       (SignalStrength < signalStrengthThreshold_5) ) )
#endif
		{
#if defined BAND_STEERING_TEST_MODE
			tempOffset = 0;
#endif

			STRCPY_S(ifnameToSteerTo, IFNAME_STRING_LENGTH, radioInterface[idx].ifnameToSteerTo);
			STRCPY_S(BSSID_ToSteerTo, FIELD_VALUE_LENGTH, radioInterface[idx].BSSID_ToSteerTo);

			console_printf("%s; Perform Band-Steering (MACAddress= '%s' from '%s' to '%s')\n", __FUNCTION__, MACAddress, ifname, ifnameToSteerTo);
			console_printf("%s; ifname= '%s', ifnameToSteerTo= '%s', BSSID_ToSteerTo= '%s'\n", __FUNCTION__, ifname, ifnameToSteerTo, BSSID_ToSteerTo);

			STRCPY_S(ifnameSteeredTo, IFNAME_STRING_LENGTH, ifnameToSteerTo);

			bandSteeringPerform(ifname, MACAddress, ifnameToSteerTo, BSSID_ToSteerTo, btm_supported);
		}
		else
		{
			console_printf("%s; (%s) Signal threshold: SignalStrength= %d, signalStrengthThreshold_2_4= %d, signalStrengthThreshold_5= %d ==> cont...\n",
			       __FUNCTION__, ifname, SignalStrength, signalStrengthThreshold_2_4, signalStrengthThreshold_5);
		}
    }
}


static int ap_manager_lite_band_steering_perform(int signalStrengthThreshold_2_4, int signalStrengthThreshold_5, int intervalInSeconds, int toleranceInSeconds, int numOfTicksAllowedForSteering)
{
	char            OperatingStandard[64] = "\0";
	char            ifnameSteeredTo[64] = "\0";
#if defined NEED_TO_BE_TESTED
	char            isLegacyBandSteeringTriedOnce[64] = "\0";
#endif
	int             secondsFromStaConnection, idx;
	time_t          rawtime;
	StationsInfo_t  *stationsInfo = NULL;

	console_printf("\n%s Entry; signalStrengthThreshold_2_4= %d, signalStrengthThreshold_5= %d, intervalInSeconds= %d, toleranceInSeconds= %d, numOfTicksAllowedForSteering= %d\n",
	       __FUNCTION__, signalStrengthThreshold_2_4, signalStrengthThreshold_5, intervalInSeconds, toleranceInSeconds, numOfTicksAllowedForSteering);

	stationsInfo = firstStationInfo;
	while (stationsInfo != NULL)
	{
		console_printf("%s; MACAddress= '%s', connectedTo= '%s', connectionTime= %d, is_5G_supported= %d, ifnameCheckIfConnected= '%s', numOfTicks= %d, btm_supported= %d, isBandSteeringPossible= %d\n",
			   __FUNCTION__, stationsInfo->MACAddress, stationsInfo->connectedTo, stationsInfo->connectionTime, stationsInfo->is_5G_supported, stationsInfo->ifnameCheckIfConnected,
			   stationsInfo->numOfTicks, stationsInfo->btm_supported, stationsInfo->isBandSteeringPossible);

		if (stationsInfo->isBandSteeringPossible == false)
		{
			/* Band-Steering is impossible for this station */
			console_printf("%s; Station (MACAddress= '%s') can NOT be steered, it failed to do so many times before ==> do NOT check for band-steering. cont...\n",
				   __FUNCTION__, stationsInfo->MACAddress);

			stationsInfo = stationsInfo->nextStation;
			continue;
		}

		/* update 'is_5G_supported' ONLY if it is NOT 'true', and that the station is connected */
		if ( (stationsInfo->is_5G_supported != 1 /*true*/) && (strncmp(stationsInfo->connectedTo, "NONE", strnlen_s("NONE", RSIZE_MAX_STR))) )
		{
            DWPAL_get_sta_measurements  sta_measurements;
            size_t                      numOfValidArgs[2];
            FieldsToParse               fieldsToParse[] =
            {
                { (void *)&sta_measurements.SignalStrength,     &numOfValidArgs[0], DWPAL_INT_PARAM,    "SignalStrength=",      0 },
                { (void *)&sta_measurements.OperatingStandard,  &numOfValidArgs[1], DWPAL_STR_PARAM,    "OperatingStandard=",   sizeof(sta_measurements.OperatingStandard) },

                /* Must be at the end */
                { NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
            };

			if (dwpal_wlan_sta_measurement_get(stationsInfo->connectedTo, stationsInfo->MACAddress, fieldsToParse) == DWPAL_FAILURE)
			{
				console_printf("%s; dwpal_wlan_sta_measurement_get ERROR\n", __FUNCTION__);
				stationsInfo = stationsInfo->nextStation;
				continue;
			}

			STRCPY_S(OperatingStandard, FIELD_VALUE_LENGTH, sta_measurements.OperatingStandard);

			console_printf("%s; OperatingStandard= '%s', is_5G_supported= %d\n", __FUNCTION__, OperatingStandard, stationsInfo->is_5G_supported);

			if (strchr(OperatingStandard, 'a') != NULL)
			{
				if (stationsInfo->is_5G_supported != 1 /*true*/)
				{
					stationsInfo->is_5G_supported = 1; /*true*/
					console_printf("%s; OperatingStandard ('%s') includes 'a' ==> supports 5 GHz; database:\n", __FUNCTION__, OperatingStandard);
					stationsInfoListPrint();
				}
				else
				{
					console_printf("%s; *** is_5G_supported= %d ==> do NOT check for update ***\n", __FUNCTION__, stationsInfo->is_5G_supported);
				}
			}
			else
			{
				console_printf("%s; OperatingStandard ('%s') does NOT include 'a' ==> NOT supporting 5 GHz\n", __FUNCTION__, OperatingStandard);
			}
		}

		console_printf("%s; connectedTo= '%s', is_5G_supported= %d, ifnameCheckIfConnected= '%s'\n",
			   __FUNCTION__, stationsInfo->connectedTo, stationsInfo->is_5G_supported, stationsInfo->ifnameCheckIfConnected);
		if ( (stationsInfo->ifnameCheckIfConnected != NULL) && (strncmp(stationsInfo->ifnameCheckIfConnected, "NONE", strnlen_s("NONE", RSIZE_MAX_STR))) && (strncmp(stationsInfo->ifnameCheckIfConnected, "", 1)))
		{
			console_printf("%s; ifnameCheckIfConnected= '%s' ==> do NOT check for band steering; cont...\n", __FUNCTION__, stationsInfo->ifnameCheckIfConnected);
		}
		else
		{
			console_printf("%s; ifnameCheckIfConnected= '%s' ==> check for band steering\n", __FUNCTION__, stationsInfo->ifnameCheckIfConnected);

			if ( ( (stationsInfo->connectedTo != NULL) && (!strncmp(stationsInfo->connectedTo, "NONE", strnlen_s("NONE", RSIZE_MAX_STR))) ) ||
				 (stationsInfo->connectedTo == NULL) ||
				 (stationsInfo->is_5G_supported == 0 /*false*/) )
			{
				/* There is no connection, or 5 GHz is not supported */
				console_printf("%s; connectedTo= '%s', is_5G_supported= %d ==> do NOT check for band-steering. cont...\n",
					   __FUNCTION__, stationsInfo->connectedTo, stationsInfo->is_5G_supported);
			}
			else if ( (strncmp(stationsInfo->connectedTo, "NONE", strnlen_s("NONE", RSIZE_MAX_STR))) && (stationsInfo->is_5G_supported == 2 /*NON_VALID*/) )
			{
				/* There is a connection, and 5 GHz supported is unknown yet! */
				console_printf("%s; connectedTo= '%s', is_5G_supported= %d ==> try to switch to 5 GHz band\n",
					   __FUNCTION__, stationsInfo->connectedTo, stationsInfo->is_5G_supported);

				idx = interfaceIndexGet(stationsInfo->connectedTo);
				if (idx == (-1))
				{
					console_printf("%s; ERROR: interfaceIdx of '%s' is %d ==> Abort!\n", __FUNCTION__, stationsInfo->connectedTo, idx);
					stationsInfo = stationsInfo->nextStation;
					continue;
				}

				console_printf("%s; ifnameToSteerTo= '%s', BSSID_ToSteerTo= '%s'\n", __FUNCTION__, radioInterface[idx].ifnameToSteerTo, radioInterface[idx].BSSID_ToSteerTo);

				bandSteeringPerform(stationsInfo->connectedTo, stationsInfo->MACAddress, radioInterface[idx].ifnameToSteerTo, radioInterface[idx].BSSID_ToSteerTo, stationsInfo->btm_supported);

				stationsInfo->numOfTicks = 0;
				STRCPY_S(stationsInfo->ifnameCheckIfConnected, FIELD_VALUE_LENGTH, radioInterface[idx].ifnameToSteerTo);  /* Update ifnameCheckIfConnected */
			}
			else
			{
				time(&rawtime);
				secondsFromStaConnection = rawtime - stationsInfo->connectionTime;
				console_printf("%s; rawtime= %ld, connectionTime= %d ==> secondsFromStaConnection= %d\n", __FUNCTION__, rawtime, stationsInfo->connectionTime, secondsFromStaConnection);

				if (secondsFromStaConnection > toleranceInSeconds)
				{
					console_printf("%s; If needed, perform Band-Steering: Connected to '%s', MACAddress= '%s'\n", __FUNCTION__, stationsInfo->connectedTo, stationsInfo->MACAddress);

					bandSteeringIfNeededPerform(stationsInfo->connectedTo, stationsInfo->MACAddress, signalStrengthThreshold_2_4, signalStrengthThreshold_5, ifnameSteeredTo, stationsInfo->btm_supported);

					console_printf("%s; *** MACAddress= '%s', ifnameSteeredTo= '%s' ***\n", __FUNCTION__, stationsInfo->MACAddress, ifnameSteeredTo);
					if (strncmp(ifnameSteeredTo, "NON_VALID", strnlen_s("NON_VALID", RSIZE_MAX_STR)))
					{
						STRNCPY_S(stationsInfo->ifnameCheckIfConnected, 6, ifnameSteeredTo, 5);  /* Update ifnameCheckIfConnected */
						stationsInfo->ifnameCheckIfConnected[5] = '\0';
					}
				}
				else
				{
					console_printf("%s; secondsFromStaConnection (%d) <= toleranceInSeconds (%d) ==> do NOT check for band-steering. cont...\n", __FUNCTION__, secondsFromStaConnection, toleranceInSeconds);
				}
			}
		}

		console_printf("%s; *** MACAddress= '%s', is_5G_supported= %d, connectedTo= '%s', ifnameCheckIfConnected= '%s', btm_supported= %d ***\n",
			   __FUNCTION__, stationsInfo->MACAddress, stationsInfo->is_5G_supported, stationsInfo->connectedTo, stationsInfo->ifnameCheckIfConnected, stationsInfo->btm_supported);

		if ( (stationsInfo->is_5G_supported != 0 /*false*/) /* 'true' or 'NON_VALID' */ &&
			 (stationsInfo->connectedTo != NULL) &&
			 (strncmp(stationsInfo->ifnameCheckIfConnected, "NONE", strnlen_s("NONE", RSIZE_MAX_STR))) &&
			 (strncmp(stationsInfo->ifnameCheckIfConnected, "", 1)) )
		{  /* The ifnameCheckIfConnected is NOT "NONE", meaning, there was a band-steering on this station */
			console_printf("%s; *** numOfTicks= %d; (connectedTo= '%s', ifnameCheckIfConnected= '%s') ***\n", __FUNCTION__, stationsInfo->numOfTicks, stationsInfo->connectedTo, stationsInfo->ifnameCheckIfConnected);

			if (!strncmp(stationsInfo->connectedTo, stationsInfo->ifnameCheckIfConnected, strnlen_s(stationsInfo->ifnameCheckIfConnected, RSIZE_MAX_STR)))
			{
				console_printf("%s; Steering occurred! (MACAddress= '%s' to '%s')\n", __FUNCTION__, stationsInfo->MACAddress, stationsInfo->connectedTo);
				stationsInfo->numOfTicks = 0;
				STRCPY_S(stationsInfo->ifnameCheckIfConnected, FIELD_VALUE_LENGTH, "NONE");
				stationsInfoListPrint();
#if defined NEED_TO_BE_TESTED
				HELP_EDIT_SELF_NODE(tmpObj, "Device.WiFi.Radio.X_LANTIQ_COM_Vendor", "isLegacyBandSteeringTriedOnce", "false", 0, 0);
#endif
			}
			else
			{
				console_printf("%s; Steering (MACAddress= '%s' to '%s') did NOT occur! (check %d out of %d)\n",
				       __FUNCTION__, stationsInfo->MACAddress, stationsInfo->ifnameCheckIfConnected, stationsInfo->numOfTicks+1, numOfTicksAllowedForSteering);

				if (stationsInfo->numOfTicks >= (numOfTicksAllowedForSteering - 1))
				{
#if defined NEED_TO_BE_TESTED
					bool isSpecialCase = false;
#endif
					console_printf("%s; PROBLEM!!! Steering did NOT work!!! (MACAddress= '%s' to '%s')\n",
					       __FUNCTION__, stationsInfo->MACAddress, stationsInfo->ifnameCheckIfConnected);

					stationsInfo->numOfTicks = 0;
					STRCPY_S(stationsInfo->ifnameCheckIfConnected, FIELD_VALUE_LENGTH, "NONE");

					if (stationsInfo->btm_supported == true)
					{
						console_printf("%s; btm_supported= %d ==> do not set 'isBandSteeringPossible' to 'false'\n", __FUNCTION__, stationsInfo->btm_supported);
						console_printf("%s; Steering did NOT occur! MACAddress= '%s'(BTM supported station)\n", __FUNCTION__, stationsInfo->MACAddress);
						console_printf("%s; btm_supported= %d ==> it should NOT try to steer for %d seconds period of time\n", __FUNCTION__, stationsInfo->btm_supported, toleranceInSeconds);
#if defined NEED_TO_BE_TESTED
						console_printf("%s; isLegacyBandSteeringTriedOnce= '%s'\n", __FUNCTION__, isLegacyBandSteeringTriedOnce);

						if ( (!strncmp(isLegacyBandSteeringTriedOnce, "", 1)) || (!strncmp(isLegacyBandSteeringTriedOnce, "false", strnlen_s("false", RSIZE_MAX_STR))) )  // if legacy steering did NOT occured once
						{
							isSpecialCase = true;

							/* perform legacy steering; update that legacy steeering occured once */
							console_printf("%s; Special case: Steering of btm_supported station failed ==> try ONE TIME Legacy-Steering (black/white list)\n", __FUNCTION__);
							HELP_EDIT_SELF_NODE(tmpObj, "Device.WiFi.Radio.X_LANTIQ_COM_Vendor", "isLegacyBandSteeringTriedOnce", "true", 0, 0);

							stationsInfo->numOfTicks = 0;
							HELP_EDIT_SELF_NODE(tmpObj, "Device.WiFi.Radio.X_LANTIQ_COM_Vendor", "numOfTicks", "0", 0, 0);

							idx = interfaceIndexGet(stationsInfo->connectedTo);
							if (idx == (-1))
							{
								console_printf("%s; ERROR: interfaceIdx of '%s' is %d ==> Abort!\n", __FUNCTION__, connectedTo, idx);
								return DWPAL_FAILURE;
							}

							console_printf("%s; Special case; connectedTo= '%s', idx= %d\n", __FUNCTION__, stationsInfo->connectedTo, idx);
							bandSteeringPerform(stationsInfo->connectedTo, stationsInfo->MACAddress, radioInterface[idx].ifnameToSteerTo, radioInterface[idx].BSSID_ToSteerTo, "false");
						}
						else
#endif
						{
							time(&rawtime);
							console_printf("%s; Reset station's connection time (rawtime= %ld)\n", __FUNCTION__, rawtime);
							stationsInfo->connectionTime = rawtime;
						}
					}
					else
					{
						stationsInfo->isBandSteeringPossible = false;
					}

#if defined NEED_TO_BE_TESTED
					console_printf("%s; isSpecialCase= %d\n", __FUNCTION__, isSpecialCase);

					/* Allow back the station for ALL active bands */
					if (isSpecialCase == false)
#endif
					{
						if (stationsInfo->btm_supported == false)
						{
							allBandsStationAllowSet(stationsInfo->MACAddress);
						}
					}

					/* In case that band steering failed, and 'is_5G_supported' is 'NON_VALID', it means that steering to 5 GHz failed ==> mark 'is_5G_supported' to 'false' */
					if (stationsInfo->is_5G_supported == 2 /*NON_VALID*/)
					{
						console_printf("%s; Steering to 5 GHz band for a station which is unknown if supporting dual-band failed ==> set is_5G_supported to 'false'\n", __FUNCTION__);
						stationsInfo->is_5G_supported = 0;  /*false*/
					}
				}
				else
				{
					stationsInfo->numOfTicks++;
					console_printf("%s; increment the counter ==> numOfTicks= %d\n", __FUNCTION__, stationsInfo->numOfTicks);
				}

				console_printf("%s; Steering did NOT occur; MACAddress= '%s' to '%s' ==> database:\n",
					   __FUNCTION__, stationsInfo->MACAddress, stationsInfo->ifnameCheckIfConnected);
				stationsInfoListPrint();
			}
		}

		stationsInfo = stationsInfo->nextStation;
	}

    return DWPAL_SUCCESS;
}


static int interfaceBSSIDInfoSet(void)
{
    int                         i;
    size_t                      numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);
	DWPAL_get_vap_measurements  get_vap_measurements;
	size_t                      numOfValidArgs[1];
	DWPAL_Ret 	                ret;
	FieldsToParse               fieldsToParse[] =
	{
		{ (void *)&get_vap_measurements.BSSID,    &numOfValidArgs[0],  DWPAL_STR_PARAM,   "BSSID=",   sizeof(get_vap_measurements.BSSID) },

		/* Must be at the end */
		{ NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
	};

    console_printf("%s; Entry\n", __FUNCTION__);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
        if (!strncmp(radioInterface[i].operationMode, "AP", strnlen_s("AP", RSIZE_MAX_STR)))
        {
            console_printf("%s; Getting BSSID for %s\n", __FUNCTION__, radioInterface[i].name);

            ret = dwpal_wlan_vap_measurements_get(radioInterface[i].name, fieldsToParse);

            if (ret == DWPAL_FAILURE)
            {
                console_printf("%s; dwpal_wlan_vap_measurements_get error\n", __FUNCTION__);
                return DWPAL_FAILURE;
            }
            else
            {
                STRCPY_S(radioInterface[i].BSSID, 24, get_vap_measurements.BSSID);
            }
        }
    }

	return DWPAL_SUCCESS;
}


static int ifnameBssidToSteerToSet(int recordIdx, char *FrequencyBandToSteerTo)
{
	int     i = 0;
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);

	console_printf("%s; recordIdx= %d, FrequencyBandToSteerTo= '%s'\n", __FUNCTION__, recordIdx, FrequencyBandToSteerTo);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
		if (!strncmp(radioInterface[i].supportedFrequencyBands, FrequencyBandToSteerTo, strnlen_s(FrequencyBandToSteerTo, RSIZE_MAX_STR)))
		{
			STRCPY_S(radioInterface[recordIdx].ifnameToSteerTo, 6, radioInterface[i].name);
			STRCPY_S(radioInterface[recordIdx].BSSID_ToSteerTo, 24, radioInterface[i].BSSID);
		}
	}

	console_printf("%s; [idx= %d] ifname= '%s', ifnameToSteerTo= '%s', BSSID= '%s'\n",
	       __FUNCTION__, recordIdx, radioInterface[recordIdx].name, radioInterface[recordIdx].ifnameToSteerTo, radioInterface[recordIdx].BSSID_ToSteerTo);

	return DWPAL_SUCCESS;
}


static DWPAL_Ret interfaceBandSteerInfoSet(void)
{
    int                  i;
    size_t               numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);
	DWPAL_radio_info_get radio_info;
	size_t               numOfValidArgs[1];
	DWPAL_Ret 	         ret;
	FieldsToParse        fieldsToParse[] =
	{
		{ (void *)&radio_info.Freq,     &numOfValidArgs[0],    DWPAL_INT_PARAM, "Freq=",   0 },

		/* Must be at the end */
		{ NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0 }
	};

    console_printf("%s; Entry\n", __FUNCTION__);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
        if (!strncmp(radioInterface[i].operationMode, "AP", strnlen_s("AP", RSIZE_MAX_STR)))
        {
            console_printf("%s; Getting supported Frequency Band for %s\n", __FUNCTION__, radioInterface[i].name);

            ret = dwpal_wlan_radio_info_get(radioInterface[i].name, fieldsToParse);

            if (ret == DWPAL_FAILURE)
            {
                console_printf("%s; GET_RADIO_INFO command send error\n", __FUNCTION__);
                return DWPAL_FAILURE;
            }
            else
            {
                if (radio_info.Freq < 3000)
                {
                    STRCPY_S(radioInterface[i].supportedFrequencyBands, DWPAL_OPERATING_MODE_STRING_LENGTH, "2.4GHz");
                }
                else
                {
                    STRCPY_S(radioInterface[i].supportedFrequencyBands, DWPAL_OPERATING_MODE_STRING_LENGTH, "5GHz");
                }
            }
        }
    }

	return DWPAL_SUCCESS;
}


static void allStationsDisconnect(char *ifname)
{
	char    command[256];
	FILE    *fout = NULL;
	char    MACAddress[18] = "\0";

	snprintf(command, sizeof(command) - 1, "iw %s station dump  | sed -n 's/Station \\([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]\\).*/\\1/p'", ifname);

	fout = popen(command, "r");
	if (fout == NULL)
	{
		console_printf("%s; popen of '%s' returned NULL ==> Abort!\n", __FUNCTION__, command);
		return;
	}

	while (fgets(MACAddress, 18, fout) != '\0')
	{
		if (STRNLEN_S(MACAddress, 32) < 17)
		{
			continue;
		}
        /* Make sure that the end of string will be '\0' instead of new-line ('\n') */
		MACAddress[17] = '\0';
		console_printf("%s; connected station ('%s') found ==> disconnect it!\n", __FUNCTION__, MACAddress);

		/* DISASSOCIATE any connected station */
		if (dwpal_wlan_sta_disassociate(ifname, MACAddress) == DWPAL_FAILURE)
		{
			console_printf("dwpal_wlan_sta_disassociate ERROR\n");
		}
	}

	pclose(fout);
}


static int ap_manager_lite_band_steering_init(void)
{
    bool    support_2_4 = false, support_5 = false;
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);
	int     i;

	console_printf("%s; Entry\n", __FUNCTION__);

	console_printf("%s; numOfActiveApInterfaces= %d\n", __FUNCTION__, numOfActiveApInterfaces);
	if (numOfActiveApInterfaces < 2)
	{
		console_printf("%s; Less than two APs (%d) are present ==> do NOT check for band-steering. Quit!\n\n", __FUNCTION__, numOfActiveApInterfaces);
		return DWPAL_FAILURE;
	}

    /* Set the band-steering data-base */
	if (interfaceBandSteerInfoSet() == DWPAL_FAILURE)
	{
		console_printf("%s; create Band-Steering DB Info ERROR\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

    if (interfaceBSSIDInfoSet() == DWPAL_FAILURE)
    {
        console_printf("%s; create BSSID Info ERROR\n", __FUNCTION__);
		return DWPAL_FAILURE;
    }

    for (i=0; i < (int)numOfInterfaces; i++)
	{
		if (!strncmp(radioInterface[i].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR)))
			support_2_4 = true;
		else if (!strncmp(radioInterface[i].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR)))
			support_5 = true;
	}

    if ( (support_2_4 == false) || (support_5 == false) )
	{
		console_printf("%s; one (or more) of the bands (2.4 & 5 GHz) are not available ==> do NOT check for band-steering. Quit!\n\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

    for (i=0; i < (int)numOfInterfaces; i++)
	{
		if ( (!strncmp(radioInterface[i].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR))) ||
		     (!strncmp(radioInterface[i].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR))) )
		{
			if (!strncmp(radioInterface[i].supportedFrequencyBands, "2.4GHz", strnlen_s("2.4GHz", RSIZE_MAX_STR)))
			{
				if (ifnameBssidToSteerToSet(i, "5GHz") == DWPAL_FAILURE)
				{
					console_printf("%s; ifnameBssidToSteerToSet returned error ==> Quit!\n\n", __FUNCTION__);
					return DWPAL_FAILURE;
				}

				/* disconnect all connected stations */
				allStationsDisconnect(radioInterface[i].name);
			}

			if (!strncmp(radioInterface[i].supportedFrequencyBands, "5GHz", strnlen_s("5GHz", RSIZE_MAX_STR)))
			{
				if (ifnameBssidToSteerToSet(i, "2.4GHz") == DWPAL_FAILURE)
				{
					console_printf("%s; ifnameBssidToSteerToSet returned error ==> Quit!\n\n", __FUNCTION__);
					return DWPAL_FAILURE;
				}

				/* disconnect all connected stations */
				allStationsDisconnect(radioInterface[i].name);
			}
		}
	}

    return DWPAL_SUCCESS;
}


static void radioInterfaceDataBaseUpdate(void)
{
    int     i;
	char    wpaCtrlName[DWPAL_WPA_CTRL_STRING_LENGTH];
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);

    console_printf("%s; Entry\n", __FUNCTION__);

	for (i=0; i < (int)numOfInterfaces; i++)
	{
		/* check if '/var/run/hostapd/wlanX' or '/var/run/wpa_supplicant/wlanX' exists */
		snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/hostapd/", radioInterface[i].name);
		if (access(wpaCtrlName, F_OK) == 0)
		{
			console_printf("%s; Radio '%s' exists - AP Mode\n", __FUNCTION__, radioInterface[i].name);
			STRCPY_S(radioInterface[i].operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "AP");
			numOfActiveApInterfaces++;
		}
		else
		{
			snprintf(wpaCtrlName, DWPAL_WPA_CTRL_STRING_LENGTH, "%s%s", "/var/run/wpa_supplicant/", radioInterface[i].name);
			if (access(wpaCtrlName, F_OK) == 0)
			{
				console_printf("%s; Radio '%s' exists - STA Mode\n", __FUNCTION__, radioInterface[i].name);
				STRCPY_S(radioInterface[i].operationMode, DWPAL_OPERATING_MODE_STRING_LENGTH, "STA");
			}
		}
	}
}


static void dwpalBandSteeringAppStart(int signalStrengthThreshold_2_4, int signalStrengthThreshold_5, int intervalInSeconds,
                                     int toleranceInSeconds, int numOfTicksAllowedForSteering)
{
    int     i;
    bool    isInterfaceActive = false;
    size_t  numOfInterfaces = sizeof(radioInterface) / sizeof(DwpalRadioInterface);

    console_printf("%s; Entry\n", __FUNCTION__);

	if (pthread_mutex_init(&bandsteering_mutex, NULL))
    {
        console_printf("%s; mutex init failed\n", __FUNCTION__);
        return;
    }

    /* find all AP radio interfaces */
    radioInterfaceDataBaseUpdate();

    for (i=0; i < (int)numOfInterfaces; i++)
	{
		if (!strncmp(radioInterface[i].operationMode, "NONE", strnlen_s("NONE", RSIZE_MAX_STR)))
		{
			console_printf("%s; radio interface '%s' not present ==> Continue\n", __FUNCTION__, radioInterface[i].name);
			continue;
		}

		if (!strncmp(radioInterface[i].operationMode, "STA", strnlen_s("STA", RSIZE_MAX_STR)))
		{
			console_printf("%s; radio interface '%s' not AP ==> Continue\n", __FUNCTION__, radioInterface[i].name);
			continue;
		}

        if (dwpal_ext_hostap_interface_attach(radioInterface[i].name, dwpalThreadSafeRadioInterfaceEventCallback) == DWPAL_FAILURE)
        {
            console_printf("%s; dwpal_ext_hostap_interface_attach returned ERROR (radio interface = '%s') ==> Abort!\n", __FUNCTION__, radioInterface[i].name);
            continue;
        }

        isInterfaceActive = true;
		console_printf("%s; supportedInterfaces[%d]= '%s'\n", __FUNCTION__, i, radioInterface[i].name);
	}

    if (isInterfaceActive)
	{
        if (ap_manager_lite_band_steering_init() == DWPAL_FAILURE)
            return;

        while (true)
        {
            sleep(intervalInSeconds);

			pthread_mutex_lock(&bandsteering_mutex);
            console_printf("%s; %d seconds passed, check if band steering is needed\n", __FUNCTION__, intervalInSeconds);

            ap_manager_lite_band_steering_perform(signalStrengthThreshold_2_4, signalStrengthThreshold_5, intervalInSeconds, toleranceInSeconds, numOfTicksAllowedForSteering);

            console_printf("%s; sleep %d seconds...\n\n", __FUNCTION__, intervalInSeconds);
			pthread_mutex_unlock(&bandsteering_mutex);
        }
    }

    for (i=0; i < (int)numOfInterfaces; i++)
	{
        if (!strncmp(radioInterface[i].operationMode, "AP", strnlen_s("AP", RSIZE_MAX_STR)) &&
				dwpal_ext_hostap_interface_detach(radioInterface[i].name) == DWPAL_FAILURE)
        {
            console_printf("%s; dwpal_ext_hostap_interface_detach returned ERROR (radio interface = '%s')\n", __FUNCTION__, radioInterface[i].name);
            continue;
        }
	}

	pthread_mutex_destroy(&bandsteering_mutex);
}


int main(int argc, char *argv[])
{
    /* default values */
    int signalStrengthThreshold_2_4 = -40;
    int signalStrengthThreshold_5 = -60;
    int intervalInSeconds = 5;
    int toleranceInSeconds = 15;
    int numOfTicksAllowedForSteering = 15;

    /*
    Usage Format:   ./dwpal_band_steering &
                    ./dwpal_band_steering -30 -70 5 10 15 &
    */
    console_printf("D-WPAL Band Steering App; argc= %d\n", argc);

    if (argc > 5)
	{
        signalStrengthThreshold_2_4 = atoi(argv[2]);
        signalStrengthThreshold_5   = atoi(argv[3]);
        intervalInSeconds           = atoi(argv[4]);
        toleranceInSeconds          = atoi(argv[5]);

        if (argc > 6)
        {
            numOfTicksAllowedForSteering = atoi(argv[6]);
        }
        else
        {
            console_printf("D-WPAL Band Steering App; parameter #5 (numOfTicksAllowedForSteering) is missing" \
                            " ==> use default (%d) value\n", numOfTicksAllowedForSteering);
        }
    }
    else
    {
        console_printf("D-WPAL Band Steering App; 4 mandatory parameters are not present" \
                        " ==> use default values:\n");
    }

    console_printf("D-WPAL Band Steering App; signalStrengthThreshold_2_4= %d, signalStrengthThreshold_5= %d," \
                    " intervalInSeconds= %d, toleranceInSeconds= %d, numOfTicksAllowedForSteering= %d\n",
			        signalStrengthThreshold_2_4, signalStrengthThreshold_5, intervalInSeconds,
                    toleranceInSeconds, numOfTicksAllowedForSteering);

    dwpalBandSteeringAppStart(signalStrengthThreshold_2_4, signalStrengthThreshold_5, intervalInSeconds,
                             toleranceInSeconds, numOfTicksAllowedForSteering);

	stationsInfoListClear();

    console_printf("D-WPAL Band Steering App; Exit!\n");

    return 0;
}
