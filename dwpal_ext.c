/*  ***************************************************************************** 
 *         File Name    : dwpal_ext.c                             	            *
 *         Description  : D-WPAL Extender control interface 		            * 
 *                                                                              *
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "dwpal_ext.h"
#include "dwpal.h"
#if defined YOCTO
#include <puma_safe_libc.h>
#else
#include "safe_str_lib.h"
#endif

#if defined YOCTO_LOGGING
#include "help_logging.h"
#define PRINT_DEBUG(...)  LOGF_LOG_DEBUG(__VA_ARGS__)
#define PRINT_ERROR(...)  LOGF_LOG_ERROR(__VA_ARGS__)
#else
#define PRINT_DEBUG(...)  printf(__VA_ARGS__)
#define PRINT_ERROR(...)  printf(__VA_ARGS__)
#endif


typedef struct
{
	char                        *interfaceType;
	char                        *radioName;
	char                        *serviceName;
	int                         fd;
	bool                        isConnectionEstablishNeeded;
	DwpalExtHostapEventCallback hostapEventCallback;
	DwpalExtNlEventCallback     nlEventCallback;
} DwpalService;


static DwpalService dwpalService[] = { { "hostap", "wlan0", "ONE_WAY", -1, false, NULL, NULL },  /* Will send commands and get events on a different socket */
                                       { "hostap", "wlan1", "ONE_WAY", -1, false, NULL, NULL },
                                       { "hostap", "wlan2", "ONE_WAY", -1, false, NULL, NULL },
                                       { "hostap", "wlan3", "ONE_WAY", -1, false, NULL, NULL },
                                       { "hostap", "wlan4", "ONE_WAY", -1, false, NULL, NULL },
                                       { "hostap", "wlan5", "ONE_WAY", -1, false, NULL, NULL },
                                       { "Driver", "ALL",   "ONE_WAY", -1, false, NULL, NULL } };

static void *context[sizeof(dwpalService) / sizeof(DwpalService)];
static pthread_t thread_id = (pthread_t)0;


static DWPAL_Ret radioInterfaceIndexGet(char *interfaceType, char *radioName, int *idx)
{
	int    i;
	size_t numOfServices = sizeof(dwpalService) / sizeof(DwpalService);

	*idx = 0;

	for (i=0; i < (int)numOfServices; i++)
	{
		if ( (!strncmp(interfaceType, dwpalService[i].interfaceType, DWPAL_GENERAL_STRING_LENGTH)) &&
		     (!strncmp(radioName, dwpalService[i].radioName, DWPAL_RADIO_NAME_STRING_LENGTH)) )
		{
			*idx = i;
			return DWPAL_SUCCESS;
		}
	}

	return DWPAL_FAILURE;
}


static void interfaceExistCheckAndRecover(void)
{
	int  i, numOfServices = sizeof(dwpalService) / sizeof(DwpalService);
	bool isExist = false;

	//PRINT_DEBUG("%s Entry\n", __FUNCTION__);

	for (i=0; i < numOfServices; i++)
	{
		if (!strncmp(dwpalService[i].interfaceType, "hostap", 7))
		{
			if (dwpalService[i].fd > 0)
			{
				/* check if interface that should exist, still exists */
				if (dwpal_hostap_is_interface_exist(context[i], &isExist /*OUT*/) == DWPAL_FAILURE)
				{
					PRINT_ERROR("%s; dwpal_hostap_is_interface_exist for radioName= '%s' error ==> cont...\n", __FUNCTION__, dwpalService[i].radioName);
					continue;
				}

				if (isExist == false)
				{  /* interface that should exist, does NOT exist */
					PRINT_ERROR("%s; radioName= '%s' interface needs to be recovered\n", __FUNCTION__, dwpalService[i].radioName);
					dwpalService[i].isConnectionEstablishNeeded = true;
					dwpalService[i].fd = -1;
					
					/* note: dwpalService[i].hostapEventCallback should be kept for usage after recovery */
				}
			}

			/* In case of recovery needed, try recover; in case of interface init, try to establish the connection */
			if (dwpalService[i].isConnectionEstablishNeeded == true)
			{  /* try recovering the interface */
				//PRINT_DEBUG("%s; try recover - radioName= '%s'\n", __FUNCTION__, dwpalService[i].radioName);
				if (dwpal_hostap_interface_attach(&context[i] /*OUT*/, dwpalService[i].radioName, NULL /*use one-way interface*/) == DWPAL_SUCCESS)
				{
					PRINT_DEBUG("%s; radioName= '%s' interface recovered successfully!\n", __FUNCTION__, dwpalService[i].radioName);
					dwpalService[i].isConnectionEstablishNeeded = false;
				}
				else
				{
					//PRINT_ERROR("%s; dwpal_hostap_interface_attach (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, dwpalService[i].radioName);
				}
			}
		}
	}
}


static void *listenerThreadStart(void *temp)
{
	int     i, highestValFD, ret, numOfServices = sizeof(dwpalService) / sizeof(DwpalService);
	bool    isTimerExpired;
	char    *msg;
	size_t  msgLen, msgStringLen;
	fd_set  rfds;
	char    opCode[64];
	struct  timeval tv;

	(void)temp;

	PRINT_DEBUG("%s Entry\n", __FUNCTION__);

	/* Receive the msg */
	while (true)
	{
		FD_ZERO(&rfds);
		highestValFD = 0;

		for (i=0; i < numOfServices; i++)
		{
			/* In case that there is no valid context, continue... */
			if (context[i] == NULL)
			{
				continue;
			}

			if (!strncmp(dwpalService[i].interfaceType, "hostap", 7))
			{
				if (dwpal_hostap_event_fd_get(context[i], &dwpalService[i].fd) == DWPAL_FAILURE)
				{
					/*PRINT_ERROR("%s; dwpal_hostap_event_fd_get returned error ==> cont. (serviceName= '%s', radioName= '%s')\n",
					       __FUNCTION__, dwpalService[i].serviceName, dwpalService[i].radioName);*/
					continue;
				}

				if (dwpalService[i].fd > 0)
				{
					FD_SET(dwpalService[i].fd, &rfds);
					highestValFD = (dwpalService[i].fd > highestValFD)? dwpalService[i].fd : highestValFD;  /* find the highest value fd */
				}
			}
			else if (!strncmp(dwpalService[i].interfaceType, "Driver", 7))
			{
				if (dwpal_driver_nl_fd_get(context[i], &dwpalService[i].fd) == DWPAL_FAILURE)
				{
					/*PRINT_ERROR("%s; dwpal_driver_nl_fd_get returned error ==> cont. (serviceName= '%s', radioName= '%s')\n",
					       __FUNCTION__, dwpalService[i].serviceName, dwpalService[i].radioName);*/
					continue;
				}

				if (dwpalService[i].fd > 0)
				{
					FD_SET(dwpalService[i].fd, &rfds);
					highestValFD = (dwpalService[i].fd > highestValFD)? dwpalService[i].fd : highestValFD;  /* find the highest value fd */
				}
			}
		}

		//PRINT_DEBUG("%s; highestValFD= %d\n", __FUNCTION__, highestValFD);

		/* Interval of time in which the select() will be released */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		isTimerExpired = true;

		/* In case that no active hostap is available, highestValFD is '0' and we'll loop out according to tv values */
		ret = select(highestValFD + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0)
		{
			PRINT_DEBUG("%s; select() return value= %d ==> cont...; errno= %d ('%s')\n", __FUNCTION__, ret, errno, strerror(errno));
			continue;
		}

		for (i=0; i < numOfServices; i++)
		{
			if (!strncmp(dwpalService[i].interfaceType, "hostap", 7))
			{
				if (dwpalService[i].fd > 0)
				{
					if (FD_ISSET(dwpalService[i].fd, &rfds))
					{
						/*PRINT_DEBUG("%s; event received; interfaceType= '%s', radioName= '%s', serviceName= '%s'\n",
						       __FUNCTION__, dwpalService[i].interfaceType, dwpalService[i].radioName, dwpalService[i].serviceName);*/

						isTimerExpired = false;

						msg = (char *)malloc((size_t)(HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char)));
						if (msg == NULL)
						{
							PRINT_ERROR("%s; invalid input ('msg') parameter ==> cont...\n", __FUNCTION__);
							continue;
						}

						memset(msg, 0, HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char));  /* Clear the output buffer */
						memset(opCode, 0, sizeof(opCode));
						msgLen = HOSTAPD_TO_DWPAL_MSG_LENGTH - 1;  //was "msgLen = HOSTAPD_TO_DWPAL_MSG_LENGTH;"

						if (dwpal_hostap_event_get(context[i], msg /*OUT*/, &msgLen /*IN/OUT*/, opCode /*OUT*/) == DWPAL_FAILURE)
						{
							PRINT_ERROR("%s; dwpal_hostap_event_get ERROR; radioName= '%s', serviceName= '%s', msgLen= %d\n",
							       __FUNCTION__, dwpalService[i].radioName, dwpalService[i].serviceName, msgLen);
						}
						else
						{
							//PRINT_DEBUG("%s; msgLen= %d, msg= '%s'\n", __FUNCTION__, msgLen, msg);
//strcpy(msg, "<3>AP-STA-CONNECTED wlan0 24:77:03:80:5d:90 SignalStrength=-49 SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108 HT_CAP=107E HT_MCS=FF FF FF 00 00 00 00 00 00 00 C2 01 01 00 00 00 VHT_CAP=03807122 VHT_MCS=FFFA 0000 FFFA 0000 btm_supported=1 nr_enabled=0 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 cell_capa=1 assoc_req=00003A01000A1B0E04606C722002E833000A1B0E0460C04331060200000E746573745F737369645F69736172010882848B960C12182432043048606C30140100000FAC040100000FAC040100000FAC020000DD070050F2020001002D1AEF1903FFFFFF00000000000000000000000000000018040109007F080000000000000040BF0CB059C103EAFF1C02EAFF1C02C70122");
//strcpy(msg, "<3>AP-STA-DISCONNECTED wlan0 14:d6:4d:ac:36:70");
//strcpy(opCode, "AP-STA-CONNECTED");

							msgStringLen = strnlen_s(msg, HOSTAPD_TO_DWPAL_MSG_LENGTH);
							//PRINT_DEBUG("%s; opCode= '%s', msg= '%s'\n", __FUNCTION__, opCode, msg);
							if (strncmp(opCode, "", 1))
							{
								dwpalService[i].hostapEventCallback(dwpalService[i].radioName, opCode, msg, msgStringLen);
							}
						}

						free((void *)msg);
					}
				}
			}
			else if (!strncmp(dwpalService[i].interfaceType, "Driver", 7))
			{
				if (dwpalService[i].fd > 0)
				{
					if (FD_ISSET(dwpalService[i].fd, &rfds))
					{
						/*PRINT_DEBUG("%s; event received; interfaceType= '%s', radioName= '%s', serviceName= '%s'\n",
						       __FUNCTION__, dwpalService[i].interfaceType, dwpalService[i].radioName, dwpalService[i].serviceName);*/

						isTimerExpired = false;

						if (dwpal_driver_nl_fd_get(context[i], &dwpalService[i].fd) == DWPAL_FAILURE)
						{
							/*PRINT_ERROR("%s; dwpal_driver_nl_fd_get returned error ==> cont. (serviceName= '%s', radioName= '%s')\n",
								   __FUNCTION__, dwpalService[i].serviceName, dwpalService[i].radioName);*/
							continue;
						}

						if (dwpal_driver_nl_msg_get(context[i], dwpalService[i].nlEventCallback) == DWPAL_FAILURE)
						{
							PRINT_ERROR("%s; dwpal_driver_nl_msg_get ERROR; serviceName= '%s'\n", __FUNCTION__, dwpalService[i].serviceName);
						}
					}
				}
			}
		}

		if (isTimerExpired)
		{
			//PRINT_DEBUG("%s; timer expired\n", __FUNCTION__);
			interfaceExistCheckAndRecover();
		}
	}

	return NULL;
}


static DWPAL_Ret listenerThreadCreate(void)
{
	int            ret;
	DWPAL_Ret      dwpalRet = DWPAL_SUCCESS;
	pthread_attr_t attr;
	size_t         stack_size = 4096;
	//void           *res;

	PRINT_DEBUG("%s Entry\n", __FUNCTION__);

	ret = pthread_attr_init(&attr);
	if (ret != 0)
	{
		PRINT_ERROR("%s; pthread_attr_init ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		return DWPAL_FAILURE;
	}

	ret = pthread_attr_setstacksize(&attr, stack_size);
	if (ret == -1)
	{
		PRINT_ERROR("%s; pthread_attr_setstacksize ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		dwpalRet = DWPAL_FAILURE;
	}

	if (dwpalRet == DWPAL_SUCCESS)
	{
		PRINT_DEBUG("%s; call pthread_create\n", __FUNCTION__);
		ret = pthread_create(&thread_id, &attr, &listenerThreadStart, NULL /*can be used to send params*/);
		if (ret != 0)
		{
			PRINT_ERROR("%s; pthread_create ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
			dwpalRet = DWPAL_FAILURE;
		}
		PRINT_DEBUG("%s; return from call pthread_create, ret= %d\n", __FUNCTION__, ret);

		if (dwpalRet == DWPAL_SUCCESS)
		{
#if 0
			/* Causing the thread to be joined with the main process;
			   meaning, the process will suspend due to the thread suspend.
			   Otherwise, when process ends, the thread ends as well (although it is suspended and waiting ) */
			ret = pthread_join(thread_id, &res);
			if (ret != 0)
			{
				PRINT_ERROR("%s; pthread_join ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
				dwpalRet = DWPAL_FAILURE;
			}

			free(res);  /* Free memory allocated by thread */
#endif
		}
	}

	/* Destroy the thread attributes object, since it is no longer needed */
	ret = pthread_attr_destroy(&attr);
	if (ret != 0)
	{
		PRINT_ERROR("%s; pthread_attr_destroy ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		dwpalRet = DWPAL_FAILURE;
	}

	return dwpalRet;
}


DWPAL_Ret dwpal_ext_driver_nl_cmd_send(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize)
{
	int i, idx;

	PRINT_DEBUG("%s; ifname= '%s', nl80211Command= 0x%x, cmdIdType= %d, subCommand= 0x%x, vendorDataSize= %d\n", __FUNCTION__, ifname, nl80211Command, cmdIdType, subCommand, vendorDataSize);

	for (i=0; i < (int)vendorDataSize; i++)
	{
		PRINT_DEBUG("%s; vendorData[%d]= 0x%x\n", __FUNCTION__, i, vendorData[i]);
	}

	if (radioInterfaceIndexGet("Driver", "ALL", &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	return dwpal_driver_nl_cmd_send(context[idx],
	                                ifname,
	                                nl80211Command,
	                                cmdIdType,
	                                subCommand,
	                                vendorData,
	                                vendorDataSize);
}


DWPAL_Ret dwpal_ext_driver_nl_detach(void)
{
	int idx;

	if (radioInterfaceIndexGet("Driver", "ALL", &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (dwpal_driver_nl_detach(&context[idx]) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_driver_nl_detach returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	dwpalService[idx].nlEventCallback = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_driver_nl_attach(DwpalExtNlEventCallback nlEventCallback)
{
	int idx;

	if (nlEventCallback == NULL)
	{
		PRINT_ERROR("%s; nlEventCallback is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (radioInterfaceIndexGet("Driver", "ALL", &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (dwpal_driver_nl_attach(&context[idx] /*OUT*/) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_driver_nl_attach returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	dwpalService[idx].nlEventCallback = nlEventCallback;

	/* Create the listener thread, if it does NOT exist yet */
	if (thread_id == 0)
	{
		PRINT_DEBUG("%s; CALLING listenerThreadCreate()\n", __FUNCTION__);
		if (listenerThreadCreate() == DWPAL_FAILURE)
		{
			PRINT_ERROR("%s; listener thread failed ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
		}
		PRINT_DEBUG("%s; return from listenerThreadCreate()\n", __FUNCTION__);
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_cmd_send(char *radioName, char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply, size_t *replyLen)
{
	int idx;

	PRINT_DEBUG("%s; radioName= '%s', cmdHeader= '%s'\n", __FUNCTION__, radioName, cmdHeader);

	if (radioName == NULL)
	{
		PRINT_ERROR("%s; radioName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (radioInterfaceIndexGet("hostap", radioName, &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, radioName);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (context[idx] == NULL)
	{
		PRINT_ERROR("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	if (dwpalService[idx].isConnectionEstablishNeeded == true)
	{
		PRINT_ERROR("%s; interface is being reconnected, but still NOT ready ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	if (dwpal_hostap_cmd_send(context[idx], cmdHeader, fieldsToCmdParse, reply, replyLen) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; '%s' command send error\n", __FUNCTION__, cmdHeader);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_interface_detach(char *radioName)
{
	int idx;

	if (radioName == NULL)
	{
		PRINT_ERROR("%s; radioName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (radioInterfaceIndexGet("hostap", radioName, &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, radioName);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (context[idx] == NULL)
	{
		PRINT_ERROR("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	if (dwpal_hostap_interface_detach(&context[idx]) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_hostap_interface_detach (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, radioName);
		return DWPAL_FAILURE;
	}

	dwpalService[idx].fd = -1;
	dwpalService[idx].isConnectionEstablishNeeded = false;
	dwpalService[idx].hostapEventCallback = NULL;

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_interface_attach(char *radioName, DwpalExtHostapEventCallback hostapEventCallback)
{
	int idx;

	if (radioName == NULL)
	{
		PRINT_ERROR("%s; radioName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (hostapEventCallback == NULL)
	{
		PRINT_ERROR("%s; hostapEventCallback is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (radioInterfaceIndexGet("hostap", radioName, &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; radioInterfaceIndexGet (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, radioName);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; radioInterfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (dwpal_hostap_interface_attach(&context[idx] /*OUT*/, radioName, NULL /*use one-way interface*/) == DWPAL_FAILURE)
	{
		PRINT_DEBUG("%s; dwpal_hostap_interface_attach (radioName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, radioName);

		/* in this case, continue and try to establish the connection later on */
		dwpalService[idx].isConnectionEstablishNeeded = true;
	}

	dwpalService[idx].hostapEventCallback = hostapEventCallback;

	/* Create the listener thread, if it does NOT exist yet */
	if (thread_id == 0)
	{
		PRINT_DEBUG("%s; CALLING listenerThreadCreate()\n", __FUNCTION__);
		if (listenerThreadCreate() == DWPAL_FAILURE)
		{
			PRINT_ERROR("%s; listener thread failed ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
		}
		PRINT_DEBUG("%s; return from listenerThreadCreate()\n", __FUNCTION__);
	}

	return DWPAL_SUCCESS;
}
