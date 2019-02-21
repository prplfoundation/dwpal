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


#define NUM_OF_SUPPORTED_VAPS 32


typedef enum
{
	THREAD_CANCEL =0,
	THREAD_CREATE
} DwpalThreadOperation;

typedef struct
{
	char                        interfaceType[DWPAL_INTERFACE_TYPE_STRING_LENGTH];
	char                        VAPName[DWPAL_VAP_NAME_STRING_LENGTH];
	int                         fd;
	bool                        isConnectionEstablishNeeded;
	DwpalExtHostapEventCallback hostapEventCallback;
	DwpalExtNlEventCallback     nlEventCallback;
} DwpalService;


static DwpalService *dwpalService[NUM_OF_SUPPORTED_VAPS + 1] = { [0 ... NUM_OF_SUPPORTED_VAPS ] = NULL };  /* add 1 place for NL */
static void *context[sizeof(dwpalService) / sizeof(DwpalService *)]= { [0 ... (sizeof(dwpalService) / sizeof(DwpalService *) - 1) ] = NULL };;


static DWPAL_Ret interfaceIndexGet(char *interfaceType, char *VAPName, int *idx)
{
	int    i;
	size_t numOfServices = sizeof(dwpalService) / sizeof(DwpalService *);

	*idx = 0;

	for (i=0; i < (int)numOfServices; i++)
	{
		if (dwpalService[i] == NULL)
			continue;

		if ( (!strncmp(interfaceType, dwpalService[i]->interfaceType, DWPAL_INTERFACE_TYPE_STRING_LENGTH)) &&
		     (!strncmp(VAPName, dwpalService[i]->VAPName, DWPAL_VAP_NAME_STRING_LENGTH)) )
		{
			*idx = i;
			return DWPAL_SUCCESS;
		}
	}

	return DWPAL_INTERFACE_IS_DOWN;
}


static DWPAL_Ret interfaceIndexCreate(char *interfaceType, char *VAPName, int *idx)
{
	int    i;
	size_t numOfServices = sizeof(dwpalService) / sizeof(DwpalService *);

	*idx = 0;

	if (interfaceIndexGet(interfaceType, VAPName, idx) == DWPAL_SUCCESS)
	{
		PRINT_ERROR("%s; the interface (interfaceType= '%s', VAPName= '%s') is already exist ==> Abort!\n",
		            __FUNCTION__, interfaceType, VAPName);
		return DWPAL_FAILURE;
	}

	/* Getting here means that the interface does NOT exist ==> create it! */
	for (i=0; i < (int)numOfServices; i++)
	{
		if (dwpalService[i] == NULL)
		{  /* First empty entry ==> use it */
			dwpalService[i] = (DwpalService *)malloc(sizeof(DwpalService));
			if (dwpalService[i] == NULL)
			{
				PRINT_ERROR("%s; malloc failed ==> Abort!\n", __FUNCTION__);
				return DWPAL_FAILURE;
			}

			STRCPY_S(dwpalService[i]->interfaceType, sizeof(dwpalService[i]->interfaceType), interfaceType);
			STRCPY_S(dwpalService[i]->VAPName, sizeof(dwpalService[i]->VAPName), VAPName);

			*idx = i;
			return DWPAL_SUCCESS;
		}
	}

	PRINT_ERROR("%s; number of interfaces (%d) reached its limit ==> Abort!\n", __FUNCTION__, i);

	return DWPAL_FAILURE;
}


static bool isAnyInterfaceActive(void)
{
	int i, numOfServices = sizeof(dwpalService) / sizeof(DwpalService *);;

	/* check if there are active interfaces */
	for (i=0; i < numOfServices; i++)
	{
		/* In case that there is a valid context, break! */
		if (context[i] != NULL)
		{
			return true;
		}
	}

	return false;
}


static void interfaceExistCheckAndRecover(void)
{
	int  i, numOfServices = sizeof(dwpalService) / sizeof(DwpalService *);
	bool isExist = false;

	//PRINT_DEBUG("%s Entry\n", __FUNCTION__);

	for (i=0; i < numOfServices; i++)
	{
		/* In case that there is no valid context, continue... */
		if (context[i] == NULL)
		{
			continue;
		}

		if (!strncmp(dwpalService[i]->interfaceType, "hostap", 7))
		{
			if (dwpalService[i]->fd > 0)
			{
				/* check if interface that should exist, still exists */
				if (dwpal_hostap_is_interface_exist(context[i], &isExist /*OUT*/) == DWPAL_FAILURE)
				{
					PRINT_ERROR("%s; dwpal_hostap_is_interface_exist for VAPName= '%s' error ==> cont...\n", __FUNCTION__, dwpalService[i]->VAPName);
					continue;
				}

				if (isExist == false)
				{  /* interface that should exist, does NOT exist */
					PRINT_ERROR("%s; VAPName= '%s' interface needs to be recovered\n", __FUNCTION__, dwpalService[i]->VAPName);
					dwpalService[i]->isConnectionEstablishNeeded = true;
					dwpalService[i]->fd = -1;

					/* note: dwpalService[i]->hostapEventCallback should be kept for usage after recovery */
				}
			}

			/* In case of recovery needed, try recover; in case of interface init, try to establish the connection */
			if (dwpalService[i]->isConnectionEstablishNeeded == true)
			{  /* try recovering the interface */
				//PRINT_DEBUG("%s; try recover - VAPName= '%s'\n", __FUNCTION__, dwpalService[i]->VAPName);
				if (dwpal_hostap_interface_attach(&context[i] /*OUT*/, dwpalService[i]->VAPName, NULL /*use one-way interface*/) == DWPAL_SUCCESS)
				{
					PRINT_DEBUG("%s; VAPName= '%s' interface recovered successfully!\n", __FUNCTION__, dwpalService[i]->VAPName);
					dwpalService[i]->isConnectionEstablishNeeded = false;
					dwpalService[i]->hostapEventCallback(dwpalService[i]->VAPName, "INTERFACE_RECONNECTED_OK", NULL, 0);
				}
				else
				{
					//PRINT_ERROR("%s; dwpal_hostap_interface_attach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, dwpalService[i]->VAPName);
				}
			}
		}
	}
}


static void *listenerThreadStart(void *temp)
{
	int     i, highestValFD, ret, numOfServices = sizeof(dwpalService) / sizeof(DwpalService *);
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

			if (!strncmp(dwpalService[i]->interfaceType, "hostap", 7))
			{
				if (dwpal_hostap_event_fd_get(context[i], &dwpalService[i]->fd) == DWPAL_FAILURE)
				{
					/*PRINT_ERROR("%s; dwpal_hostap_event_fd_get returned error ==> cont. (VAPName= '%s')\n",
					       __FUNCTION__, dwpalService[i]->VAPName);*/
					continue;
				}

				if (dwpalService[i]->fd > 0)
				{
					FD_SET(dwpalService[i]->fd, &rfds);
					highestValFD = (dwpalService[i]->fd > highestValFD)? dwpalService[i]->fd : highestValFD;  /* find the highest value fd */
				}
			}
			else if (!strncmp(dwpalService[i]->interfaceType, "Driver", 7))
			{
				if (dwpal_driver_nl_fd_get(context[i], &dwpalService[i]->fd) == DWPAL_FAILURE)
				{
					/*PRINT_ERROR("%s; dwpal_driver_nl_fd_get returned error ==> cont. (VAPName= '%s')\n",
					       __FUNCTION__, dwpalService[i].VAPName);*/
					continue;
				}

				if (dwpalService[i]->fd > 0)
				{
					FD_SET(dwpalService[i]->fd, &rfds);
					highestValFD = (dwpalService[i]->fd > highestValFD)? dwpalService[i]->fd : highestValFD;  /* find the highest value fd */
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
			/* In case that there is no valid context, continue... */
			if (context[i] == NULL)
			{
				continue;
			}

			if (!strncmp(dwpalService[i]->interfaceType, "hostap", 7))
			{
				if (dwpalService[i]->fd > 0)
				{
					if (FD_ISSET(dwpalService[i]->fd, &rfds))
					{
						/*PRINT_DEBUG("%s; event received; interfaceType= '%s', VAPName= '%s'\n",
						       __FUNCTION__, dwpalService[i]->interfaceType, dwpalService[i]->VAPName);*/

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
							PRINT_ERROR("%s; dwpal_hostap_event_get ERROR; VAPName= '%s', msgLen= %d\n",
							       __FUNCTION__, dwpalService[i]->VAPName, msgLen);
						}
						else
						{
							//PRINT_DEBUG("%s; msgLen= %d, msg= '%s'\n", __FUNCTION__, msgLen, msg);
//strcpy(msg, "<3>AP-STA-CONNECTED wlan0 24:77:03:80:5d:90 SignalStrength=-49 SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108 HT_CAP=107E HT_MCS=FF FF FF 00 00 00 00 00 00 00 C2 01 01 00 00 00 VHT_CAP=03807122 VHT_MCS=FFFA 0000 FFFA 0000 btm_supported=1 nr_enabled=0 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 cell_capa=1 assoc_req=00003A01000A1B0E04606C722002E833000A1B0E0460C04331060200000E746573745F737369645F69736172010882848B960C12182432043048606C30140100000FAC040100000FAC040100000FAC020000DD070050F2020001002D1AEF1903FFFFFF00000000000000000000000000000018040109007F080000000000000040BF0CB059C103EAFF1C02EAFF1C02C70122");
//strcpy(msg, "<3>AP-STA-DISCONNECTED wlan0 14:d6:4d:ac:36:70");
//strcpy(opCode, "AP-STA-CONNECTED");

							msgStringLen = STRNLEN_S(msg, HOSTAPD_TO_DWPAL_MSG_LENGTH);
							//PRINT_DEBUG("%s; opCode= '%s', msg= '%s'\n", __FUNCTION__, opCode, msg);
							if (strncmp(opCode, "", 1))
							{
								dwpalService[i]->hostapEventCallback(dwpalService[i]->VAPName, opCode, msg, msgStringLen);
							}
						}

						free((void *)msg);
					}
				}
			}
			else if (!strncmp(dwpalService[i]->interfaceType, "Driver", 7))
			{
				if (dwpalService[i]->fd > 0)
				{
					if (FD_ISSET(dwpalService[i]->fd, &rfds))
					{
						/*PRINT_DEBUG("%s; event received; interfaceType= '%s', VAPName= '%s'\n",
						       __FUNCTION__, dwpalService[i]->interfaceType, dwpalService[i]->VAPName);*/

						isTimerExpired = false;

						if (dwpal_driver_nl_fd_get(context[i], &dwpalService[i]->fd) == DWPAL_FAILURE)
						{
							/*PRINT_ERROR("%s; dwpal_driver_nl_fd_get returned error ==> cont. (VAPName= '%s')\n",
								   __FUNCTION__, dwpalService[i]->VAPName);*/
							continue;
						}

						if (dwpal_driver_nl_msg_get(context[i], dwpalService[i]->nlEventCallback) == DWPAL_FAILURE)
						{
							PRINT_ERROR("%s; dwpal_driver_nl_msg_get ERROR\n", __FUNCTION__);
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


static DWPAL_Ret listenerThreadCreate(pthread_t *thread_id)
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
		ret = pthread_create(thread_id, &attr, &listenerThreadStart, NULL /*can be used to send params*/);
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
			ret = pthread_join(*thread_id, &res);
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

	/* sleep for 100 ms - it is needed in case of a loop of thread create/cancel */
	usleep(100000 /*micro-sec*/);

	return dwpalRet;
}


static DWPAL_Ret listenerThreadSet(DwpalThreadOperation threadOperation)
{
	int ret;
	static pthread_t thread_id = (pthread_t)0;

	switch (threadOperation)
	{
		case THREAD_CREATE:
			if (thread_id == 0)
			{
				return listenerThreadCreate(&thread_id);
			}
			break;

		case THREAD_CANCEL:
			if (thread_id != 0)
			{
				if ( (ret = pthread_cancel(thread_id)) != 0 )
				{
					PRINT_ERROR("%s; pthread_attr_destroy ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
					return DWPAL_FAILURE;
				}

				thread_id = 0;
			}
			break;

		default:
			PRINT_ERROR("%s; threadOperation (%d) not supported ==> Abort!\n", __FUNCTION__, threadOperation);
			return DWPAL_FAILURE;
			break;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_driver_nl_cmd_send(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize)
{
	int i, idx;

	PRINT_DEBUG("%s; ifname= '%s', nl80211Command= 0x%x, cmdIdType= %d, subCommand= 0x%x, vendorDataSize= %d\n", __FUNCTION__, ifname, nl80211Command, cmdIdType, subCommand, vendorDataSize);

	for (i=0; i < (int)vendorDataSize; i++)
	{
		PRINT_DEBUG("%s; vendorData[%d]= 0x%x\n", __FUNCTION__, i, vendorData[i]);
	}

	if (interfaceIndexGet("Driver", "ALL", &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		PRINT_ERROR("%s; interfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	PRINT_DEBUG("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

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

	if (interfaceIndexGet("Driver", "ALL", &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		PRINT_ERROR("%s; interfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	PRINT_DEBUG("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	/* dealocate the interface */
	free((void *)dwpalService[idx]);
	dwpalService[idx] = NULL;

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_driver_nl_detach(&context[idx]) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_driver_nl_detach returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (isAnyInterfaceActive())
	{ /* There are still active interfaces */
		/* Create the listener thread, if it does NOT exist yet */
		listenerThreadSet(THREAD_CREATE);
	}

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

	if (interfaceIndexCreate("Driver", "ALL", &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; interfaceIndexCreate returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; interfaceIndexCreate returned idx= %d\n", __FUNCTION__, idx);

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_driver_nl_attach(&context[idx] /*OUT*/) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_driver_nl_attach returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	dwpalService[idx]->nlEventCallback = nlEventCallback;

	/* Create the listener thread, if it does NOT exist yet */
	listenerThreadSet(THREAD_CREATE);

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_cmd_send(char *VAPName, char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply /*OUT*/, size_t *replyLen /*IN/OUT*/)
{
	int idx;

	PRINT_DEBUG("%s; VAPName= '%s', cmdHeader= '%s'\n", __FUNCTION__, VAPName, cmdHeader);

	if (VAPName == NULL)
	{
		PRINT_ERROR("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexGet("hostap", VAPName, &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		PRINT_ERROR("%s; interfaceIndexGet (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	PRINT_DEBUG("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (context[idx] == NULL)
	{
		PRINT_ERROR("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	if (dwpalService[idx]->isConnectionEstablishNeeded == true)
	{
		PRINT_ERROR("%s; interface is being reconnected, but still NOT ready ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (dwpal_hostap_cmd_send(context[idx], cmdHeader, fieldsToCmdParse, reply, replyLen) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; '%s' command send error\n", __FUNCTION__, cmdHeader);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_interface_detach(char *VAPName)
{
	int idx;

	if (VAPName == NULL)
	{
		PRINT_ERROR("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexGet("hostap", VAPName, &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		PRINT_ERROR("%s; interfaceIndexGet (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	PRINT_DEBUG("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	/* dealocate the interface */
	free((void *)dwpalService[idx]);
	dwpalService[idx] = NULL;

	if (context[idx] == NULL)
	{
		PRINT_ERROR("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_hostap_interface_detach(&context[idx]) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; dwpal_hostap_interface_detach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_FAILURE;
	}

	if (isAnyInterfaceActive())
	{ /* There are still active interfaces */
		/* Create the listener thread, if it does NOT exist yet */
		listenerThreadSet(THREAD_CREATE);
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_interface_attach(char *VAPName, DwpalExtHostapEventCallback hostapEventCallback)
{
	int idx;

	if (VAPName == NULL)
	{
		PRINT_ERROR("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (hostapEventCallback == NULL)
	{
		PRINT_ERROR("%s; hostapEventCallback is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexCreate("hostap", VAPName, &idx) == DWPAL_FAILURE)
	{
		PRINT_ERROR("%s; interfaceIndexCreate (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_FAILURE;
	}

	PRINT_DEBUG("%s; interfaceIndexCreate returned idx= %d\n", __FUNCTION__, idx);

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_hostap_interface_attach(&context[idx] /*OUT*/, VAPName, NULL /*use one-way interface*/) == DWPAL_FAILURE)
	{
		PRINT_DEBUG("%s; dwpal_hostap_interface_attach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);

		/* in this case, continue and try to establish the connection later on */
		dwpalService[idx]->isConnectionEstablishNeeded = true;
	}
	else
	{
		dwpalService[idx]->isConnectionEstablishNeeded = false;
	}

	dwpalService[idx]->hostapEventCallback = hostapEventCallback;

	/* Create the listener thread, if it does NOT exist yet */
	listenerThreadSet(THREAD_CREATE);

	return DWPAL_SUCCESS;
}
