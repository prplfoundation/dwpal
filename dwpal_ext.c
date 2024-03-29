/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2013-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

/*  *****************************************************************************
 *         File Name    : dwpal_ext.c                             	            *
 *         Description  : D-WPAL Extender control interface 		            *
 *                                                                              *
 *  *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#if defined YOCTO
#include <slibc/string.h>
#else
#include "safe_str_lib.h"
#include "safe_mem_lib.h"
#endif

#include "dwpal_ext.h"
#include "dwpal_log.h"	//Logging

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
	int                         fd, fdCmdGet;
	bool                        isConnectionEstablishNeeded;
	DwpalExtHostapEventCallback hostapEventCallback;
	DwpalExtNlEventCallback     nlEventCallback, nlCmdGetCallback;
} DwpalService;


size_t        *getOutLen = NULL;
unsigned char *getOutData = NULL;

static DwpalService *dwpalService[NUM_OF_SUPPORTED_VAPS + 1] = { [0 ... NUM_OF_SUPPORTED_VAPS ] = NULL };  /* add 1 place for NL */
static void *context[sizeof(dwpalService) / sizeof(DwpalService *)]= { [0 ... (sizeof(dwpalService) / sizeof(DwpalService *) - 1) ] = NULL };;
static int dwpal_command_get_ended = (-1);


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
		console_printf("%s; the interface (interfaceType= '%s', VAPName= '%s') is already exist ==> Abort!\n",
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
				console_printf("%s; malloc failed ==> Abort!\n", __FUNCTION__);
				return DWPAL_FAILURE;
			}

			strcpy_s(dwpalService[i]->interfaceType, sizeof(dwpalService[i]->interfaceType), interfaceType);
			strcpy_s(dwpalService[i]->VAPName, sizeof(dwpalService[i]->VAPName), VAPName);

			*idx = i;
			return DWPAL_SUCCESS;
		}
	}

	console_printf("%s; number of interfaces (%d) reached its limit ==> Abort!\n", __FUNCTION__, i);

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

	//console_printf("%s Entry\n", __FUNCTION__);

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
					console_printf("%s; dwpal_hostap_is_interface_exist for VAPName= '%s' error ==> cont...\n", __FUNCTION__, dwpalService[i]->VAPName);
					continue;
				}

				if (isExist == false)
				{  /* interface that should exist, does NOT exist */
					console_printf("%s; VAPName= '%s' interface needs to be recovered\n", __FUNCTION__, dwpalService[i]->VAPName);
					dwpalService[i]->isConnectionEstablishNeeded = true;
					dwpalService[i]->fd = -1;

					/* note: dwpalService[i]->hostapEventCallback should be kept for usage after recovery */
				}
			}

			/* In case of recovery needed, try recover; in case of interface init, try to establish the connection */
			if (dwpalService[i]->isConnectionEstablishNeeded == true)
			{  /* try recovering the interface */
				//console_printf("%s; try recover - VAPName= '%s'\n", __FUNCTION__, dwpalService[i]->VAPName);
				if (dwpal_hostap_interface_attach(&context[i] /*OUT*/, dwpalService[i]->VAPName, NULL /*use one-way interface*/) == DWPAL_SUCCESS)
				{
					console_printf("%s; VAPName= '%s' interface recovered successfully!\n", __FUNCTION__, dwpalService[i]->VAPName);
					dwpalService[i]->isConnectionEstablishNeeded = false;
					dwpalService[i]->hostapEventCallback(dwpalService[i]->VAPName, "INTERFACE_RECONNECTED_OK", NULL, 0);
				}
				else
				{
					//console_printf("%s; dwpal_hostap_interface_attach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, dwpalService[i]->VAPName);
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

	console_printf("%s Entry\n", __FUNCTION__);

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
					/*console_printf("%s; dwpal_hostap_event_fd_get returned error ==> cont. (VAPName= '%s')\n",
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
				if (dwpal_driver_nl_fd_get(context[i], &dwpalService[i]->fd, &dwpalService[i]->fdCmdGet) == DWPAL_FAILURE)
				{
					/*console_printf("%s; dwpal_driver_nl_fd_get returned error ==> cont. (VAPName= '%s')\n",
					       __FUNCTION__, dwpalService[i].VAPName);*/
					continue;
				}

				if (dwpalService[i]->fd > 0)
				{
					FD_SET(dwpalService[i]->fd, &rfds);
					highestValFD = (dwpalService[i]->fd > highestValFD)? dwpalService[i]->fd : highestValFD;  /* find the highest value fd */
				}

				if (dwpalService[i]->fdCmdGet > 0)
				{
					FD_SET(dwpalService[i]->fdCmdGet, &rfds);
					highestValFD = (dwpalService[i]->fdCmdGet > highestValFD)? dwpalService[i]->fdCmdGet : highestValFD;  /* find the highest value fd */
				}
			}
		}

		//console_printf("%s; highestValFD= %d\n", __FUNCTION__, highestValFD);

		/* Interval of time in which the select() will be released */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		isTimerExpired = true;

		/* In case that no active hostap is available, highestValFD is '0' and we'll loop out according to tv values */
		ret = select(highestValFD + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0)
		{
			console_printf("%s; select() return value= %d ==> cont...; errno= %d ('%s')\n", __FUNCTION__, ret, errno, strerror(errno));
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
						/*console_printf("%s; event received; interfaceType= '%s', VAPName= '%s'\n",
						       __FUNCTION__, dwpalService[i]->interfaceType, dwpalService[i]->VAPName);*/

						isTimerExpired = false;

						msg = (char *)malloc((size_t)(HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char)));
						if (msg == NULL)
						{
							console_printf("%s; invalid input ('msg') parameter ==> cont...\n", __FUNCTION__);
							continue;
						}

						memset(msg, 0, HOSTAPD_TO_DWPAL_MSG_LENGTH * sizeof(char));  /* Clear the output buffer */
						memset(opCode, 0, sizeof(opCode));
						msgLen = HOSTAPD_TO_DWPAL_MSG_LENGTH - 1;  //was "msgLen = HOSTAPD_TO_DWPAL_MSG_LENGTH;"

						if (dwpal_hostap_event_get(context[i], msg /*OUT*/, &msgLen /*IN/OUT*/, opCode /*OUT*/) == DWPAL_FAILURE)
						{
							console_printf("%s; dwpal_hostap_event_get ERROR; VAPName= '%s', msgLen= %d\n",
							       __FUNCTION__, dwpalService[i]->VAPName, msgLen);
						}
						else
						{
							//console_printf("%s; msgLen= %d, msg= '%s'\n", __FUNCTION__, msgLen, msg);
//strcpy(msg, "<3>AP-STA-CONNECTED wlan0 24:77:03:80:5d:90 SignalStrength=-49 SupportedRates=2 4 11 22 12 18 24 36 48 72 96 108 HT_CAP=107E HT_MCS=FF FF FF 00 00 00 00 00 00 00 C2 01 01 00 00 00 VHT_CAP=03807122 VHT_MCS=FFFA 0000 FFFA 0000 btm_supported=1 nr_enabled=0 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:9 non_pref_chan=81:200:1:7 non_pref_chan=81:100:2:5 cell_capa=1 assoc_req=00003A01000A1B0E04606C722002E833000A1B0E0460C04331060200000E746573745F737369645F69736172010882848B960C12182432043048606C30140100000FAC040100000FAC040100000FAC020000DD070050F2020001002D1AEF1903FFFFFF00000000000000000000000000000018040109007F080000000000000040BF0CB059C103EAFF1C02EAFF1C02C70122");
//strcpy(msg, "<3>AP-STA-DISCONNECTED wlan0 14:d6:4d:ac:36:70");
//strcpy(opCode, "AP-STA-CONNECTED");

							msgStringLen = strnlen_s(msg, HOSTAPD_TO_DWPAL_MSG_LENGTH);
							//console_printf("%s; opCode= '%s', msg= '%s'\n", __FUNCTION__, opCode, msg);
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
				if ( (dwpalService[i]->fd > 0) && (FD_ISSET(dwpalService[i]->fd, &rfds)) )
				{
					console_printf("%s; event received; interfaceType= '%s', VAPName= '%s'\n",
						   __FUNCTION__, dwpalService[i]->interfaceType, dwpalService[i]->VAPName);

					isTimerExpired = false;

					if (dwpal_driver_nl_msg_get(context[i], DWPAL_NL_EVENT_GET, dwpalService[i]->nlEventCallback) == DWPAL_FAILURE)
					{
						console_printf("%s; dwpal_driver_nl_msg_get ERROR\n", __FUNCTION__);
					}
				}
				else if ( (dwpalService[i]->fdCmdGet > 0) && (FD_ISSET(dwpalService[i]->fdCmdGet, &rfds)) )
				{
					console_printf("%s; 'get command' event received; interfaceType= '%s', VAPName= '%s'\n",
						   __FUNCTION__, dwpalService[i]->interfaceType, dwpalService[i]->VAPName);

					isTimerExpired = false;

					if (dwpal_driver_nl_msg_get(context[i], DWPAL_NL_CMD_GET, dwpalService[i]->nlCmdGetCallback) == DWPAL_FAILURE)
					{
						console_printf("%s; dwpal_driver_nl_msg_get ERROR\n", __FUNCTION__);
					}
				}
			}
		}

		if (isTimerExpired)
		{
			//console_printf("%s; timer expired\n", __FUNCTION__);
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

	console_printf("%s Entry\n", __FUNCTION__);

	ret = pthread_attr_init(&attr);
	if (ret != 0)
	{
		console_printf("%s; pthread_attr_init ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		return DWPAL_FAILURE;
	}

	ret = pthread_attr_setstacksize(&attr, stack_size);
	if (ret == -1)
	{
		console_printf("%s; pthread_attr_setstacksize ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
		dwpalRet = DWPAL_FAILURE;
	}

	if (dwpalRet == DWPAL_SUCCESS)
	{
		console_printf("%s; call pthread_create\n", __FUNCTION__);
		ret = pthread_create(thread_id, &attr, &listenerThreadStart, NULL /*can be used to send params*/);
		if (ret != 0)
		{
			console_printf("%s; pthread_create ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
			dwpalRet = DWPAL_FAILURE;
		}
		console_printf("%s; return from call pthread_create, ret= %d\n", __FUNCTION__, ret);

		if (dwpalRet == DWPAL_SUCCESS)
		{
#if 0
			/* Causing the thread to be joined with the main process;
			   meaning, the process will suspend due to the thread suspend.
			   Otherwise, when process ends, the thread ends as well (although it is suspended and waiting ) */
			ret = pthread_join(*thread_id, &res);
			if (ret != 0)
			{
				console_printf("%s; pthread_join ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
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
		console_printf("%s; pthread_attr_destroy ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
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
					console_printf("%s; pthread_attr_destroy ERROR (ret= %d) ==> Abort!\n", __FUNCTION__, ret);
					return DWPAL_FAILURE;
				}

				thread_id = 0;
			}
			break;

		default:
			console_printf("%s; threadOperation (%d) not supported ==> Abort!\n", __FUNCTION__, threadOperation);
			return DWPAL_FAILURE;
			break;
	}

	return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_command_get_ended_socket_wait(bool *isReceived)
{
	int    res;
	fd_set rfds;
	struct timeval tv;

	*isReceived = false;

	if (dwpal_command_get_ended <= 0)
	{
		console_printf("%s; dwpal_command_get_ended= %d ==> Abort!\n", __FUNCTION__, dwpal_command_get_ended);
		return DWPAL_FAILURE;
	}

	/* Receive the msg */
	while (1)
	{
		FD_ZERO(&rfds);
		FD_SET(dwpal_command_get_ended, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		res = select(dwpal_command_get_ended + 1, &rfds, NULL, NULL, &tv);
		if (res < 0)
		{
			console_printf("%s; select() return value= %d ==> cont...; errno= %d ('%s') ==> expected behavior when 'Interrupted system call'\n", __FUNCTION__, res, errno, strerror(errno));
			continue;
		}

		if (FD_ISSET(dwpal_command_get_ended, &rfds))
		{  /* the select() was triggered due to the above daemon fd */
			console_printf("%s; right event indication received ==> break\n", __FUNCTION__);
			*isReceived = true;
			break;
		}

		console_printf("%s; the right event indication was NOT received ==> break\n", __FUNCTION__);
		break;
	}

	return DWPAL_SUCCESS;
}


static int fdDaemonSet(char *socketName, int *fd /* output param */)
{
	struct sockaddr_un un;
	size_t len;

	if ((*fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		console_printf("%s; create socket fail; socketName= '%s'; errno= %d ('%s')\n", __FUNCTION__, socketName, errno, strerror(errno));
		return DWPAL_FAILURE;
    }

	console_printf("%s; fd_daemon (socketName='%s') = %d\n", __FUNCTION__, socketName, *fd);

	unlink(socketName);   /* in case it already exists */

    /* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy_s(un.sun_path, sizeof(un.sun_path) - 1, socketName);
	len = offsetof(struct sockaddr_un, sun_path) + strnlen_s(socketName, SOCKET_NAME_LENGTH);

    /* bind the name to the descriptor */
	if (bind(*fd, (struct sockaddr *)&un, len) < 0)  // check if can use connect() instead...
	{
		console_printf("%s; bind() fail; errno= %d ('%s')\n", __FUNCTION__, errno, strerror(errno));

		if (close(*fd) == (-1))
		{
			console_printf("%s; close() fail; errno= %d ('%s')\n", __FUNCTION__, errno, strerror(errno));
		}

		return DWPAL_FAILURE;
    }

	if (chmod(socketName, 0666) < 0)
	{
		console_printf("%s; FAIL to chmod '%s' to 0666\n", __FUNCTION__, socketName);

		if (close(*fd) == (-1))
		{
			console_printf("%s; close() fail; errno= %d ('%s')\n", __FUNCTION__, errno, strerror(errno));
		}

		return DWPAL_FAILURE;
    }

	if (listen(*fd, 10 /*Q Length*/) < 0)
	{ /* tell kernel we're a server */
		console_printf("%s; listen fail\n", __FUNCTION__);

		if (close(*fd) == (-1))
		{
			console_printf("%s; close() fail; errno= %d ('%s')\n", __FUNCTION__, errno, strerror(errno));
		}

		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


static DWPAL_Ret dwpal_command_get_ended_socket_create(void)
{
	pid_t pid = getpid();
	char  socketName[SOCKET_NAME_LENGTH] = "\0";

	snprintf(socketName, sizeof(socketName) - 1, "%s_%d", COMMAND_ENDED_SOCKET, pid);

	if (dwpal_command_get_ended > 0)
	{
		console_printf("%s; dwpal_command_get_ended (%d) ==> cont...\n", __FUNCTION__, dwpal_command_get_ended);
		return DWPAL_SUCCESS;
	}

	if (fdDaemonSet(socketName, &dwpal_command_get_ended /*output*/) == DWPAL_FAILURE)
	{
		console_printf("%s; ERROR; dwpal_command_get_ended= %d\n", __FUNCTION__, dwpal_command_get_ended);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


static DWPAL_Ret nlCmdGetCallback(char *ifname, int event, int subevent, size_t len, unsigned char *data)
{
	console_printf("%s Entry; ifname= '%s', event= %d, subevent= %d (len= %d)\n", __FUNCTION__, ifname, event, subevent, len);

	memcpy_s((void *)getOutData, (rsize_t)len, (void *)data, (rsize_t)len);
	*getOutLen = (size_t)len;

	{
		int i;
		size_t lenToPrint = (*getOutLen <= 10)? *getOutLen : 10;

		console_printf("%s; Output data from the 'get' function:\n", __FUNCTION__);
		for (i=0; i < (int)lenToPrint; i++)
		{
			console_printf(" 0x%x", getOutData[i]);
		}
		console_printf("\n");
	}

	return DWPAL_SUCCESS;
}


static DWPAL_Ret nl_cmd_handle(char *ifname,
                               unsigned int nl80211Command,
							   CmdIdType cmdIdType,
							   unsigned int subCommand,
							   unsigned char *vendorData,
							   size_t vendorDataSize,
							   size_t *outLen,
							   unsigned char *outData)
{
	int    i, idx, ret;
	bool   isReceived = false;

	console_printf("%s; ifname= '%s', nl80211Command= 0x%x, cmdIdType= %d, subCommand= 0x%x, vendorDataSize= %d, outLen= 0x%x, outData= 0x%x\n",
	            __FUNCTION__, ifname, nl80211Command, cmdIdType, subCommand, vendorDataSize, (unsigned int)outLen, (unsigned int)outData);

	for (i=0; i < (int)vendorDataSize; i++)
	{
		console_printf("%s; vendorData[%d]= 0x%x\n", __FUNCTION__, i, vendorData[i]);
	}

	if (interfaceIndexGet("Driver", "ALL", &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		console_printf("%s; interfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	console_printf("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if ( (outLen != NULL) && (outData != NULL) )
	{
		/* Handle a command which invokes an event with the output data */
		getOutLen = outLen;
		getOutData = outData;

		ret = dwpal_driver_nl_cmd_send(context[idx],
									   DWPAL_NL_CMD_GET,
									   ifname,
									   nl80211Command,
									   cmdIdType,
									   subCommand,
									   vendorData,
									   vendorDataSize);
		if (ret == DWPAL_FAILURE)
		{
			console_printf("%s; dwpal_driver_nl_cmd_send returned ERROR ==> Abort!\n", __FUNCTION__);
			return DWPAL_FAILURE;
		}

		dwpal_command_get_ended_socket_wait(&isReceived);
		if (isReceived == false)
		{
			console_printf("%s; 'get command' (subCommand= 0x%x) was NOT received ==> Abort!\n", __FUNCTION__, subCommand);
			*outLen = 0;
			return DWPAL_FAILURE;
		}

		return DWPAL_SUCCESS;
	}
	else
	{
		getOutLen = NULL;
		getOutData = NULL;

		return dwpal_driver_nl_cmd_send(context[idx],
										DWPAL_NL_EVENT_GET,
										ifname,
										nl80211Command,
										cmdIdType,
										subCommand,
										vendorData,
										vendorDataSize);
	}
}


/* APIs */

DWPAL_Ret dwpal_ext_driver_nl_get(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize, size_t *outLen, unsigned char *outData)
{
	console_printf("%s; ifname= '%s', nl80211Command= 0x%x, cmdIdType= %d, subCommand= 0x%x\n", __FUNCTION__, ifname, nl80211Command, cmdIdType, subCommand);

	return nl_cmd_handle(ifname, nl80211Command, cmdIdType, subCommand, vendorData, vendorDataSize, outLen, outData);
}


DWPAL_Ret dwpal_ext_driver_nl_cmd_send(char *ifname, unsigned int nl80211Command, CmdIdType cmdIdType, unsigned int subCommand, unsigned char *vendorData, size_t vendorDataSize)
{
	console_printf("%s; ifname= '%s', nl80211Command= 0x%x, cmdIdType= %d, subCommand= 0x%x, vendorDataSize= %d\n", __FUNCTION__, ifname, nl80211Command, cmdIdType, subCommand, vendorDataSize);

	return nl_cmd_handle(ifname, nl80211Command, cmdIdType, subCommand, vendorData, vendorDataSize, NULL, NULL);
}


DWPAL_Ret dwpal_ext_driver_nl_detach(void)
{
	int idx;

	if (dwpal_command_get_ended != (-1))
	{
		pid_t pid = getpid();
		char  socketName[SOCKET_NAME_LENGTH] = "\0";

		snprintf(socketName, sizeof(socketName) - 1, "%s_%d", COMMAND_ENDED_SOCKET, pid);

		if (close(dwpal_command_get_ended) == (-1))
		{
			console_printf("%s; close() fail; dwpal_command_get_ended= %d; errno= %d ('%s')\n", __FUNCTION__, dwpal_command_get_ended, errno, strerror(errno));
		}

		unlink(socketName);
		dwpal_command_get_ended = (-1);
	}

	if (interfaceIndexGet("Driver", "ALL", &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		console_printf("%s; interfaceIndexGet returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	console_printf("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	/* dealocate the interface */
	free((void *)dwpalService[idx]);
	dwpalService[idx] = NULL;

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_driver_nl_detach(&context[idx]) == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_driver_nl_detach returned ERROR ==> Abort!\n", __FUNCTION__);
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
		console_printf("%s; nlEventCallback is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexCreate("Driver", "ALL", &idx) == DWPAL_FAILURE)
	{
		console_printf("%s; interfaceIndexCreate returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	console_printf("%s; interfaceIndexCreate returned idx= %d\n", __FUNCTION__, idx);

	if (dwpal_command_get_ended_socket_create() == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_command_get_ended_socket_create returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_driver_nl_attach(&context[idx] /*OUT*/) == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_driver_nl_attach returned ERROR ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	dwpalService[idx]->nlEventCallback = nlEventCallback;

	/* Register here the internal static callback function of the 'get command' event */
	dwpalService[idx]->nlCmdGetCallback = nlCmdGetCallback;

	/* Create the listener thread, if it does NOT exist yet */
	listenerThreadSet(THREAD_CREATE);

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_cmd_send(char *VAPName, char *cmdHeader, FieldsToCmdParse *fieldsToCmdParse, char *reply /*OUT*/, size_t *replyLen /*IN/OUT*/)
{
	int idx;

	console_printf("%s; VAPName= '%s', cmdHeader= '%s'\n", __FUNCTION__, VAPName, cmdHeader);

	if (VAPName == NULL)
	{
		console_printf("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexGet("hostap", VAPName, &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		console_printf("%s; interfaceIndexGet (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	console_printf("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	if (context[idx] == NULL)
	{
		console_printf("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	if (dwpalService[idx]->isConnectionEstablishNeeded == true)
	{
		console_printf("%s; interface is being reconnected, but still NOT ready ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (dwpal_hostap_cmd_send(context[idx], cmdHeader, fieldsToCmdParse, reply, replyLen) == DWPAL_FAILURE)
	{
		console_printf("%s; '%s' command send error\n", __FUNCTION__, cmdHeader);
		return DWPAL_FAILURE;
	}

	return DWPAL_SUCCESS;
}


DWPAL_Ret dwpal_ext_hostap_interface_detach(char *VAPName)
{
	int idx;

	if (VAPName == NULL)
	{
		console_printf("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexGet("hostap", VAPName, &idx) == DWPAL_INTERFACE_IS_DOWN)
	{
		console_printf("%s; interfaceIndexGet (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_INTERFACE_IS_DOWN;
	}

	console_printf("%s; interfaceIndexGet returned idx= %d\n", __FUNCTION__, idx);

	/* dealocate the interface */
	free((void *)dwpalService[idx]);
	dwpalService[idx] = NULL;

	if (context[idx] == NULL)
	{
		console_printf("%s; context[%d] is NULL ==> Abort!\n", __FUNCTION__, idx);
		return DWPAL_FAILURE;
	}

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_hostap_interface_detach(&context[idx]) == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_hostap_interface_detach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
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
		console_printf("%s; VAPName is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (hostapEventCallback == NULL)
	{
		console_printf("%s; hostapEventCallback is NULL ==> Abort!\n", __FUNCTION__);
		return DWPAL_FAILURE;
	}

	if (interfaceIndexCreate("hostap", VAPName, &idx) == DWPAL_FAILURE)
	{
		console_printf("%s; interfaceIndexCreate (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);
		return DWPAL_FAILURE;
	}

	console_printf("%s; interfaceIndexCreate returned idx= %d\n", __FUNCTION__, idx);

	/* Cancel the listener thread, if it does exist */
	listenerThreadSet(THREAD_CANCEL);

	if (dwpal_hostap_interface_attach(&context[idx] /*OUT*/, VAPName, NULL /*use one-way interface*/) == DWPAL_FAILURE)
	{
		console_printf("%s; dwpal_hostap_interface_attach (VAPName= '%s') returned ERROR ==> Abort!\n", __FUNCTION__, VAPName);

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
