/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2013-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef __DWPAL_LOG_H_
#define __DWPAL_LOG_H_

#if defined YOCTO
#include <help_logging.h>

//Log helper functions
#define PRINT_CRIT(...)  LOGF_LOG_CRITICAL(__VA_ARGS__)
#define PRINT_ERROR(...)  LOGF_LOG_ERROR(__VA_ARGS__)
#define PRINT_WARN(...)  LOGF_LOG_WARNING(__VA_ARGS__)
#define PRINT_INFO(...)  LOGF_LOG_INFO(__VA_ARGS__)
#define PRINT_DEBUG(...)  LOGF_LOG_DEBUG(__VA_ARGS__)
//END Log helper functions
#else
#define PRINT_DEBUG(...)  printf(__VA_ARGS__)
#define PRINT_ERROR(...)  printf(__VA_ARGS__)
#endif

#endif //__DWPAL_LOG_H_
