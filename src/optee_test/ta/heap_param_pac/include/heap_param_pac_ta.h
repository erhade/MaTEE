/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __HEAP_PARAM_PAC_TA_H__
#define __HEAP_PARAM_PAC_TA_H__

#define TA_HEAP_PARAM_PAC_UUID \
	{ 0xc3098aa8, 0x0a7c, 0x4931, \
		{ 0x98, 0xe4, 0x1a, 0x88, 0x7a, 0x3e, 0xc4, 0xe4 } }

/* The function ID(s) implemented in this TA */
#define TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP	0
#define TA_HEAP_PARAM_PAC_CMD_READ_HEAP		1
#define TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP	2
#define TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP	3

#endif
