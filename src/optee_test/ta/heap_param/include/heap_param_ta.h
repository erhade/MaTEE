/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __HEAP_PARAM_TA_H__
#define __HEAP_PARAM_TA_H__

#define TA_HEAP_PARAM_UUID \
	{ 0x30654317, 0xf844, 0x4355, \
		{ 0x8f, 0x76, 0x8c, 0x40, 0x4b, 0xcf, 0x10, 0xe2 } }

/* The function ID(s) implemented in this TA */
#define TA_HEAP_PARAM_CMD_ALLOC_HEAP	0
#define TA_HEAP_PARAM_CMD_READ_HEAP		1
#define TA_HEAP_PARAM_CMD_WRITE_HEAP	2
#define TA_HEAP_PARAM_CMD_RELEASE_HEAP	3

#endif
