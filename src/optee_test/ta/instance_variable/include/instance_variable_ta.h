/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __INSTANCE_VARIABLE_TA_H__
#define __INSTANCE_VARIABLE_TA_H__

#define TA_INSTANCE_VARIABLE_UUID \
	{ 0x5713f3c1, 0x0361, 0x4c8c, \
		{ 0x94, 0x61, 0xb4, 0xb4, 0xa6, 0xc4, 0x41, 0x1b } }

/* The function ID(s) implemented in this TA */
#define TA_INSTANCE_VARIABLE_CMD_REGISTER_SHARED_KEY	0
#define TA_INSTANCE_VARIABLE_CMD_GET_SHARED_KEY		1

#endif
