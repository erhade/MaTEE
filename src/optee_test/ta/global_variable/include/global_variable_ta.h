/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __GLOBAL_VARIABLE_TA_H__
#define __GLOBAL_VARIABLE_TA_H__

#define TA_GLOBAL_VARIABLE_UUID \
	{ 0x9bc692b2, 0x52f0, 0x4407, \
		{ 0xbd, 0x77, 0xac, 0xf2, 0xc3, 0x98, 0x78, 0x65 } }

/* The function ID(s) implemented in this TA */
#define TA_GLOBAL_VARIABLE_CMD_REGISTER_SHARED_KEY	0
#define TA_GLOBAL_VARIABLE_CMD_GET_SHARED_KEY		1

#endif
