/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __CTX_VARIABLE_TA_H__
#define __CTX_VARIABLE_TA_H__

#define TA_CTX_VARIABLE_UUID \
	{ 0x6917e1e7, 0x570f, 0x41e3, \
		{ 0xa7, 0x24, 0x7b, 0xfc, 0x6c, 0x19, 0x79, 0x10 } }

/* The function ID(s) implemented in this TA */
#define TA_CTX_VARIABLE_CMD_REGISTER_SHARED_KEY	0
#define TA_CTX_VARIABLE_CMD_GET_SHARED_KEY		1

#endif
