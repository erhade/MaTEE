/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <include/global_variable_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

/* GP says that for HMAC SHA-1, max is 512 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */

/*
 * Currently this only supports a single key, in the future this could be
 * updated to support multiple users, all with different unique keys (stored
 * using secure storage).
 */
static uint8_t K[MAX_KEY_SIZE];
static uint32_t K_len;

static TEE_Result register_shared_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > sizeof(K))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(K, 0, sizeof(K));
	memcpy(K, params[0].memref.buffer, params[0].memref.size);

	K_len = params[0].memref.size;

	return res;
}

static TEE_Result get_shared_key_32(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(&params[0].value.a, K, sizeof(params[0].value.a));

	return res;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_GLOBAL_VARIABLE_CMD_REGISTER_SHARED_KEY:
		return register_shared_key(param_types, params);

	case TA_GLOBAL_VARIABLE_CMD_GET_SHARED_KEY:
		return get_shared_key_32(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
