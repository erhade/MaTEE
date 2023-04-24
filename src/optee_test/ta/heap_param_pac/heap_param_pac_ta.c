/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <include/heap_param_pac_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

/* GP says that for HMAC SHA-1, max is 512 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */

struct key
{
	uint8_t K[MAX_KEY_SIZE];
	uint32_t K_len;
};

static TEE_Result alloc_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	struct key *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	params[0].value.a = state;

	return res;
}

static TEE_Result read_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	struct key *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = params[0].value.a;

	memcpy(&params[0].value.a, state->K, sizeof(params[0].value.a));

	return res;
}

static TEE_Result write_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	struct key *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = params[0].value.a;

	memset(state->K, 0, sizeof(state->K));
	memcpy(state->K, params[1].memref.buffer, params[1].memref.size);

	state->K_len = params[1].memref.size;

	return res;
}

static TEE_Result release_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Free((void *)params[0].value.a);

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
	case TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP:
		return alloc_heap(param_types, params);

	case TA_HEAP_PARAM_PAC_CMD_READ_HEAP:
		return read_heap(param_types, params);

	case TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP:
		return write_heap(param_types, params);

	case TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP:
		return release_heap(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
