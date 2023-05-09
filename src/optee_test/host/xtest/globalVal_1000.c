#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <global_variable_ta.h>
#include <ctx_variable_ta.h>
#include <instance_variable_ta.h>
#include <heap_param_ta.h>
#include <heap_param_pac_ta.h>

#include "xtest_test.h"
#include "xtest_helpers.h"
#include "xtest_uuid_helpers.h"

static uint8_t K[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x30
};	

static void xtest_globalVal_test_3001(ADBG_Case_t *c)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint32_t shared_key32;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_OpenSession(&ctx, &session, &global_variable_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);


	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_GLOBAL_VARIABLE_CMD_REGISTER_SHARED_KEY, &op, &ret_orig)))
		goto out;

	/* 2. Get 32 bits of the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_GLOBAL_VARIABLE_CMD_GET_SHARED_KEY, &op, &ret_orig)))
		goto out;

	shared_key32 = op.params[0].value.a;

	ADBG_EXPECT_COMPARE_SIGNED(c, shared_key32, ==, 0x34333231);
out:
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 3001, xtest_globalVal_test_3001,
		"Using Global Variables to Share Data");

static void xtest_globalVal_test_3002(ADBG_Case_t *c)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint32_t shared_key32;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_OpenSession(&ctx, &session, &ctx_variable_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);


	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_CTX_VARIABLE_CMD_REGISTER_SHARED_KEY, &op, &ret_orig)))
		goto out;

	/* 2. Get 32 bits of the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_CTX_VARIABLE_CMD_GET_SHARED_KEY, &op, &ret_orig)))
		goto out;

	shared_key32 = op.params[0].value.a;

	ADBG_EXPECT_COMPARE_SIGNED(c, shared_key32, ==, 0x34333231);
out:
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 3002, xtest_globalVal_test_3002,
		"Using Ctx Variables to Share Data");

static void xtest_globalVal_test_3003(ADBG_Case_t *c)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint32_t shared_key32;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_OpenSession(&ctx, &session, &instance_variable_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);


	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_INSTANCE_VARIABLE_CMD_REGISTER_SHARED_KEY, &op, &ret_orig)))
		goto out;

	/* 2. Get 32 bits of the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_INSTANCE_VARIABLE_CMD_GET_SHARED_KEY, &op, &ret_orig)))
		goto out;

	shared_key32 = op.params[0].value.a;

	ADBG_EXPECT_COMPARE_SIGNED(c, shared_key32, ==, 0x34333231);
out:
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 3003, xtest_globalVal_test_3003,
		"Using TEE_Get/SetInstanceData to Share Data");

static void xtest_globalVal_test_3004(ADBG_Case_t *c)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint32_t shared_key32;
	uint32_t heap_addr;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_OpenSession(&ctx, &session, &heap_param_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* 1. Alloc heap to store the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_CMD_ALLOC_HEAP, &op, &ret_orig)))
		goto out;
	
	heap_addr = op.params[0].value.a;

	/* 2. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;
	op.params[1].tmpref.buffer = K;
	op.params[1].tmpref.size = sizeof(K);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_CMD_WRITE_HEAP, &op, &ret_orig)))
		goto out;

	/* 3. Get 32 bits of the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_CMD_READ_HEAP, &op, &ret_orig)))
		goto out;

	shared_key32 = op.params[0].value.a;

	/* 4. Release the heap */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_CMD_RELEASE_HEAP, &op, &ret_orig)))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(c, shared_key32, ==, 0x34333231);
out:
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 3004, xtest_globalVal_test_3004,
		"Test Heap Address Without PAC");

static void xtest_globalVal_test_3005(ADBG_Case_t *c)
{
    TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint32_t shared_key32;
	uint32_t heap_addr;
	uint32_t heap_sign;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_OpenSession(&ctx, &session, &heap_param_pac_uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* 1. Alloc heap to store the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP, &op, &ret_orig)))
		goto out;
	
	heap_addr = op.params[0].value.a;
	heap_sign = op.params[0].value.b;

	/* 2. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;
	op.params[0].value.b = heap_sign;
	op.params[1].tmpref.buffer = K;
	op.params[1].tmpref.size = sizeof(K);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP, &op, &ret_orig)))
		goto out;

	/* 3. Get 32 bits of the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;
	op.params[0].value.b = heap_sign;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_PAC_CMD_READ_HEAP, &op, &ret_orig)))
		goto out;

	shared_key32 = op.params[1].value.a;

	/* 4. Release the heap */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = heap_addr;
	op.params[0].value.b = heap_sign;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP, &op, &ret_orig)))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(c, shared_key32, ==, 0x34333231);
out:
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 3005, xtest_globalVal_test_3005,
		"Test Heap Address With PAC");