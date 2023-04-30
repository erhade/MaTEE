/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <ta_avb.h>

static long get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_REALTIME, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
	return 0;
}

#define TEST_OBJECT_SIZE	(4 * 1024)

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	uint64_t ns = 0;

	if (end->tv_nsec < start->tv_nsec) {
		ns += 1000000000 * (end->tv_sec - start->tv_sec - 1);
		ns += 1000000000 - start->tv_nsec + end->tv_nsec;
	} else {
		ns += 1000000000 * (end->tv_sec - start->tv_sec);
		ns += end->tv_nsec - start->tv_nsec;
	}
	return ns;
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_AVB_UUID;
	uint32_t err_origin;
	char obj_id[] = "object#1";
	char obj_data[TEST_OBJECT_SIZE];
	char read_data[TEST_OBJECT_SIZE];
	int i = 0;

	uint64_t t;
	double x;
	struct timespec t0 = { };
	struct timespec t1 = { };

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	/* rollback index slot */
	op.params[0].value.a = 0x1;
	/* upper 32 bits of rollback index */
 	op.params[1].value.a = 0xffffffff;
	/* lower 32 bits of rollback index */
	op.params[1].value.b = 0xffffffff;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_WRITE_ROLLBACK_INDEX, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	fprintf(stdout, "TA_AVB_CMD_WRITE_ROLLBACK_INDEX: %gus\n", x / 1000);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	/* rollback index slot */
	op.params[0].value.a = 0x1;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_READ_ROLLBACK_INDEX, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

    /* fprintf(stdout, "%02x %02x\n", op.params[1].value.a, op.params[1].value.b); */
	fprintf(stdout, "TA_AVB_CMD_READ_ROLLBACK_INDEX: %gus\n", x / 1000);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	/* lock state */
	op.params[0].value.a = 0x1;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_WRITE_LOCK_STATE, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	fprintf(stdout, "TA_AVB_CMD_WRITE_LOCK_STATE: %gus\n", x / 1000);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_READ_LOCK_STATE, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* fprintf(stdout, "lock state: 0x%x\n", op.params[0].value.a); */
	fprintf(stdout, "TA_AVB_CMD_READ_LOCK_STATE: %gus\n", x / 1000);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	memset(obj_data, 0xA1, sizeof(obj_data));
	
	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	/* lock state */
	op.params[0].tmpref.buffer = obj_id;
	op.params[0].tmpref.size = strlen(obj_id);
	op.params[1].tmpref.buffer = obj_data;
	op.params[1].tmpref.size = TEST_OBJECT_SIZE;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_WRITE_PERSIST_VALUE, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	fprintf(stdout, "TA_AVB_CMD_WRITE_PERSIST_VALUE: %gus\n", x / 1000);

		/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	memset(read_data, 0, sizeof(read_data));
	
	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INOUT,
					 TEEC_NONE, TEEC_NONE);
	/* lock state */
	op.params[0].tmpref.buffer = obj_id;
	op.params[0].tmpref.size = strlen(obj_id);
	op.params[1].tmpref.buffer = read_data;
	op.params[1].tmpref.size = TEST_OBJECT_SIZE;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_AVB_CMD_READ_PERSIST_VALUE, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* for (i = 0; i < op.params[1].tmpref.size; i++)
	{
		fprintf(stdout, "%02X ", read_data[i]);
	}
	fprintf(stdout, "\n"); */
	fprintf(stdout, "TA_AVB_CMD_READ_PERSIST_VALUE: %gus\n", x / 1000);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
