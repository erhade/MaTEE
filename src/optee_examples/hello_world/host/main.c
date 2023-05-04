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
#include <unistd.h>
#include <time.h>
#include <pthread.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hello_world_ta.h>

#define BUFFER_SIZE    20

static long get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_REALTIME, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
	return 0;
}

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

static void *cancellation_thread(void *arg)
{
	uint64_t t;
	double x;
	struct timespec t0 = { };
	struct timespec t1 = { };
	/*
	 * Sleep 0.5 seconds before cancellation to make sure that the other
	 * thread is in RPC_WAIT.
	 */
	(void)usleep(500000);
	get_current_time(&t0);
	TEEC_RequestCancellation(arg);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	fprintf(stdout, "TEEC_RequestCancellation: %gus\n", x / 1000);
	return NULL;
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shm;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	uint32_t err_origin;
	int ret;

	uint64_t t;
	double x;
	struct timespec t0 = { };
	struct timespec t1 = { };

	pthread_t thr;
	memset(&thr, 0, sizeof(thr));

	/* Test TEEC_InitializeContext */
	get_current_time(&t0);
	res = TEEC_InitializeContext(NULL, &ctx);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	fprintf(stdout, "TEEC_InitializeContext: %gus\n", x / 1000);

	/* Test TEEC_OpenSession */
	get_current_time(&t0);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	fprintf(stdout, "TEEC_OpenSession: %gus\n", x / 1000);

	/* Test TEEC_RegisterSharedMemory */
	memset(&op, 0, sizeof(op));
	memset(&shm, 0, sizeof(shm));

	shm.buffer = malloc(BUFFER_SIZE);
	shm.size = BUFFER_SIZE;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	get_current_time(&t0);
	res = TEEC_RegisterSharedMemory(&ctx, &shm);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);
	fprintf(stdout, "TEEC_RegisterSharedMemory: %gus\n", x / 1000);

	/* Test TEEC_ReleaseSharedMemory */
	get_current_time(&t0);
	TEEC_ReleaseSharedMemory(&shm);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	fprintf(stdout, "TEEC_ReleaseSharedMemory: %gus\n", x / 1000);

	/* Test TEEC_AllocateSharedMemory */
	memset(&shm, 0, sizeof(shm));
	
	shm.size = BUFFER_SIZE;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	get_current_time(&t0);
	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x", res);
	fprintf(stdout, "TEEC_AllocateSharedMemory: %gus\n", x / 1000);

	TEEC_ReleaseSharedMemory(&shm);

	/* Test TEEC_InvokeCommand */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;

	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_INC_VALUE, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	fprintf(stdout, "TEEC_InvokeCommand: %gus\n", x / 1000);

	/* Test TEEC_RequestCancellation */
	memset(&op, 0, sizeof(op));
	op.session = &sess;
	op.started = 0;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 1000;

	if ((ret = pthread_create(&thr, NULL, cancellation_thread, &op)))
	{
        fprintf(stderr, "pthread_create: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
	}

	res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_TIME_WAIT, &op, &err_origin);
	if (res != TEEC_ERROR_CANCEL)
	{
		fprintf(stderr, "TEEC_InvokeCommand not be canceled\n");
        exit(EXIT_FAILURE);
	}

	if ((ret = pthread_join(thr, NULL)))
    {
        fprintf(stderr, "pthread_join: %s\n", strerror(ret));
        exit(EXIT_FAILURE);
    }

	/* Test TEEC_CloseSession */
	get_current_time(&t0);
	TEEC_CloseSession(&sess);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	fprintf(stdout, "TEEC_CloseSession: %gus\n", x / 1000);

	/* Test TEEC_FinalizeContext */
	get_current_time(&t0);
	TEEC_FinalizeContext(&ctx);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	fprintf(stdout, "TEEC_FinalizeContext: %gus\n", x / 1000);

	return 0;
}
