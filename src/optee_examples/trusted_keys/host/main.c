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
#include <trusted_keys.h>

#define IV_SIZE			16
#define TAG_SIZE		16

/*
 * Acronym:
 *
 * TK - Trusted Key
 */

struct tk_blob_hdr {
	uint8_t reserved;
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
	uint8_t enc_key[];
};

#define KEY_SIZE	128
#define SEAL_KEY_SIZE	(KEY_SIZE + sizeof(struct tk_blob_hdr))

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

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shm;
	TEEC_UUID uuid = TRUSTED_KEYS_UUID;
	uint32_t err_origin;
	int i = 0;
	uint8_t *key_byte = NULL;
	uint8_t seal_key[SEAL_KEY_SIZE];
	uint8_t unseal_key[KEY_SIZE];

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
	memset(&shm, 0, sizeof(shm));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */

	key_byte = malloc(KEY_SIZE);
	shm.buffer = key_byte;
	shm.size = KEY_SIZE;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;


	res = TEEC_RegisterSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = KEY_SIZE;
	op.params[0].memref.offset = 0;

	/*
	 * TA_CMD_GET_RANDOM is the actual function in the TA to be
	 * called.
	 */
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_CMD_GET_RANDOM, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* for (i = 0; i < KEY_SIZE; i++) {
        fprintf(stdout, "%02x ", key_byte[i]);
    }
	fprintf(stdout, "\n"); */
	fprintf(stdout, "TA_CMD_GET_RANDOM: %gus\n", x / 1000);


	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, 
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = KEY_SIZE;
	op.params[0].memref.offset = 0;

	op.params[1].tmpref.buffer = seal_key;
	op.params[1].tmpref.size = SEAL_KEY_SIZE;

	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_CMD_SEAL, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* for (i = 0; i < SEAL_KEY_SIZE; i++) {
        fprintf(stdout, "%02x ", seal_key[i]);
    }
	fprintf(stdout, "\n"); */
	fprintf(stdout, "TA_CMD_SEAL: %gus\n", x / 1000);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = seal_key;
	op.params[0].tmpref.size = SEAL_KEY_SIZE;

	op.params[1].tmpref.buffer = unseal_key;
	op.params[1].tmpref.size = KEY_SIZE;

	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_CMD_UNSEAL, &op,
				 &err_origin);
	get_current_time(&t1);
	t = timespec_diff_ns(&t0, &t1);
	x = (double)t;
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* for (i = 0; i < KEY_SIZE; i++) {
        fprintf(stdout, "%02x ", unseal_key[i]);
    }
	fprintf(stdout, "\n"); */
	fprintf(stdout, "TA_CMD_UNSEAL: %gus\n", x / 1000);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 */

	TEEC_ReleaseSharedMemory(&shm);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
