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
#include <sys/ipc.h>
#include <sys/shm.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <semantic_victim_ta.h>

#define BUFFER_SIZE    256

TEEC_Result write_secure_object(TEEC_Session *sess, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(TEEC_Session *sess, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shm;
	TEEC_UUID uuid = TA_SEMANTIC_VICTIM_UUID;
	uint32_t err_origin;
	uint64_t key = 0x66546A576D5A7134;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Test for session hijacking */
	
	/* Test for shared memory hijacking */
	memset(&op, 0, sizeof(op));
	memset(&shm, 0, sizeof(shm));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	shm.buffer = malloc(BUFFER_SIZE);
	shm.size = BUFFER_SIZE;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	res = TEEC_RegisterSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", res);

	/* printf("shm id: %d\n", shm.id); */

	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = BUFFER_SIZE;
	op.params[0].memref.offset = 0;

	res = TEEC_InvokeCommand(&sess, TA_SEMANTIC_VICTIM_CMD_SECURE_INITIALIZATION, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	/* printf("TA initialize the shared memory: %s\n", (char *)shm.buffer); */

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = key >> 32;
	op.params[0].value.b = key & 0xffffffff;

	/* printf("Invoking TA to store secret: 0x%X%X\n", op.params[0].value.a, op.params[0].value.b); */
	res = TEEC_InvokeCommand(&sess, TA_HPE_VICTIM_CMD_STORE_SECRET, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* printf("The shared memory: %s\n", (char *)shm.buffer); */

	char obj1_id[] = "object#1";		/* string identification for the object */
	char obj1_data[TEST_OBJECT_SIZE];

	memset(obj1_data, 'A', sizeof(obj1_data));

	res = write_secure_object(&sess, obj1_id,
				  obj1_data, sizeof(obj1_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to create an object in the secure storage");

	uint32_t addr;
	uint32_t sign;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	addr = op.params[0].value.a;
	sign = op.params[0].value.b;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = addr;
	op.params[0].value.b = sign;
	op.params[1].value.a = key >> 32;
	op.params[1].value.b = key & 0xffffffff;

	res = TEEC_InvokeCommand(&sess, TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	int shmid;
    key_t key_id = ftok("shared_memory_key", 123);
    size_t size = sizeof(uint32_t) * 2;

    shmid = shmget(key_id, size, IPC_CREAT | 0666);

    uint32_t* sharedData = (uint32_t*)shmat(shmid, NULL, 0);

    sharedData[0] = addr;
    sharedData[1] = sign;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 1024;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	int shmid_acipher;
    key_t key_acipher = ftok("shared_memory_key", 456);

    shmid_acipher = shmget(key_acipher, size, IPC_CREAT | 0666);

    uint32_t* shared_acipher = (uint32_t*)shmat(shmid_acipher, NULL, 0);

    shared_acipher[0] = op.params[0].value.a;
    shared_acipher[1] = op.params[0].value.b;

	useconds_t usec = 10000000;
    usleep(usec);

	shmdt(shared_acipher);
	shmctl(shmid_acipher, IPC_RMID, NULL);

	shmdt(sharedData);
    shmctl(shmid, IPC_RMID, NULL);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = addr;
	op.params[0].value.b = sign;

	res = TEEC_InvokeCommand(&sess, TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP, &op,
				 &err_origin);

	TEEC_ReleaseSharedMemory(&shm);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
