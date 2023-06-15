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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <semantic_victim_ta.h>

#include <string.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("semantic victim!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Goodbye!\n");
}

static TEE_Result load_secret(uint32_t param_types,
	TEE_Param params[4])
{
	uint64_t secret = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MemMove(&secret, TEE_GetInstanceData(), sizeof(uint64_t));

	params[0].value.a = secret >> 32;
	params[0].value.b = secret & 0xffffffff;
	IMSG("load secret: 0x%X%X from SW", params[0].value.a, params[0].value.b);

	return TEE_SUCCESS;
}

static TEE_Result store_secret(uint32_t param_types,
	TEE_Param params[4])
{
	uint64_t secret = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("store secret: 0x%X%X from NW", params[0].value.a, params[0].value.b);
	secret = ((uint64_t)params[0].value.a << 32) + params[0].value.b;

	uint64_t *sec = TEE_Malloc(sizeof(uint64_t), 0);
	if (!sec)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_SetInstanceData(sec);
	TEE_MemMove(sec, &secret, sizeof(uint64_t));

	return TEE_SUCCESS;
}

static TEE_Result alloc_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = TEE_Malloc(sizeof(uint64_t), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	SET_INVARIANT_PARAMS(params[0], state, SESSION_PUBLIC);

	return res;
}

static TEE_Result read_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t *state = NULL;

	DMSG("has been called");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = params[0].value.a;

	params[1].value.a = (*state) >> 32;
	params[1].value.b = (*state) & 0xffffffff;
	IMSG("load secret: 0x%X%X from SW", params[1].value.a, params[1].value.b);

	return res;
}

static TEE_Result write_heap(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t *state = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_INVARIANT_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	state = params[0].value.a;

	IMSG("store secret: 0x%X%X from NW", params[1].value.a, params[1].value.b);
	*state = ((uint64_t)params[1].value.a << 32) + params[1].value.b;

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

static TEE_Result secure_initialize(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(params[0].memref.buffer, "0x66546A576D5A7134", 19);
	
	IMSG("Initialize shared memory: %s", (char *)(params[0].memref.buffer));

	return TEE_SUCCESS;
}

static TEE_Result secure_write_shm(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(params[0].memref.buffer, "Boomerang!", 11);
	
	IMSG("Write shared memory: %s", (char *)(params[0].memref.buffer));

	return TEE_SUCCESS;
}

static TEE_Result delete_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	/*
	 * Check object exists and delete it
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META, /* we must be allowed to delete it */
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		return res;
	}

	TEE_CloseAndDeletePersistentObject1(object);
	TEE_Free(obj_id);

	return res;
}

static TEE_Result create_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	/*
	 * Create object in secure storage and fill with data
	 */
	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
			TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
			TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
			TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					obj_data_flag,
					TEE_HANDLE_NULL,
					NULL, 0,		/* we may not fill it right now */
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	} else {
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

static TEE_Result read_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}
	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}

	if (object_info.dataSize > data_sz) {
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}
	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, data, read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
		goto exit;
	}
	/* Return the number of byte effectively filled */
	params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

static TEE_Result cmd_gen_key(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

	params[0].value.a = (uint64_t) key >> 32;
	params[0].value.b = (uint64_t) key & 0xffffffff;
	return TEE_SUCCESS;
}

static TEE_Result cmd_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	TEE_ObjectHandle key;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	
	key = (TEE_ObjectHandle) (((uint64_t) params[0].value.a) << 32 | params[0].value.b);

	res = TEE_GetObjectInfo1(key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

	inbuf = params[1].memref.buffer;
	inbuf_len = params[1].memref.size;
	outbuf = params[2].memref.buffer;
	outbuf_len = params[2].memref.size;

	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf,
				    &outbuf_len);
	if (res) {
		EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[2].memref.size, res);
	}
	params[2].memref.size = outbuf_len;

out:
	TEE_FreeOperation(op);
	return res;

}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_SEMANTIC_VICTIM_CMD_SECURE_INITIALIZATION:
		return secure_initialize(param_types, params);
	case TA_SEMANTIC_VICTIM_CMD_SECURE_WRITE_SHM:
		return secure_write_shm(param_types, params);
	case TA_HPE_VICTIM_CMD_STORE_SECRET:
		return store_secret(param_types, params);
	case TA_HPE_VICTIM_CMD_LOAD_SECRET:
		return load_secret(param_types, params);
	case TA_SECURE_STORAGE_CMD_WRITE_RAW:
		return create_raw_object(param_types, params);
	case TA_SECURE_STORAGE_CMD_READ_RAW:
		return read_raw_object(param_types, params);
	case TA_SECURE_STORAGE_CMD_DELETE:
		return delete_object(param_types, params);
	case TA_HEAP_PARAM_PAC_CMD_ALLOC_HEAP:
		return alloc_heap(param_types, params);
	case TA_HEAP_PARAM_PAC_CMD_READ_HEAP:
		return read_heap(param_types, params);
	case TA_HEAP_PARAM_PAC_CMD_WRITE_HEAP:
		return write_heap(param_types, params);
	case TA_HEAP_PARAM_PAC_CMD_RELEASE_HEAP:
		return release_heap(param_types, params);
	case TA_ACIPHER_CMD_GEN_KEY:
		return cmd_gen_key(param_types, params);
	case TA_ACIPHER_CMD_ENCRYPT:
		return cmd_enc(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
