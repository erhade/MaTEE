/*
 * Copyright (c) 2016-2017, Linaro Limited
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
#ifndef TA_SEMANTIC_VICTIM_H
#define TA_SEMANTIC_VICTIM_H


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

#endif /*TA_SEMANTIC_VICTIM_H*/
