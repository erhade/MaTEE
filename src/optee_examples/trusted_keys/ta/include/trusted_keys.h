/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019-2020, Linaro Limited
 */

#ifndef TRUSTED_KEYS_H
#define TRUSTED_KEYS_H

#define TRUSTED_KEYS_UUID { 0xf510e07a, 0x7f43, 0x42e1, \
		{ 0xa0, 0xf9, 0xa7, 0xd0, 0x56, 0xd2, 0x5b, 0xdd } }

/*
 * Get random data for symmetric key
 *
 * [out]     memref[0]        Random data
 */
#define TA_CMD_GET_RANDOM	0x0

/*
 * Seal trusted key using hardware unique key
 *
 * [in]      memref[0]        Plain key
 * [out]     memref[1]        Sealed key datablob
 */
#define TA_CMD_SEAL		0x1

/*
 * Unseal trusted key using hardware unique key
 *
 * [in]      memref[0]        Sealed key datablob
 * [out]     memref[1]        Plain key
 */
#define TA_CMD_UNSEAL		0x2

#endif /* TRUSTED_KEYS_H */
