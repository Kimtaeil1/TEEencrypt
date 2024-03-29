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
#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TEEencrypt_UUID \
	{ 0x5a532670, 0x2d7e, 0x4751, \
		{ 0x8a, 0xf9, 0x7f, 0xfb, 0x57, 0x2f, 0x9c, 0xa0} }

/* The function IDs implemented in this TA */
#define TA_TEEencrypt_CAESAR_ENCRYPT		0
#define TA_TEEencrypt_CAESAR_DECRYPT		1
#define TA_TEEencrypt_CMD_RANDOMKEY_ENC		2
#define TA_TEEencrypt_CMD_RANDOMKEY_DEC		3
#define TA_TEEencrypt_CMD_CREATE_RANDOMKEY	4
#define TA_TEEencrypt_CMD_ENC_VALUE		5
#define TA_TEEencrypt_CMD_DEC_VALUE		6

#endif /*TA_HELLO_WORLD_H*/

