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
#include <fcntl.h>
#include <unistd.h>

#define CAESAR_ENC 0
#define CAESAR_DEC 1

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>


int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	int work;
	char plaintext[1000] = {0,};
	char ciphertext[1000] = {0,};
	char encrypted_randomkey[3];
	int len = 1000;
	int file;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));


	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);



	if(argc > 4 || argc < 3){
		printf("check option.\n");
		return 1;
	}
	if(argc == 3){
		if(!strcmp("-e", argv[1])){
			work = CAESAR_ENC;
		}

		if(!strcmp("-d", argv[1])){
			work = CAESAR_DEC;
		}
		
	}else if(!strcmp("Caesar", argv[3])){
		if(!strcmp("-e", argv[1])){
			work = CAESAR_ENC;
		}
		if(!strcmp("-d", argv[1])){
			work = CAESAR_DEC;
		}


	}else{
		printf("check option.\n");
		return 1;

	}

	
	switch(work){
		
		case CAESAR_ENC:

			res = TEEC_InitializeContext(NULL, &ctx);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

			res = TEEC_OpenSession(&ctx, &sess, &uuid,
					       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);
			
			file = open(argv[2], O_RDONLY);
			if(file == -1){
				perror("error");
				return 1;
			}
			else
			{
				read(file, plaintext, len);
				close(file);
			}
			
			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, 								TEEC_VALUE_INOUT,
							TEEC_NONE,
							TEEC_NONE);

			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, plaintext, len);


			
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_CREATE_RANDOMKEY, &op,
						 &err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
						 &err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
						 &err_origin);

			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	
			encrypted_randomkey[0] = op.params[1].value.a;
			encrypted_randomkey[1] = '\0';
			strcat(ciphertext, encrypted_randomkey);
			

			
			if(0 < (file = creat("./ciphertext.txt", 0644))){
				write(file, ciphertext, strlen(ciphertext));
				close(file);
			}
			else
			{
				perror("error");
				return 1;
			}


			printf("CAESAR Encryption complete!\n");

			
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			break;

		case CAESAR_DEC:

			// Connect
			res = TEEC_InitializeContext(NULL, &ctx);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

			res = TEEC_OpenSession(&ctx, &sess, &uuid,
					       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);
			file = open(argv[2], O_RDONLY);
			

			if(file == -1){
				perror("error");
				return 1;
			}
			else
			{
				read(file, ciphertext, len);
				close(file);
			}
			
			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, 								TEEC_VALUE_INOUT,
							TEEC_NONE,
							TEEC_NONE);
			op.params[0].tmpref.buffer = ciphertext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
						 &err_origin);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
						 &err_origin);

			memcpy(plaintext, op.params[0].tmpref.buffer, len);
	
			
			
			if(0 < (file = creat("./plaintext.txt", 0644))){
				write(file, plaintext, strlen(plaintext));
				close(file);
			}
			else
			{
				perror("error");
				return 1;
			}


			printf("CAESAR Decryption complete!\n");

			
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			break;
		default:
			break;


	}
	return 0;
}
