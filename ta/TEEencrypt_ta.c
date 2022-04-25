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

#include <TEEencrypt_ta.h>

#include <string.h>
#include <stdio.h>

unsigned int random_key;
int root_key=5;
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
		void __maybe_unused **sess_ctx)
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
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

/*
 * 
 * caesar start
 */

static TEE_Result create_randomkey(uint32_t param_types,
	TEE_Param params[4])
{
	DMSG("Create Random Key\n");
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = random_key % 26;

	while(random_key == 0){
		TEE_GenerateRandom(&random_key, sizeof(random_key));
		random_key = random_key % 26;
	}
	
	IMSG("Create New RandomKey : %d\n", random_key);

	return TEE_SUCCESS;
}

static TEE_Result enc_randomkey(uint32_t param_types,
	TEE_Param params[4])
{
	DMSG("Encryption\n");

	if(random_key>='a' && random_key <='z'){
		random_key -= 'a';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'A';
	}
	params[1].value.a = (uint32_t)random_key;

	return TEE_SUCCESS;

}

static TEE_Result dec_randomkey(uint32_t param_types,
	TEE_Param params[4])
{
	
	char * in = (char *)params[0].memref.buffer;
	int len = strlen (params[0].memref.buffer);
	char encrypted [1000]={0,};	
	
	DMSG("Decryption\n");
	memcpy(encrypted, in, len);
	random_key = encrypted[len-1];

	if(random_key>='a' && random_key <='z'){
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'A';
	}
	
	IMSG("RandomKey : %d\n", random_key);

	return TEE_SUCCESS;
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	DMSG("ENC_VALUE has been called");

	char * in = (char *)params[0].memref.buffer;
	int len = strlen (params[0].memref.buffer);
	char encrypted [1000]={0,};
	DMSG("Encryption Value\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, len);

	for(int i=0; i<len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
		memcpy(in, encrypted, len);
		DMSG ("Ciphertext :  %s", encrypted);

		return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int len = strlen (params[0].memref.buffer);
	char decrypted [1000]={0,};
	
	DMSG("Decryption\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, len);

	for(int i=0; i<len-1;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	decrypted[len-1] = '\0';
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, len);

	return TEE_SUCCESS;
}

//caesar end


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_CREATE_RANDOMKEY:
		return create_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return enc_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
		return dec_randomkey(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
