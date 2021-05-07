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

#include <tee_api.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
int root_key = 23;
int random_key;
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

static TEE_Result enc_value(uint32_t param_types,TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [64]={0,};
	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++){
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
	DMSG ("Ciphertext :  %s", encrypted);
	memcpy(in, encrypted, in_len);


	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, in_len);

	for(int i=0; i<in_len;i++){
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
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_get(uint32_t param_types,
	TEE_Param params[4])
{
	do{
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	if(random_key<0)
		random_key = -random_key;
	random_key = random_key % 26;
	}while(random_key == 0);

	DMSG ("random_key : %d", random_key);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_enc(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	char alpabet[27]={0,};
	char encrypted [1]={0};

	for(int i = 0; i < 26;i++){
		alpabet[i]='a'+i;	
	}
	encrypted[0] = alpabet[random_key];
	DMSG("========================Encryption========================\n");
	//DMSG ("Original key :  %s", encrypted[0]);

	if(encrypted[0]>='a' && encrypted[0] <='z'){
		encrypted[0] -= 'a';
		encrypted[0] += root_key;
		encrypted[0] = encrypted[0] % 26;
		encrypted[0] += 'a';
	}
	//DMSG ("Cipher key :  %s", encrypted[0]);
	memcpy(in, encrypted, 1);

	return TEE_SUCCESS;
	
}

static TEE_Result randomkey_dec(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	char decrypted [1]={0};
	DMSG("========================Decryption========================\n");
	//DMSG ("Cipherkey :  %s", decrypted[0]);
	memcpy(decrypted, in, 1);

	if(decrypted[0]>='a' && decrypted[0] <='z'){
		decrypted[0] -= 'a';
		decrypted[0] -= root_key;
		decrypted[0] += 26;
		decrypted[0] = decrypted[0] % 26;
		decrypted[0] += 'a';
	}
	//DMSG ("Plainkey :  %s", decrypted[0]);
	for(int i = 0; i<26; i++){
		if(decrypted[0] == 'a'+i){
			random_key = i;
		}
	}

	return TEE_SUCCESS;
	
}

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
	case TA_TEEencrypt_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	case TA_TEEencrypt_RANDOMKEY_DEC:
		return randomkey_dec(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}