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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plainfile[64] = {0,};
	char cipherfile[64] = {0,};
	char plainkey[1]={0};
	char cipherkey[1]={0};
	int len = 64;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);


	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,TEEC_NONE, TEEC_NONE);


	op.params[0].tmpref.buffer = plainfile;
	op.params[0].tmpref.size = sizeof(plainfile);
	
	if(strcmp("-e", argv[1]) == 0){
		int fd;
		char file_name[100]="/root/";	
		strcat(file_name,argv[2]);
		if((fd = open(file_name, O_RDONLY)) == -1) { 
			printf("%s\n", strerror(errno));
			 return -1; 
		}
		read(fd, plainfile, len);
		printf("%s\n",plainfile);
		close(fd);
		
		memcpy(op.params[0].tmpref.buffer, plainfile, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RANDOMKEY_GET, &op,&err_origin);
		if (res != TEEC_SUCCESS){
			printf("TA_TEEencrypt_RANDOMKEY_GET Error\n");
			return -1;
			}
		

		memcpy(op.params[0].tmpref.buffer, plainfile, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS){
			printf("TA_TEEencrypt_CMD_ENC_VALUE Error\n");
			return -1;
			}

		memcpy(cipherfile, op.params[0].tmpref.buffer, len);
		
		fd=open("/root/cipherText.txt", O_CREAT|O_WRONLY|O_TRUNC);
		if(fd==-1){
			printf("%s\n", strerror(errno));
			 return -1;
		}
		if(write(fd, cipherfile, sizeof(cipherfile))==-1){
			printf("%s\n", strerror(errno));
			 return -1;
			}
		close(fd);
		
		memcpy(op.params[0].tmpref.buffer, cipherkey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RANDOMKEY_ENC, &op,&err_origin);
		if (res != TEEC_SUCCESS){
			printf("TA_TEEencrypt_RANDOMKEY_ENC Error\n");
			return -1;
			}
		memcpy(cipherkey, op.params[0].tmpref.buffer, 1);
		
		fd=open("/root/cipherKey.txt", O_CREAT|O_WRONLY|O_TRUNC);
		if(fd==-1){
			printf("%s\n", strerror(errno));
			 return -1;
		}
		if(write(fd, cipherkey, 1)==-1){
			printf("%s\n", strerror(errno));
			 return -1;
			}
		close(fd);
	}
	
	else if(strcmp("-d", argv[1]) == 0){
		int fd;
		char key_file_name[100]="/root/";
		strcat(key_file_name,argv[3]);
		if((fd = open(key_file_name, O_RDONLY)) == -1) { 
			printf("%s\n", strerror(errno));
			 return -1; 
		}
		read(fd, cipherkey, 1);
		close(fd);
		
		memcpy(op.params[0].tmpref.buffer, cipherkey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RANDOMKEY_DEC, &op, &err_origin);
		if (res != TEEC_SUCCESS){
			printf("TA_TEEencrypt_RANDOMKEY_DEC Error\n");
			return -1;
			}
		char cip_file_name[100]="/root/";
		strcat(cip_file_name,argv[2]);
		if((fd = open(cip_file_name, O_RDONLY)) == -1) { 
			printf("%s\n", strerror(errno));
			 return -1; 
		}
		read(fd, cipherfile, len);
		printf("%s\n",cipherfile);
		close(fd);
		
		memcpy(op.params[0].tmpref.buffer, cipherfile, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS){
			printf("TA_TEEencrypt_CMD_DEC_VALUE Error\n");
			return -1;
			}
		memcpy(plainfile, op.params[0].tmpref.buffer, len);
		
		fd=open("/root/plainText.txt", O_CREAT|O_WRONLY|O_TRUNC);
		if(fd==-1){
			printf("%s\n", strerror(errno));
			 return -1;
		}
		if(write(fd, plainfile, sizeof(plainfile))==-1){
			printf("%s\n", strerror(errno));
			 return -1;
			}
		close(fd);
	}else{
		printf("Command ERROR\n");
}


	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
