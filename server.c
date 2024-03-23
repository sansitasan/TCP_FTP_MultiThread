#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <pthread.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <dirent.h>

#include <json-c/json.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

#define MAX_CLNT 256

int BIO_dump_fp (FILE *fp, const char *s, int len);
void* register_clnt();
void download(char *);
void upload(char *);
void dirlist(char *);
void order(char *, char *);
void error_handling(char *);
void send_msg(APP_MSG *);
void* handle_clnt(void *arg);

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;
pthread_mutex_t datamut;

int main(int argc, char* argv[])
{
	int i;
	int serv_sock = -1, clnt_sock = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;

	socklen_t clnt_addr_size;
	pthread_t t_id, register_thread;

	if(argc != 2)
	{
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	pthread_mutex_init(&mutx, NULL);
	pthread_mutex_init(&datamut, NULL);
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1)
		error_handling("socket() error");

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		error_handling("bind() error");

	if(listen(serv_sock, 5) == -1)
		error_handling("listen() error");

	pthread_create(&register_thread, NULL, register_clnt, NULL);

	while(1)
	{
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

		if(clnt_sock == -1)
			error_handling("accept() error");
		
		pthread_mutex_lock(&mutx);
		clnt_socks[clnt_cnt++] = clnt_sock;
		pthread_mutex_unlock(&mutx);

		pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);

		printf("\n[TCP Server] Client connected: IP=%s \n", inet_ntoa(clnt_addr.sin_addr));
	}

err:
	close(serv_sock);
	return 0;
}

void* register_clnt()
{
	int len;
	char userinfo[BUFSIZE];
	char *id, *pw;
	json_object *data = json_object_from_file("userlist.json");
	if(data == NULL)
	{
		data = json_object_new_object();
		json_object_to_file("userlist.json", data);
	}

	json_object *user, *isregist = NULL;

	while(1)
	{
		user = json_object_new_object();
		printf("regist user > id pw, or input save\n");
		if(fgets(userinfo, BUFSIZE + 1, stdin) == NULL)
			continue;

		len = strlen(userinfo);
		if(userinfo[len - 1] == '\n')
		{
			userinfo[len - 1] = '\0';
		}
		if(len == 0){
			continue;
		}

		if(!strcmp(userinfo, "save"))
		{
			//printf("%s\n", json_object_to_json_string_ext(data, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
			pthread_mutex_lock(&datamut);
			json_object_to_file("userlist.json", data);
			pthread_mutex_unlock(&datamut);
			continue;
		}

		id = strtok(userinfo, " ");
		pw = strtok(NULL, " ");
		
		if(strlen(pw) == 0)
		{
			printf("Please enter pw\n");
			continue;
		}
		isregist = json_object_object_get(data, id);

		if(isregist == NULL){
		json_object_object_add(user, id, json_object_new_string(pw));
		json_object_object_add(data, id, user);
		}

		else
		{
			printf("%s already registered!\n", id);
			isregist = NULL;
		}

	}

	pthread_mutex_lock(&datamut);
	json_object_object_add(data, "data", user);       
	json_object_to_file("userlist.json", data);
	pthread_mutex_unlock(&datamut);
}

void download(char *plaintext)
{
	int n, fd, ret;
	char *name, *name2;
	struct stat buf;
	name = strtok(NULL, " ");
	name2 = strtok(NULL, " ");

	char tempmsg[BUFSIZE];
	tempmsg[0] = '\0';

	//printf("in down: %s\n", plaintext);
	fd = open(name, O_RDONLY, S_IRWXU);
	
	if(fd == -1)
	{
		close(fd);
		strcpy(plaintext, "Cannot found file");
		printf("%s\n", plaintext);
		return;
	}
	ret = stat(name, &buf);

	n = readn(fd, plaintext, buf.st_size);

	if(n == -1)
		error_handling("readn() error");
	
	plaintext[n] = '\0';
	strcat(tempmsg, "down ");
	strcat(tempmsg, name2);
	strcat(tempmsg, " ");
	strcat(tempmsg, plaintext);
	printf("tempmsg: %s\n", tempmsg);
	strcpy(plaintext, tempmsg);

	close(fd);
}

void upload(char *plaintext)
{
	int n, fd;
        char *name;
        char *buf;

        name = strtok(NULL, " ");
        buf = strtok(NULL, "\0");
        fd = open(name, O_CREAT | O_WRONLY, S_IRWXU);

        if(fd == -1)
        {
                close(fd);
                error_handling("open error");
        }

	printf("Receiving file..\n");

        //printf("%s\n", buf);
        
	n = writen(fd, buf, strlen(buf));

        if(n  == -1)
        {
                close(fd);
                error_handling("write error");
        }

        sprintf(plaintext, "Receiving completed\n");
	
	close(fd);
}

void dirlist(char *plaintext)
{
	DIR *dp;
	struct dirent *dir;

	if((dp = opendir(".")) == NULL)
		error_handling("opendir error");
	
	while((dir = readdir(dp)) != NULL)
	{
		if(dir->d_ino == 0) continue;

		strcat(plaintext, dir->d_name);
		strcat(plaintext, "\n");
	}

	closedir(dp);
}

void error_handling(char *message)
{
        fputs(message, stderr);
        fputc('\n', stderr);
        exit(1);
}

void order(char *msg, char *plaintext)
{
	if(!strcmp(msg, "list"))
		dirlist(plaintext);

	else if(!strcmp(msg, "down"))
		download(plaintext);

	else if(!strcmp(msg, "up"))
		upload(plaintext);
	else
		strcpy(plaintext, "No answer");
}

int checkuser(int *clnt_sock, char *key, char *iv)
{
	int plaintext_len, ciphertext_len, flag, n;
	json_object *data = NULL, *userobj = NULL, *pwobj = NULL;
        char *id, *pw;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	APP_MSG msg_in, msg_out;
	
	memset(&msg_in, 0, sizeof(msg_out));

	n = readn(*clnt_sock, &msg_in, sizeof(APP_MSG));
     	if(n == -1)
	{
		error_handling("readn() error");
	}

	msg_in.msg_len = ntohl(msg_in.msg_len);

	printf("\n* encryptedMSG: \n");
	BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);

	plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);

	printf("* decryptedMsg: \n");
	BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

	plaintext[plaintext_len] = '\0';
	id = strtok(plaintext, " ");
	pw = strtok(NULL, " ");
	pthread_mutex_lock(&datamut);
	data = json_object_from_file("userlist.json");
	
	if(data == NULL)
		flag = 0;
	
	else
	{
		userobj = json_object_object_get(data, id);
		if(userobj == NULL)
			flag = 0;
		else
		{
			pwobj = json_object_object_get(userobj, id);
			if(strcmp(pw,  json_object_get_string(pwobj)))
				flag = 0;
			else
				flag = 1;
		}
	}
	pthread_mutex_unlock(&datamut);

	if(flag == 0)
	{
		plaintext[0] = '\0';
		strcpy(plaintext, "unlisted");
		msg_out.type = htonl(msg_out.type);

		ciphertext_len = encrypt((unsigned char*)plaintext, strlen(plaintext), key, iv, msg_out.payload);
		msg_out.msg_len = htonl(ciphertext_len);

		//send msg
		n = writen(*clnt_sock, &msg_out, sizeof(APP_MSG));

		if(n == -1)
			error_handling("wirten()  error");

	}
	else
	{
		plaintext[0] = '\0';
                strcpy(plaintext, "welcome!");
                msg_out.type = htonl(msg_out.type);
		printf("%s\n", plaintext);

                ciphertext_len = encrypt((unsigned char*)plaintext, strlen(plaintext), key, iv, msg_out.payload);
                msg_out.msg_len = htonl(ciphertext_len);

                //send msg
                n = writen(*clnt_sock, &msg_out, sizeof(APP_MSG));

                if(n == -1)
                        error_handling("wirten()  error");

	}
	return flag;
}

void* handle_clnt(void *arg)
{
        char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
        char temptext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };

        unsigned char key[AES_KEY_128] = {0x00, };
        unsigned char iv[AES_KEY_128] = {0x00, };

        APP_MSG msg_in, msg_out, msg_buf;
        int n, i;
	int len, flag;
        int plaintext_len;
        int ciphertext_len;
	int publickey_len;
	int encryptedkey_len;

	int clnt_sock = *((int*)arg);
	int str_len = 0;
	char msg[BUFSIZE];
	char *command;

	json_object *data = NULL, *userobj = NULL, *pwobj = NULL;
        char *id, *pw;

	for(i = 0; i < AES_KEY_128; i++)
	{
                iv[i] = (unsigned char)i;
	}

	
	BIO *bp_public = NULL, *bp_private = NULL;
	BIO *pub = NULL;
	RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

	bp_public = BIO_new_file("public.pem", "r");
	
	rsa_pubkey = PEM_read_bio_RSA_PUBKEY(bp_public, NULL, NULL, NULL);

	if(rsa_pubkey == NULL)
		error_handling("no pub.pem file");

	bp_private = BIO_new_file("private.pem", "r");
	
	if(!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL))
                error_handling("no priv.pem file");

	memset(&msg_in, 0, sizeof(msg_out));
	n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

	if(n == -1)
                error_handling("readn error");
        else if(n == 0)
                error_handling("reading EOF");

        if(msg_in.type != PUBLIC_KEY_REQUEST)
                error_handling("message error");

	else
	{
		memset(&msg_out, 0, sizeof(msg_out));
		msg_out.type = PUBLIC_KEY;
	       	msg_out.type = htonl(msg_out.type);

		pub = BIO_new(BIO_s_mem());
		PEM_write_bio_RSA_PUBKEY(pub, rsa_pubkey);
		publickey_len = BIO_pending(pub);

		BIO_read(pub, msg_out.payload, publickey_len);
		//perfect
		msg_out.msg_len = htonl(publickey_len);

		n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));

		if(n == -1)
			error_handling("writen error");
	}

	memset(&msg_in, 0, sizeof(msg_out));
	memset(&msg_buf, 0, sizeof(msg_out));
        n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

	if(msg_in.type != ENCRYPTED_KEY)
	{
		error_handling("message error");
	}

	else
	{
		encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, msg_buf.payload, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
		
		memcpy(key, msg_buf.payload, encryptedkey_len);
	}

	flag = checkuser(&clnt_sock, key, iv);
	printf("clnt key: %s\n", key);

	if(flag)
	{
	while((n = readn(clnt_sock, &msg_in, sizeof(APP_MSG))) != 0)
	{
                if(n == -1)
                {
                        error_handling("readn() error");
                        break;
                }

		msg_in.msg_len = ntohl(msg_in.msg_len);

		printf("\n* encryptedMSG: \n");
		BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);

		plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);

		printf("* decryptedMsg: \n");
		BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

                plaintext[plaintext_len] = '\0';
                printf("%s\n", plaintext);

                strcpy(temptext, plaintext);
                id = strtok(temptext, " ");

		command = strtok(NULL, " ");

		if(plaintext[len - 1] == '\n')
                        plaintext[len - 1] = '\0';
                if(strlen(plaintext) == 0)
                        break;
		if(!strcmp(plaintext, "q\n") || !strcmp(plaintext, "Q\n"))
			break;

		plaintext[0] ='\0';
                order(command, plaintext);

		len = strlen(plaintext);
		
		printf("sending plaintext: %s\n", plaintext);

		if(strcmp(plaintext, "No answer"))
		{
			msg_out.type = htonl(msg_out.type);

			ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
			msg_out.msg_len = htonl(ciphertext_len);
			//send msg
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));

			if(n == -1)
				error_handling("wirten()  error");
		}
	}
	}

	pthread_mutex_lock(&mutx);
	for(i = 0; i < clnt_cnt; i++)
	{
		if(clnt_sock == clnt_socks[i])
		{
			while(i++ < clnt_cnt-1)
				clnt_socks[i] = clnt_socks[i+1];
			break;
		}
	}

	clnt_cnt--;
	pthread_mutex_unlock(&mutx);
	close(clnt_sock);
	return NULL;
}
