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
#include <openssl/bio.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

int BIO_dump_fp (FILE *fp, const char *s, int len);
void download();
void upload(char *, char *);
void error_handling(char *);
void *send_msg(void *arg);
void *recv_msg(void *arg);
void order(char *);


char name[NAME_SIZE] = "[DEFAULT]";
char pw[NAME_SIZE] = "[DEFAULT]";
char msg[BUFSIZE];
char key[AES_KEY_128];
char iv[AES_KEY_128];

int main(int argc, char* argv[])
{
	int n, i, len, sock;
	struct sockaddr_in serv_addr;
	pthread_t snd_thread, rcv_thread;
	void *thread_return;
	char user[NAME_SIZE * 2];
	unsigned char text[BUFSIZE+AES_BLOCK_SIZE];

	APP_MSG msg_in, msg_out, msg_temp;

	BIO *rpub = NULL;
	RSA *rsa_pubkey = NULL;

	if(argc != 5)
	{
		printf("Usage : %s <IP> <port> <id> <pw>\n", argv[0]);
		exit(1);
	}

	sprintf(name, "%s", argv[3]);
	sprintf(pw, "%s", argv[4]);
	sprintf(user,"%s %s", name, pw);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1)
		error_handling("socket() error");

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error!");

	
        RAND_poll();
        RAND_bytes(key, sizeof(key));
        
	memset(&msg_out, 0, sizeof(msg_out));
        msg_out.type = PUBLIC_KEY_REQUEST;
        msg_out.type = htonl(msg_out.type);
        
	n = writen(sock, &msg_out, sizeof(APP_MSG));

        if(n == -1)
                error_handling("writen error");

        memset(&msg_in, 0, sizeof(msg_out));
        n = readn(sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

        if(n == -1)
                error_handling("readn error");
        else if(n == 0)
                error_handling("reading EOF");

	if(msg_in.type != PUBLIC_KEY)
                error_handling("message error");

        else
        {
                BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);

                rpub = BIO_new_mem_buf(msg_in.payload, -1);

                BIO_write(rpub, msg_in.payload, msg_in.msg_len);
		//perfect	
		rsa_pubkey = PEM_read_bio_RSA_PUBKEY(rpub, NULL, NULL, NULL);
                if(rsa_pubkey == NULL)
		{
                        error_handling("PEM_read_bio_RSAPublicKey error");
		}
        }

        memset(&msg_out, 0, sizeof(msg_out));
        msg_out.type = ENCRYPTED_KEY;
        msg_out.type = htonl(msg_out.type);
        msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);

        msg_out.msg_len = htonl(msg_out.msg_len);

	n = writen(sock, &msg_out, sizeof(APP_MSG));

        if(n == -1)
                error_handling("send_writen error");
	
	for(i = 0; i < AES_KEY_128; i++)
	{
		iv[i] = (unsigned char)i;
	}
	printf("my key: %s\n", key);
	
	memset(&msg_temp, 0, sizeof(msg_temp));

	user[strlen(user)] = '\0';
        len = encrypt((unsigned char*)user, strlen(user), key, iv, msg_temp.payload);

	msg_temp.msg_len = htonl(len);

	n = writen(sock, &msg_temp, sizeof(APP_MSG));
	if(n == -1)
		error_handling("writen error");

	n = readn(sock, &msg_in, sizeof(APP_MSG));
        if(n == -1)
        {
                error_handling("readn() error");
        }

        msg_in.msg_len = ntohl(msg_in.msg_len);

        printf("\n* encryptedMSG: \n");

	BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);

        len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)text);

        printf("* decryptedMsg: \n");
        BIO_dump_fp(stdout, (const char *)text, len);

	printf("%s\n", text);
	if(strcmp(text, "unlisted"))
	{
		pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
		pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);

		pthread_join(snd_thread, &thread_return);
		pthread_join(rcv_thread, &thread_return);
	}
	close(sock);

	return 0;
}

void download()
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

	//printf("in file: %s\n", buf);

	n = writen(fd, buf, strlen(buf));
	
	if(n  == -1)
	{
		close(fd);
		error_handling("write error");
	}

	printf("Receiving completed\n");

	close(fd);
}

void upload(char *id, char *plaintext)
{
	int n, fd, ret;
        char *name, *name2;
	struct stat buf;
        name = strtok(NULL, " ");
        name2 = strtok(NULL, " ");

        name2[strlen(name2) - 1] = '\0';
	char tempmsg[BUFSIZE];
        tempmsg[0] = '\0';
	plaintext[0] = '\0';

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

	//printf("plaintext after read: %s\n", name2);
	strcat(tempmsg, id);
        strcat(tempmsg, " up ");
        strcat(tempmsg, name2);
        strcat(tempmsg, " ");
        strcat(tempmsg, plaintext);
        printf("tempmsg: %s\n", tempmsg);
        strcpy(plaintext, tempmsg);

	printf("after readn: %s\n", plaintext);

        close(fd);
}

void error_handling(char *message)
{
        fputs(message, stderr);
        fputc('\n', stderr);
        exit(1);
}

void* send_msg(void *arg)
{
	int i;
	int sock = *((int*)arg);
	int len;
        char plaintext[NAME_SIZE+BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	char tempmsg[BUFSIZE] = {0x00, };

        APP_MSG msg_in, msg_out;
        int n;
        int plaintext_len;
        int ciphertext_len;

	while(1)
	{
                if(fgets(msg, BUFSIZE, stdin) == NULL)
                        break;
		if(!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
		{
			close(sock);
			exit(0);
		}
		strcpy(tempmsg, msg);
		strtok(tempmsg, " ");
		
		if(!strcmp(tempmsg, "up"))
			upload(name, plaintext);
		
		else
			sprintf(plaintext, "%s %s", name, msg);

                len = strlen(plaintext);
                if(plaintext[len - 1] == '\n')
                        plaintext[len - 1] = '\0';
                if(strlen(plaintext) == 0)
                        break;

                memset(&msg_out, 0, sizeof(msg_out));
		//msg_out.type = ENCRYPTED_MSG;
		//msg_out.type = htonl(msg_out.type);

                ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);

		msg_out.msg_len = htonl(ciphertext_len);

                n = writen(sock, &msg_out, sizeof(APP_MSG));
		if(n == -1)
			error_handling("writen error");
	}
}

void* recv_msg(void *arg)
{
	int i;
	int sock = *((int*)arg);
        int len;
        char plaintext[NAME_SIZE+BUFSIZE+AES_BLOCK_SIZE] = {0x00, };

        char temptext[NAME_SIZE+BUFSIZE+AES_BLOCK_SIZE] = {0x00, };

        APP_MSG msg_in, msg_out;
        int n;
        int plaintext_len;
        int ciphertext_len;

	while(1)
	{
		n = readn(sock, &msg_in, sizeof(APP_MSG));

                if(n == -1)
                        return (void*)-1;

                else if(n == 0)
                        break;

                msg_in.msg_len = ntohl(msg_in.msg_len);

		printf("\n* encryptedMSG: \n");
                                BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);
                                plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
                                printf("* decryptedMsg: \n");
                                BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

		printf("%s\n", plaintext);

                plaintext[plaintext_len] = '\0';
		strcpy(temptext, plaintext);
		strtok(temptext, " ");
		order(temptext);
                printf("%s\n", plaintext);
	}

	return NULL;
}

void order(char *text)
{
	if(!strcmp(text, "down"))
		download();

	else if(!strcmp(text, "list"))
		return;
}
