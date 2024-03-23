#ifndef __MSG_H__
#define __MSG_H__

#define AES_KEY_128 16
#define BUFSIZE 512
#define NAME_SIZE 10

enum MSG_TYPE{
	PUBLIC_KEY,
	SECRET_KEY,
	PUBLIC_KEY_REQUEST,
	IV,
	ENCRYPTED_KEY,
	ENCRYPTED_MSG,
};

typedef struct _APP_MSG_
{
	int type;
	unsigned char payload[BUFSIZE+AES_BLOCK_SIZE];
	int msg_len;
}APP_MSG;

typedef struct _NET_S_
{
	int sock;
	unsigned char key[AES_KEY_128];
        unsigned char iv[AES_KEY_128];
        unsigned char encrypted_key[BUFSIZE];
}NET_S;

#endif
