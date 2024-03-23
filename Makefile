server:
	gcc 20161897_serv.c aesenc.c readnwrite.c -o serv -lpthread -lcrypto -ljson-c

client:
	gcc 20161897_clnt.c aesenc.c readnwrite.c -o clnt -lpthread -lcrypto

