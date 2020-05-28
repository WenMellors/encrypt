CC = g++
CFLAGS = -lssl -lcrypto

rec:main.o receiver.o librsa.a aes_ni_support.o aes.o sha256.o
	$(CC) -o rec main.o receiver.o librsa.a aes_ni_support.o aes.o sha256.o $(CFLAGS)
main.o:main.cpp
	$(CC) -c main.cpp $(CFLAGS)
receiver.o:receiver.cpp
	$(CC) -c receiver.cpp $(CFLAGS)
librsa.a:rsa.c
	gcc -c rsa.c
	ar rc librsa.a rsa.o
aes_ni_support.o:
	$(CC) -c aes_ni_support.cpp $(CFLAGS)
aes.o:
	$(CC) -c aes.cpp $(CFLAGS)
sha256.o:sha256.cpp
	$(CC) -c sha256.cpp $(CFLAGS)
clean:
	rm rec main.o receiver.o librsa.a rsa.o aes_ni_support.o aes.o
