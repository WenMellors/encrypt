CC = g++
CFLAGS = -lssl -lcrypto

rec:main.o receiver.o sha256.o
	$(CC) -o send main.o sender.o sha256.o $(CFLAGS)
main.o:main.cpp
	$(CC) -c main.cpp $(CFLAGS)
receiver.o:sender.cpp
	$(CC) -c sender.cpp $(CFLAGS)
sha256.o:sha256.cpp
	$(CC) -c sha256.cpp $(CFLAGS)
clean:
	rm rec main.o sender.o
