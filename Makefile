CC=gcc
CFLAGS=-Wall -Wextra -g3
LIBS=-lssl -lcrypto
# Add -Werror when possible
TARGET=ssl-tls-proxy
OBJECTS=obj/main.o obj/tls-client.o obj/tls-server.o obj/cert.o obj/buffer-reader.o obj/tls-common.o

all: create_object_and_out_directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LIBS)

obj/main.o: src/main.c
	$(CC) $(CFLAGS) -o obj/main.o -c src/main.c

obj/tls-client.o: src/tls/tls-client.c
	$(CC) $(CFLAGS) -o obj/tls-client.o -c src/tls/tls-client.c

obj/tls-server.o: src/tls/tls-server.c
	$(CC) $(CFLAGS) -o obj/tls-server.o -c src/tls/tls-server.c

obj/cert.o: src/cert/cert.c
	$(CC) $(CFLAGS) -o obj/cert.o -c src/cert/cert.c

obj/buffer-reader.o: src/buffer/buffer-reader.c
	$(CC) $(CFLAGS) -o obj/buffer-reader.o -c src/buffer/buffer-reader.c

obj/tls-common.o: src/tls/tls-common.c
	$(CC) $(CFLAGS) -o obj/tls-common.o -c src/tls/tls-common.c

create_object_and_out_directories: 
	mkdir -p obj

clean:
	rm -rf obj/ $(TARGET)
