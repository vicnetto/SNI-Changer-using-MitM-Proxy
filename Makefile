CC=gcc
CFLAGS=-Wall -Wextra -g3
LIBS=-lssl -lcrypto
# Add -Werror when possible
TARGET=ssl-tls-proxy
OBJECTS=obj/main.o obj/tls-client.o obj/tls-server.o obj/cert.o obj/tls-io.o obj/tls-handshake.o obj/configuration.o

all: create_object_and_out_directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LIBS)

obj/main.o: src/main.c
	$(CC) $(CFLAGS) -o obj/main.o -c src/main.c

obj/tls-client.o: src/tls/client/tls-client.c
	$(CC) $(CFLAGS) -o obj/tls-client.o -c src/tls/client/tls-client.c

obj/tls-server.o: src/tls/server/tls-server.c
	$(CC) $(CFLAGS) -o obj/tls-server.o -c src/tls/server/tls-server.c

obj/tls-io.o: src/tls/io/tls-io.c
	$(CC) $(CFLAGS) -o obj/tls-io.o -c src/tls/io/tls-io.c

obj/tls-handshake.o: src/tls/io/tls-handshake.c
	$(CC) $(CFLAGS) -o obj/tls-handshake.o -c src/tls/io/tls-handshake.c

obj/cert.o: src/cert/cert.c
	$(CC) $(CFLAGS) -o obj/cert.o -c src/cert/cert.c

obj/configuration.o: src/config/configuration.c
	$(CC) $(CFLAGS) -o obj/configuration.o -c src/config/configuration.c

create_object_and_out_directories:
	mkdir -p obj

clean:
	rm -rf obj/ $(TARGET)
