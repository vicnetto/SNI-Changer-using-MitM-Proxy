CC=gcc
CFLAGS=-Wall -Wextra -g3
LIBS=-lssl -lcrypto
# Add -Werror when possible
TARGET=ssl-tls-proxy
OBJECTS=obj/main.o obj/socket.o obj/tls-client.o obj/tls-server.o

all: create_object_and_out_directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LIBS)

obj/main.o: src/main.c
	$(CC) $(CFLAGS) -o obj/main.o -c src/main.c

obj/socket.o: src/socket/socket.c
	$(CC) $(CFLAGS) -o obj/socket.o -c src/socket/socket.c

obj/tls-client.o: src/tls/tls-client.c
	$(CC) $(CFLAGS) -o obj/tls-client.o -c src/tls/tls-client.c

obj/tls-server.o: src/tls/tls-server.c
	$(CC) $(CFLAGS) -o obj/tls-server.o -c src/tls/tls-server.c

create_object_and_out_directories: 
	mkdir -p obj

clean:
	rm -rf obj/ $(TARGET)
