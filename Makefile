CC=gcc
CFLAGS=-Wall -Wextra -g3
# Add -Werror when possible
TARGET=ssl-tls-proxy
OBJECTS=obj/main.o obj/socket.o

all: create_object_and_out_directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET)

obj/main.o: src/main.c
	$(CC) $(CFLAGS) -o obj/main.o -c src/main.c

obj/socket.o: src/socket.c
	$(CC) $(CFLAGS) -o obj/socket.o -c src/socket.c

create_object_and_out_directories: 
	mkdir -p obj

clean:
	rm -rf obj/ $(TARGET)
