#ifndef SOCKET_H

#define BUFFER_SIZE 4096
#define SUCCESS 1

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setAddress(struct sockaddr_in *address, uint32_t ip, int port);
int createSocket(struct sockaddr_in address, int port);

#endif // !SOCKET_H
