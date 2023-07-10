#ifndef SOCKET_H

#define BUFFER_MAX_SIZE 4096
#define SUCCESS 1

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void getHostname(struct hostent *host, char *hostname);
void setAddress(struct sockaddr_in *address, uint32_t ip, int port);
int createServerSocket(struct sockaddr_in address, int port);
int createClientSocket(struct sockaddr_in hostAddress);
void *handleClientConnection(void *arg);

#endif // !SOCKET_H
