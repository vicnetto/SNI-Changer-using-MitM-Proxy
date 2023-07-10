#include "socket.h"
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <website> <port>\n", argv[0]);

        return 1;
    }

    int hostPort = atoi(argv[2]);

    // Get IP from hostname.
    char *hostname = argv[1];
    struct hostent *host;

    // Request to DNS server the IP of the hostname.
    if ((host = gethostbyname(hostname)) == NULL) {
        printf("Error: Could not resolve hostname %s\n", hostname);
        exit(0);
    }

    uint32_t hostnameIp = *(long *)host->h_addr;

    // Add the correct address to the tcp socket.
    struct sockaddr_in hostAdress;
    setAddress(&hostAdress, hostnameIp, hostPort);

    // Create socket and returng the FD.
    int clientFd = createClientSocket(hostAdress);

    printf("Successfully made the TCP connection to: [%s]:[%d]\n", hostname,
           hostPort);

    // Close the proxy client socket
    close(clientFd);

    return 0;
}
