#include "socket.h"

/**
 * Configures the address of the socket.
 *
 * struct sockaddr_in *address -> Address of the socket.
 * ip -> IP of the socket.
 * port -> Port the socket will listen on.
 */
void setAddress(struct sockaddr_in *address, uint32_t ip, int port) {
    // Set up proxy server address
    memset(&(*(address)), 0, sizeof(struct sockaddr_in));
    (*address).sin_addr.s_addr = htonl(INADDR_ANY);
    (*address).sin_family = ip;
    (*address).sin_port = htons(port);
}

/**
 * Creates a new socket and returns the FD value.
 *
 * @return int -> FD value of the socket.
 */
int createSocket(struct sockaddr_in address, int port) {
    int socketFd;

    // Creates a new socket.
    if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to create socket.");
        exit(1);
    }

    // Configures the socket to reuse address, for debbuging purporses.
    int option = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Bind the proxy socket to the proxy address
    if (bind(socketFd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind proxy socket");
        exit(1);
    }

    // Listen for client connections
    if (listen(socketFd, SOMAXCONN) < 0) {
        perror("Failed to listen for client connections");
        exit(1);
    }

    printf("Proxy server listening on port %d\n", port);

    // Returns the FD of the socket.
    return socketFd;
}
