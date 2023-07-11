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
    (*address).sin_family = AF_INET;
    (*address).sin_port = htons(port);
    (*address).sin_addr.s_addr = ip;
}

/**
 * Create a new socket and connect to host.
 *
 * @param struct sockaddr_in hostAddress -> Address of the destination host.
 *
 * @return int -> FD value of the socket.
 */
int createClientSocket(struct sockaddr_in hostAddress) {
    int socketFd;

    // Create a new socket.
    if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to create socket.");
        exit(1);
    }

    // Configure the socket to reuse address, for debbuging purporses.
    int option = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Try to connect to host.
    if (connect(socketFd, (struct sockaddr *)&hostAddress,
                sizeof(struct sockaddr)) == -1) {
        printf("Error: Failed to create TCP socket with the destination.\n");
        exit(1);
    }

    // Returns the FD of the connection.
    return socketFd;
}

/**
 * Creates a new socket and returns the FD value.
 *
 * @return int -> FD value of the socket.
 */
int createServerSocket(struct sockaddr_in address, int port) {
    int socketFd;

    // Creates a new socket.
    if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error: Failed to create socket.\n");
        exit(1);
    }

    // Configures the socket to reuse address, for debbuging purporses.
    int option = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Bind the proxy socket to the proxy address
    if (bind(socketFd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Error: Failed to bind proxy socket\n");
        exit(1);
    }

    // Listen for client connections
    if (listen(socketFd, SOMAXCONN) < 0) {
        perror("Error: Failed to listen for client connections\n");
        exit(1);
    }

    printf("Proxy server listening on port %d\n", port);

    // Returns the FD of the socket.
    return socketFd;
}
