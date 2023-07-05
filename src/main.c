#include "socket.h"
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <proxy_port>\n", argv[0]);

        return 1;
    }

    int proxyServerPort = atoi(argv[1]);

    // Adding the correct address to the tcp socket.
    struct sockaddr_in proxyServerAddress;
    setAddress(&proxyServerAddress, INADDR_ANY, proxyServerPort);

    // Creating socket and returning the FD.
    int proxyServerSocket = createSocket(proxyServerAddress, proxyServerPort);

    int clientSocket;
    socklen_t clientAddressLength = sizeof(struct sockaddr_in);

    char *buffer;

    // Accept and handle client connections
    while (1) {
        // Waits for client connection
        if ((clientSocket = accept(proxyServerSocket,
                                   (struct sockaddr *)&proxyServerAddress,
                                   &clientAddressLength)) < 0) {
            perror("Failed to accept client connection");
            continue;
        }

        printf("Accepted client connection in socket %d\n", clientSocket);
        printf("Message: %s\n", buffer);

        // Handle client connection in a separate function
        // handleClientConnection(clientSocket);
    }

    // Close the proxy client socket
    close(proxyServerSocket);

    return 0;
}
