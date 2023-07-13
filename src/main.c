// #include "socket/socket.h"
#include "tls/tls-client.h"
#include "tls/tls-server.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // if (argc != 4) {
    //     printf("Usage: %s <website> <sni> <port>\n", argv[0]);

    //     return 1;
    // }

    // char *peer_hostname = argv[1];
    // char *peer_sni = argv[2];
    // char *peer_port = argv[3];

    // createTLSConnectionWithChangedSNI(peer_hostname, peer_sni, peer_port);

    createServerTLSConncection();

    // Request to DNS server the IP of the hostname.
    // if ((host = gethostbyname(hostname)) == NULL) {
    //     printf("Error: Could not resolve hostname %s\n", hostname);
    //     exit(0);
    // }

    // uint32_t hostnameIp = *(long *)host->h_addr;

    // // Add the correct address to the tcp socket.
    // struct sockaddr_in hostAdress;
    // setAddress(&hostAdress, hostnameIp, hostPort);

    // // Create socket and returng the FD.
    // int clientFd = createClientSocket(hostAdress);

    // printf("Successfully made the TCP connection to: [%s]:[%d]\n", hostname,
    //        hostPort);

    // // Close the proxy client socket
    // close(clientFd);

    return 0;
}
