#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../buffer/buffer-reader.h"
#include "../cert/cert.h"
#include "tls-common.h"

#define DEFAULT_RESPONSE_TO_CLIENT "HTTP/1.1 200 OK\r\n\r\n"

#define ROOT_CA_CERTIFICATE_LOCATION "cert/cert-test/rootCA.pem"
#define ROOT_CA_KEY_LOCATION "cert/cert-test/rootCA.key"
#define CONNECT_MAX_SIZE 4096

#define SERVER_PORT 8080

/**
 * Configures the address of the socket.
 *
 * struct sockaddr_in *address -> Address of the socket.
 * ip -> IP of the socket.
 * port -> Port the socket will listen on.
 */
void set_address(struct sockaddr_in *address, uint32_t ip, int port) {
    // Set up proxy server address
    memset(&(*(address)), 0, sizeof(struct sockaddr_in));
    (*address).sin_family = AF_INET;
    (*address).sin_port = htons(port);
    (*address).sin_addr.s_addr = ip;
}

/**
 * Creates a new socket and returns the FD value.
 *
 * @param struct sockaddr_in address -> Address of the server.
 * @param int port -> Port to access the server.
 * @return int -> FD value of the socket.
 */
int create_server_socket(struct sockaddr_in address, int port) {
    int server_fd;

    // Creates a new socket.
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("(error) Failed to create socket.\n");
        exit(EXIT_FAILURE);
    }

    // Configures the socket to reuse address, for debbuging purporses.
    int option = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option,
                   sizeof(option))) {
        printf("(error) Failed to set reusable configuration.\n");
        exit(EXIT_FAILURE);
    }

    if (fcntl(server_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("(error) Error setting socket to non-blocking mode.\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Bind the proxy socket to the proxy address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        printf("(error) Failed to bind proxy socket\n");
        exit(EXIT_FAILURE);
    }

    // Listen for client connections
    if (listen(server_fd, SOMAXCONN) < 0) {
        printf("(error) Failed to listen for client connections\n");
        exit(EXIT_FAILURE);
    }

    printf("(info) Proxy server listening on port %d\n", port);

    // Returns the FD of the socket.
    return server_fd;
}

/*
 * Creates factory of SSL connections, specifying that we want to create a
 * TLS server.
 *
 * @return SSL_CTX -> Configured context.
 */
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Specify method.
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("(error) Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/*
 * Configures the certificate used by the server when any connection asks for a
 * certificate.
 *
 * @param SSL_CTX *ctx -> Context used to create the SSL connections.
 */
void configure_context(SSL_CTX *ctx, char *hostname) {

    EVP_PKEY *key = NULL;
    X509 *crt = NULL;

    generate_certificate(ROOT_CA_KEY_LOCATION, ROOT_CA_CERTIFICATE_LOCATION,
                         &key, &crt, hostname);
    // Set certificate
    if (SSL_CTX_use_certificate(ctx, crt) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set key
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
}

int extractHost(char *source, char *host, char *port) {
    if (sscanf(source, "CONNECT %99[^:]:%s", host, port) != 2) {
        printf("(error) Failed to extract domain.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int create_TLS_connection_with_user(SSL_CTX *ctx,
                                    struct ssl_connection *ssl_connection,
                                    int server_fd) {
    struct sockaddr_in client_address;
    unsigned int address_length = sizeof(client_address);
    SSL *ssl;
    char connect[BUFFER_MAX_SIZE];
    size_t written; // readbytes;

    int connection_fd =
        accept(server_fd, (struct sockaddr *)&client_address, &address_length);

    if (connection_fd < 0) {
        if (errno != EWOULDBLOCK) {
            printf("(error) Error in accept.");
            exit(0);
        }
    }

    // Set fd of the connection.
    ssl_connection->user.fd = connection_fd;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(connection_fd, &read_fds);
    int max_fd = server_fd;

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10;

    int status = select(connection_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (status == 0) {
        printf("(error) Read timed out .\n");
        return EXIT_FAILURE;
    }

    printf("========================== BEGIN "
           "===============================\n");
    printf("Connection fd: %d\n", connection_fd);

    // Read the request from the client.
    int size = read(connection_fd, connect, CONNECT_MAX_SIZE);
    if (size <= 0) {
        printf("(error) Error reading user socket.\n");
        return EXIT_FAILURE;
    }

    connect[size] = '\0';
    printf("(info) Message:\n%s", connect);

    // Set socket to non-block mode.
    if (fcntl(connection_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        close(connection_fd);
        exit(EXIT_FAILURE);
    }

    // Get the hostname and the port.
    extractHost(connect, ssl_connection->hostname, ssl_connection->port);
    strcpy(ssl_connection->sni, ssl_connection->hostname);

    printf("(debug) CONNECT Host: %s / Port: %s\n", ssl_connection->hostname,
           ssl_connection->port);

    // Send a message stating that the connection has been established with
    // the destination server.
    char *proxy_response = DEFAULT_RESPONSE_TO_CLIENT;
    ssize_t bytesSent =
        write(connection_fd, proxy_response, strlen(proxy_response));
    if (bytesSent < 0) {
        perror("(error) Failed to send response to the client\n");
        close(connection_fd);
        exit(1);
    }

    printf("(debug) Message sent!\n");

    // Create a new certificate with the hostname.
    configure_context(ctx, ssl_connection->hostname);

    // Create SSL connection with changed certificate.
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connection_fd);

    if (do_tls_handshake(ssl, connection_fd, 1) == EXIT_FAILURE)
        return EXIT_FAILURE;

    ssl_connection->user.connection = ssl;
    return EXIT_SUCCESS;
}
