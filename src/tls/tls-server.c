#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../buffer/buffer-reader.h"
#include "../cert/cert.h"
#include "tls-client.h"

#define ROOT_CA_CERTIFICATE_LOCATION "cert/cert-test/rootCA.pem"
#define ROOT_CA_KEY_LOCATION "cert/cert-test/rootCA.key"
#define BUFFER_MAX_SIZE 4096

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
    int socketFd;

    // Creates a new socket.
    if ((socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("(error) Failed to create socket.\n");
        exit(1);
    }

    // Configures the socket to reuse address, for debbuging purporses.
    int option = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Bind the proxy socket to the proxy address
    if (bind(socketFd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("(error) Failed to bind proxy socket\n");
        exit(1);
    }

    // Listen for client connections
    if (listen(socketFd, SOMAXCONN) < 0) {
        perror("(error) Failed to listen for client connections\n");
        exit(1);
    }

    printf("(info) Proxy server listening on port %d\n", port);

    // Returns the FD of the socket.
    return socketFd;
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

void extractHost(char *source, char *host, char *port) {
    if (sscanf(source, "CONNECT %99[^:]:%s", host, port) != 2) {
        fprintf(stderr,
                "Falha ao extrair o domínio e a porta da primeira linha.\n");
    }
}

int create_server_TLS_connection() {
    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_context();

    // Add the correct address to the tcp socket.
    struct sockaddr_in server_address;
    set_address(&server_address, INADDR_ANY, 8080);

    // Create socket and returng the FD.
    int server_fd = create_server_socket(server_address, 8080);

    while (1) {
        struct sockaddr_in client_address;
        unsigned int address_length = sizeof(client_address);
        SSL *ssl;
        char buffer[BUFFER_MAX_SIZE];
        size_t written; // readbytes;

        // Connect to client when connection arrives.
        int client_fd = accept(server_fd, (struct sockaddr *)&client_address,
                               &address_length);
        if (client_fd < 0) {
            perror("(error) Unable to accept\n");
            exit(EXIT_FAILURE);
        }

        printf("========================== BEGIN "
               "===============================\n");

        // Read the request from the client.
        read(client_fd, buffer, BUFFER_MAX_SIZE);
        printf("(info) Message:\n%s", buffer);

        // Get the hostname and the port.
        char host[BUFFER_MAX_SIZE];
        char port[5];
        extractHost(buffer, host, port);

        printf("(debug) CONNECT Host: %s / Port: %s\n", host, port);

        // Send a message stating that the connection has been established with
        // the destination server.
        char *proxy_response = "HTTP/1.1 200 OK\r\n\r\n";
        ssize_t bytesSent =
            write(client_fd, proxy_response, strlen(proxy_response));
        if (bytesSent < 0) {
            perror("(error) Failed to send response to the client\n");
            close(client_fd);
            exit(1);
        }

        printf("(debug) Message sent!\n");

        configure_context(ctx, host);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        // Establishing a TLS connection with the client acting as a server.
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("(info) TLS established!\n");
            memset(buffer, 0, BUFFER_MAX_SIZE);
            SSL_read(ssl, buffer, BUFFER_MAX_SIZE);
            // int total_bytes;
            // char *testando;
            // testando = read_data_from_ssl(ssl, &total_bytes);
            printf("(info) Message received from client (size: %ld):\n%s",
                   strlen(buffer), buffer);
        }

        int readbytes;
        char *response = createTLSConnectionWithChangedSNI(buffer, host, host,
                                                           port, &readbytes);

        if (!SSL_write_ex(ssl, response, readbytes, &written)) {
            printf("(error) Failed to write HTTP request\n");
            exit(EXIT_FAILURE);
        }

        free(response);

        printf(
            "========================== END ===============================\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
}
