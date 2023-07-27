#include <asm-generic/errno.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../buffer/buffer-reader.h"
#include "tls-common.h"

#define READER_BUFFER_SIZE 160

/*
 * Create socket and connect to destination server.
 *
 * @param const char *hostname -> Domain of the website.
 * @param const char *port -> Port of the connection (normally specifies the
 * protocol).
 * @return int -> socket;
 */
static int create_client_socket(const char *hostname, const char *port) {
    struct sockaddr_in serveraddr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    int option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Error: Could not resolve hostname\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(atoi(port));
    memcpy(&serveraddr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) ==
        -1) {
        if (errno != EINPROGRESS) {
            perror("Error connecting to server");
            close(sock);
            exit(EXIT_FAILURE);
        }
    }

    return sock;
}

/*
 * Create a TLS connection and send a simple HTTP/1.1 request to test the
 * connection. In the handshake, change the server_name extension to the value
 * passed as parameter (sni).
 *
 * @param const char *hostname -> Domain of the website.
 * @param const char *sni -> New SNI.
 * @param const char *port -> Port of the connection (normally specifies the
 * protocol).
 * @return int -> 1 if success.
 */
int create_TLS_connection_with_host_with_changed_SNI(
    SSL_CTX *ctx, struct ssl_connection *ssl_connection) {

    printf("(info) Creating TLS connection:\n");
    printf("(info) Hostname: %s\n", ssl_connection->hostname);
    printf("(info) SNI: %s\n", ssl_connection->sni);
    printf("(info) Port: %s\n", ssl_connection->port);

    /*
     * Create a factory of SSL objects. TLS_client_method() specifies that we
     * want the context for creating clients.
     */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("(debug) Failed to create the SSL_CTX\n");
        return EXIT_FAILURE;
    }

    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);

    /*
     * Configure the client to abort the handshake if certificate
     * verification fails.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Use the default trusted certificate store */
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        printf("Failed to set the default trusted certificate store\n");
        return EXIT_FAILURE;
    }

    /*
     * Require a minimum TLS version of TLSv1.2.
     */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
        return EXIT_FAILURE;
    }

    /* Create an SSL object to represent the TLS connection */
    ssl_connection->host.connection = SSL_new(ctx);
    if (ssl_connection->host.connection == NULL) {
        printf("Failed to create the SSL object\n");
        return EXIT_FAILURE;
    }

    /*
     * Create the underlying transport socket/BIO and associate it with the
     * connection.
     */
    int client_fd =
        create_client_socket(ssl_connection->hostname, ssl_connection->port);
    if (client_fd <= 0) {
        printf("Failed to create the BIO\n");
        return EXIT_FAILURE;
    }
    SSL_set_fd(ssl_connection->host.connection, client_fd);

    ssl_connection->host.fd = client_fd;

    /*
     * Tell the server during the handshake which hostname we are attempting
     * to connect to in case the server supports multiple hosts. The hostname
     * used is also called SNI. This is the part that we want to change.
     */
    if (!SSL_set_tlsext_host_name(ssl_connection->host.connection,
                                  ssl_connection->sni)) {
        printf("Failed to set the SNI hostname\n");
        return EXIT_FAILURE;
    }

    printf("(debug) SNI changed to: %s\n", ssl_connection->sni);

    /*
     * Ensure we check during certificate verification that the server has
     * supplied a certificate for the hostname that we were expecting. This is
     * optional in our process, for the moment.
     */
    if (!SSL_set1_host(ssl_connection->host.connection,
                       ssl_connection->hostname)) {
        printf("Failed to set the certificate verification hostname");
        return EXIT_FAILURE;
    }

    printf("(debug) Attempt to handshake with %s...\n",
           ssl_connection->hostname);
    /* Do the handshake with the server */
    do_tls_handshake(ssl_connection->host.connection, client_fd, 0);

    printf("(debug) Successful handshake!\n");

    return 0;
}
