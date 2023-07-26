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
char *createTLSConnectionWithChangedSNI(char *message, const char *hostname,
                                        const char *sni, const char *port,
                                        int *bytes) {

    printf("(info) Creating TLS connection:\n");
    printf("(info) Hostname: %s\n", hostname);
    printf("(info) SNI: %s\n", sni);
    printf("(info) Port: %s\n", port);

    SSL_CTX *ctx = NULL;
    SSL *ssl;
    int response = EXIT_FAILURE, status;
    size_t written, readbytes;
    char buf[READER_BUFFER_SIZE];

    // Add connection close
    printf("(debug) Request to be sent:\n%s", message);

    /*
     * Create a factory of SSL objects. TLS_client_method() specifies that we
     * want the context for creating clients.
     */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("(debug) Failed to create the SSL_CTX\n");
        goto end;
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
        goto end;
    }

    /*
     * Require a minimum TLS version of TLSv1.2.
     */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
        goto end;
    }

    /* Create an SSL object to represent the TLS connection */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create the SSL object\n");
        goto end;
    }

    /*
     * Create the underlying transport socket/BIO and associate it with the
     * connection.
     */
    int client_fd = create_client_socket(hostname, port);
    if (client_fd <= 0) {
        printf("Failed to create the BIO\n");
        goto end;
    }
    SSL_set_fd(ssl, client_fd);

    /*
     * Tell the server during the handshake which hostname we are attempting
     * to connect to in case the server supports multiple hosts. The hostname
     * used is also called SNI. This is the part that we want to change.
     */
    if (!SSL_set_tlsext_host_name(ssl, sni)) {
        printf("Failed to set the SNI hostname\n");
        goto end;
    }

    printf("(debug) SNI changed to: %s\n", sni);

    /*
     * Ensure we check during certificate verification that the server has
     * supplied a certificate for the hostname that we were expecting. This is
     * optional in our process, for the moment.
     */
    if (!SSL_set1_host(ssl, hostname)) {
        printf("Failed to set the certificate verification hostname");
        goto end;
    }

    fd_set read_fds;
    int max_fd = client_fd + 1; // One more than the highest file descriptor
    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);

    printf("(debug) Attempt to handshake with %s...\n", hostname);
    /* Do the handshake with the server */
    do_tls_handshake(ssl, client_fd, 0);

    printf("(debug) Successful handshake!\n");

    // const char *testando = "GET / HTTP/1.1\r\n"
    //                        "Host: www.google.com\r\n"
    //                        "User-Agent: curl/8.1.2\r\n"
    //                        "Accept: */*\r\n\r\n";

    /* Write an HTTP GET request to the peer */
    // const char *request = message;
    status = write_data_in_ssl(ssl, message);
    if (status == WRITE_ERROR)
        goto end;

    printf("(info) Request sent!\n");

    /*
     * Get up to sizeof(buf) bytes of the response. We keep reading until the
     * server closes the connection.
     */
    bool end_connection = false;
    char *response_body = read_data_from_ssl(ssl, &end_connection);
    printf("(info) Message received from server:\n%s", response_body);

    /*
     * Closing the connection. Try to close until connection returns a success
     * value.
     */
    printf("Attempt shutdown connection with %s...\n", hostname);
    do_tls_shutdown(ssl, client_fd);

    printf("(info) Connection closed!\n");

    /* Success! */
    response = EXIT_SUCCESS;
end:
    /*
     * If something bad happened then we will dump the contents of the
     * OpenSSL error stack to stderr. There might be some useful diagnostic
     * information there.
     */
    if (response == EXIT_FAILURE)
        ERR_print_errors_fp(stderr);

    /*
     * Free the resources we allocated. We do not free the BIO object here
     * because ownership of it was immediately transferred to the SSL object
     * via SSL_set_bio(). The BIO will be freed when we free the SSL object.
     */
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // *bytes = total_bytes;
    return response_body;
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
