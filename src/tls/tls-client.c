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

#ifndef BUFFER_MAX_SIZE
#define BUFFER_MAX_SIZE 2048
#endif /* ifndef BUFFER_MAX_SIZE */

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
    int clientFd = create_client_socket(hostname, port);
    if (clientFd <= 0) {
        printf("Failed to create the BIO\n");
        goto end;
    }
    SSL_set_fd(ssl, clientFd);

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
    int max_fd = clientFd + 1; // One more than the highest file descriptor
    FD_ZERO(&read_fds);
    FD_SET(clientFd, &read_fds);

    /* Do the handshake with the server */
    while (1) {
        printf("(debug) Attempt to handshake with %s...\n", hostname);

        int status = SSL_connect(ssl);
        // Connection made successfully
        if (status == 1)
            break;

        int decodedError = SSL_get_error(ssl, status);

        // Error while creating the connection
        if (decodedError == SSL_ERROR_WANT_READ) {
            int result = select(max_fd, &read_fds, NULL, NULL, NULL);

            if (result == -1) {
                printf("Read-select error.\n");
                goto end;
            }
        } else if (decodedError == SSL_ERROR_WANT_WRITE) {
            int result = select(max_fd, NULL, &read_fds, NULL, NULL);

            if (result == -1) {
                printf("Write-select error.\n");
                goto end;
            }
        } else {
            printf("Error creating SSL connection.  err=%x\n", decodedError);
            goto end;
        }
    }

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
    int total_bytes = 0;
    char *response_body = read_data_from_ssl(ssl, &total_bytes);
    printf("(info) Message received from server:\n%s", response_body);

    /*
     * Closing the connection. Try to close until connection returns a success
     * value.
     */
    while (1) {
        printf("Attempt shutdown connection with %s...\n", hostname);

        int err = SSL_shutdown(ssl);
        if (err == 1) {
            break;
        }

        if (err == -1) {
            int decodedError = SSL_get_error(ssl, err);

            if (decodedError == SSL_ERROR_WANT_READ) {
                int result = select(max_fd, &read_fds, NULL, NULL, NULL);
                if (result == -1) {
                    printf("(error) Read-select error while closing the "
                           "connection with %s.\n",
                           hostname);
                    exit(-1);
                }
            } else if (decodedError == SSL_ERROR_WANT_WRITE) {
                int result = select(max_fd, NULL, &read_fds, NULL, NULL);
                if (result == -1) {
                    printf("(error) Write-select error while closing the "
                           "connection with %s.\n",
                           hostname);
                    exit(-1);
                }
            } else {
                printf("(error) Error closing SSL connection.  err=%x\n",
                       decodedError);
                exit(-1);
            }
        }
    }

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

    *bytes = total_bytes;
    return response_body;
}
