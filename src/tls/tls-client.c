#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * Differently than a normal socket, this function creates a BIO_socket. A
 * BIO_socket gives more control over the communication in the transport
 * layer.
 *
 * @param const char *hostname -> Domain of the website.
 * @param const char *port -> Port of the connection (normally specifies the
 * protocol).
 * @return BIO -> socket;
 */
static BIO *create_socket_bio(const char *hostname, const char *port) {
    int sock = -1;
    BIO_ADDRINFO *ips;
    const BIO_ADDRINFO *address_info = NULL;
    BIO *bio;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, 0, SOCK_STREAM, 0,
                       &ips))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (address_info = ips; address_info != NULL;
         address_info = BIO_ADDRINFO_next(address_info)) {

        /*
         * Create BIO_socket to show errors on the OpenSSL stack.
         *
         * It is also possible to use normal functions, if needed.
         */
        sock = BIO_socket(BIO_ADDRINFO_family(address_info), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        if (!BIO_connect(sock, BIO_ADDRINFO_address(address_info),
                         BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* We have a connected socket so break out of the loop */
        break;
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(ips);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket*/
    bio = BIO_new(BIO_s_socket());
    if (bio == NULL)
        BIO_closesocket(sock);

    /* Associate newly created BIO with the underlying socket. */
    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
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
int createTLSConnectionWithChangedSNI(char *message, const char *hostname,
                                      const char *sni, const char *port) {

    printf("(info) Creating TLS connection:\n");
    printf("(info) Hostname: %s\n", hostname);
    printf("(info) SNI: %s\n", sni);
    printf("(info) Port: %s\n", port);

    SSL_CTX *ctx = NULL;
    SSL *ssl;
    BIO *bio = NULL;
    int response = EXIT_FAILURE;
    size_t written, readbytes;
    char buf[160];

    char request[200] = "GET / HTTP/1.1\r\nConnection: close\r\nHost: ";
    strcat(request, hostname);
    strcat(request, "\r\n\r\n");

    printf("(debug) Request to be sent:\n%s", request);

    /*
     * Create a factory of SSL objects. TLS_client_method() specifies that we
     * want the context for creating clients.
     */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Failed to create the SSL_CTX\n");
        goto end;
    }

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
    bio = create_socket_bio(hostname, port);
    if (bio == NULL) {
        printf("Failed to create the BIO\n");
        goto end;
    }
    SSL_set_bio(ssl, bio, bio);

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

    /* Do the handshake with the server */
    if (SSL_connect(ssl) < 1) {
        printf("Failed to connect to the server\n");
        /*
         * If the failure is due to a verification error we can get more
         * information about it from SSL_get_verify_result().
         */
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            printf("Verify error: %s\n",
                   X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        goto end;
    }

    printf("(debug) Successful handshake!\n");

    /* Write an HTTP GET request to the peer */
    if (!SSL_write_ex(ssl, request, 2048, &written)) {
        printf("Failed to write HTTP request\n");
        goto end;
    }

    printf("(info) Request sent!\n");

    printf("(info) Message received!\n");

    /*
     * Get up to sizeof(buf) bytes of the response. We keep reading until the
     * server closes the connection.
     */

    memset(message, 0, 2048);
    // while (SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {
    //     fwrite(buf, 1, readbytes, stdout);
    // }
    while (SSL_read_ex(ssl, buf, sizeof(buf), &readbytes)) {
        // Concatene os dados lidos no char* teste
        strncat(message, buf, readbytes);
    }
    printf("(info) Message received from server:\n%s", message);
    /* In case the response didn't finish with a newline we add one now */
    printf("\n");

    /*
     * Check whether we finished the while loop above normally or as the
     * result of an error. The 0 argument to SSL_get_error() is the return
     * code we received from the SSL_read_ex() call. It must be 0 in order
     * to get here. Normal completion is indicated by SSL_ERROR_ZERO_RETURN.
     */
    if (SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        /*
         * Some error occurred other than a graceful close down by the
         * peer.
         */
        printf("Failed reading remaining data\n");
        goto end;
    }

    /*
     * The peer already shutdown gracefully (we know this because of the
     * SSL_ERROR_ZERO_RETURN above). We should do the same back.
     */
    if (SSL_shutdown(ssl) < 1) {
        /*
         * ret < 0 indicates an error. ret == 0 would be unexpected here
         * because that means "we've sent a close_notify and we're waiting
         * for one back". But we already know we got one from the peer
         * because of the SSL_ERROR_ZERO_RETURN above.
         */
        printf("Error shutting down\n");
        goto end;
    }

    printf("(info) Closing connection!\n");

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

    return response;
}
