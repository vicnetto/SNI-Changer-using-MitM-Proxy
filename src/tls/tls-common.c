#include <openssl/ssl.h>
#include <stdlib.h>

int do_tls_handshake(SSL *ssl, int fd, int type) {

    fd_set read_fds;
    int max_fd = fd + 1; // One more than the highest file descriptor
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    while (1) {
        int status = type == 0 ? SSL_connect(ssl) : SSL_accept(ssl);
        // Connection made successfully
        if (status == 1)
            break;

        int decodedError = SSL_get_error(ssl, status);

        // Error while creating the connection
        if (decodedError == SSL_ERROR_WANT_READ) {
            int result = select(max_fd, &read_fds, NULL, NULL, NULL);

            if (result == -1) {
                printf("Read-select error.\n");
                return EXIT_FAILURE;
            }
        } else if (decodedError == SSL_ERROR_WANT_WRITE) {
            int result = select(max_fd, NULL, &read_fds, NULL, NULL);

            if (result == -1) {
                printf("Write-select error.\n");
                return EXIT_FAILURE;
            }
        } else {
            printf("Error creating SSL connection.  err=%x\n", decodedError);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int do_tls_shutdown(SSL *ssl, int fd) {
    fd_set read_fds;
    int max_fd = fd + 1; // One more than the highest file descriptor
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    /*
     * Closing the connection. Try to close until connection returns a success
     * value.
     */
    while (1) {
        int status = SSL_shutdown(ssl);
        if (status == 1) {
            break;
        }

        if (status == -1) {
            int decodedError = SSL_get_error(ssl, status);

            if (decodedError == SSL_ERROR_WANT_READ) {
                int result = select(max_fd, &read_fds, NULL, NULL, NULL);
                if (result == -1) {
                    printf("(error) Read-select error\n");
                    return EXIT_FAILURE;
                }
            } else if (decodedError == SSL_ERROR_WANT_WRITE) {
                int result = select(max_fd, NULL, &read_fds, NULL, NULL);
                if (result == -1) {
                    printf("(error) Write-select error.\n");
                    return EXIT_FAILURE;
                }
            } else {
                printf("(error) Error closing SSL connection.  err=%x\n",
                       decodedError);
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}