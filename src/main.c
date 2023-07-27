#include "buffer/buffer-reader.h"
#include "cert/cert.h"
#include "tls/tls-client.h"
#include "tls/tls-server.h"

#include <netinet/in.h>
#include <openssl/err.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define ROOT_CA_CERTIFICATE_LOCATION "cert/cert-test/rootCA.pem"
#define ROOT_CA_KEY_LOCATION "cert/cert-test/rootCA.key"
#define MAX_CONNECTIONS 20

/*
 * Creates factory of SSL connections, specifying that we want to create a
 * TLS server.
 *
 * @return SSL_CTX -> Configured context.
 */
SSL_CTX *create_ssl_context() {
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
void configure_ssl_context(SSL_CTX *ctx, char *hostname) {

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

void update_FDSET_with_all_connected_sockets(
    struct ssl_connection *ssl_connections, fd_set *read_fds, int *max_fd) {

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        int client_fd = ssl_connections[i].user.fd;
        int server_fd = ssl_connections[i].host.fd;

        // Add sd to the list of select.
        if (client_fd > 0)
            FD_SET(client_fd, read_fds);

        if (server_fd > 0)
            FD_SET(server_fd, read_fds);

        // Find the max value of sd, to the select function.
        if (client_fd > *max_fd)
            *max_fd = client_fd;

        if (server_fd > *max_fd)
            *max_fd = server_fd;
    }
}

int find_empty_position_in_ssl_connection_list(
    struct ssl_connection *ssl_connections) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {

        // If position is empty
        if (ssl_connections[i].user.fd == 0) {
            return i;
        }
    }

    return -1;
}

void free_data_in_SSL_connection(struct ssl_connection *ssl_connection) {
    if (ssl_connection->user.connection != NULL)
        SSL_free(ssl_connection->user.connection);

    if (ssl_connection->host.connection != NULL)
        SSL_free(ssl_connection->host.connection);

    if (ssl_connection->user.fd != 0)
        close(ssl_connection->user.fd);

    if (ssl_connection->host.fd != 0)
        close(ssl_connection->host.fd);
}

void clean_data_in_SSL_connection(struct ssl_connection *ssl_connection) {
    ssl_connection->user.fd = 0;
    ssl_connection->user.connection = NULL;

    ssl_connection->host.fd = 0;
    ssl_connection->host.connection = NULL;

    memset(ssl_connection->hostname, 0, DOMAIN_MAX_SIZE);
    memset(ssl_connection->sni, 0, DOMAIN_MAX_SIZE);
    memset(ssl_connection->port, 0, PORT_MAX_SIZE);
}

void free_and_clean_SSL_connection(struct ssl_connection *ssl_connection) {
    free_data_in_SSL_connection(ssl_connection);
    clean_data_in_SSL_connection(ssl_connection);
}

void free_and_clean_all_SSL_connections(struct ssl_connection *ssl_connection, int is_first_part) {
    int begin = is_first_part ? 0 : MAX_CONNECTIONS / 2;
    int end = is_first_part ? MAX_CONNECTIONS / 2 : MAX_CONNECTIONS;

    for (int i = begin; i < end; i++) {
        free_data_in_SSL_connection(&ssl_connection[i]);
        clean_data_in_SSL_connection(&ssl_connection[i]);
    }
}

int main(int argc, char *argv[]) {

    // Ignore broken pipe signals.
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_ssl_context();

    // Add the correct address to the tcp socket.
    struct sockaddr_in server_address;
    set_address(&server_address, INADDR_ANY, SERVER_PORT);

    // Create socket and returng the FD.
    int server_fd = create_server_socket(server_address, 8080);

    struct ssl_connection ssl_connections[MAX_CONNECTIONS];
    fd_set read_fds;

    // Initialize all sockets with zero.
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clean_data_in_SSL_connection(&ssl_connections[i]);
    }

    bool is_first_part = true;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        int max_fd = server_fd;

        update_FDSET_with_all_connected_sockets(ssl_connections, &read_fds,
                                                &max_fd);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            printf("(error) Error in user select!\n");
            exit(0);
        }

        // New connection to the server
        if (FD_ISSET(server_fd, &read_fds)) {
            int empty_position =
                find_empty_position_in_ssl_connection_list(ssl_connections);
            printf("(info) Empty position: %d\n", empty_position);

            if (empty_position == -1) {
                free_and_clean_all_SSL_connections(ssl_connections, is_first_part);
                is_first_part = !is_first_part;
                empty_position =
                find_empty_position_in_ssl_connection_list(ssl_connections);
            }

            // Create TLS with user and host.
            if (create_TLS_connection_with_user(
                    ctx, &ssl_connections[empty_position], server_fd) ==
                EXIT_FAILURE) {
                free_and_clean_SSL_connection(&ssl_connections[empty_position]);
                continue;
            }

            if (create_TLS_connection_with_host_with_changed_SNI(
                    ctx, &ssl_connections[empty_position]) == EXIT_FAILURE) {
                free_and_clean_SSL_connection(&ssl_connections[empty_position]);
                continue;
            }
        }

        // Read all sockets to see if message has arrived.
        int current_user_fd, current_host_fd;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            current_user_fd = ssl_connections[i].user.fd;
            current_host_fd = ssl_connections[i].host.fd;

            // Verify if any request was sent by the user.
            if (FD_ISSET(current_user_fd, &read_fds)) {
                int total_bytes;
                bool end_connection = false;
                char *request_body =
                    read_data_from_ssl(ssl_connections[i].user.connection,
                                       &end_connection, &total_bytes);

                if (end_connection) {
                    printf(
                        "\n(info) Connection closed with %s and socket %d!\n",
                        ssl_connections[i].hostname, current_user_fd);

                    free_and_clean_SSL_connection(&ssl_connections[i]);
                    break;
                } else {
                    write_data_in_ssl(ssl_connections[i].host.connection,
                                      request_body, total_bytes);
                    printf("(debug) Message sent:\n%s\n", request_body);
                }

                free(request_body);
                continue;
            }

            // Verify if any response was sent by the host.
            if (FD_ISSET(current_host_fd, &read_fds)) {
                int total_bytes = 0;
                bool end_connection = false;
                char *response_body =
                    read_data_from_ssl(ssl_connections[i].host.connection,
                                       &end_connection, &total_bytes);

                if (end_connection) {
                    printf("(info) Connection closed with %s and socket %d\n",
                           ssl_connections[i].hostname, current_host_fd);

                    free_and_clean_SSL_connection(&ssl_connections[i]);
                    break;
                } else {
                    write_data_in_ssl(ssl_connections[i].user.connection,
                                      response_body, total_bytes);
                    printf("(debug) Response:\n%s\n", response_body);
                }

                free(response_body);
                continue;
            }
        }
    }

    free_and_clean_all_SSL_connections(ssl_connections, true);
    free_and_clean_all_SSL_connections(ssl_connections, false);

    return 0;
}
