#include "buffer/buffer-reader.h"
#include "tls/tls-client.h"
#include "tls/tls-server.h"

#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#define SERVER_PORT 8080
#define MAX_CONNECTIONS 200

/**
 * Iterate through all elements of the connection to update the FD_SET passed as
 * a parameter. This FD_SET will be used by a select function to check if any
 * socket has data to be read.
 *
 * @param ssl_connections -> Array with all connections.
 * @param read_fds -> FD_SET that will be filled.
 * @param max_fd -> Max FD value of the sockets.
 */
void update_FDSET_with_all_connected_sockets(
    const struct ssl_connection *ssl_connections, fd_set *read_fds, int *max_fd,
    int server_fd) {
    FD_ZERO(read_fds);
    FD_SET(server_fd, read_fds);
    *max_fd = server_fd;

    // Iterates over all elements of the connection array.
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        int user_fd = ssl_connections[i].user.fd;
        int host_fd = ssl_connections[i].host.fd;

        // Add FD to the list if available.
        if (user_fd > 0)
            FD_SET(user_fd, read_fds);

        if (host_fd > 0)
            FD_SET(host_fd, read_fds);

        // Find the max value of FD.
        if (user_fd > *max_fd)
            *max_fd = user_fd;

        if (host_fd > *max_fd)
            *max_fd = host_fd;
    }
}

/**
 * Find a not used position on the ssl_connection list.
 *
 * @param ssl_connections -> List of all connections.
 * @return -> >= 0 in case of free position, otherwise -1.
 */
int find_empty_position_in_ssl_connection_list(
    const struct ssl_connection *ssl_connections) {

    for (int i = 0; i < MAX_CONNECTIONS; i++) {

        // If position is empty, return the position.
        if (ssl_connections[i].user.fd == 0) {
            return i;
        }
    }

    return -1;
}

/**
 * Verify if the system socket is still open.
 *
 * @param ssl_connection -> Connection attached to the socket to clean if the
 * socket is closed.
 * @param socket_fd -> Socket fd.
 * @return -> True if is still open, and false if it isn't.
 */
bool is_socket_still_open(struct ssl_connection *ssl_connection,
                          int socket_fd) {
    char socket_peek;

    // Make a peek in the socket (without blocking), to see if it is possible to
    // use the socket.
    if (recv(socket_fd, &socket_peek, 1, MSG_PEEK) == 0) {
        clean_SSL_connection(ssl_connection, true);
        return false;
    }

    return true;
}

/**
 * Create two TLS connections, one with the user and another with the
 * destination server.
 *
 * @param ctx -> All the configuration of the SSL connection.
 * @param root_ca -> Root certificate.
 * @param ssl_connection -> In which element of the array the connection will be
 * saved.
 * @param server_fd -> FD of the server socket.
 */
int create_two_sided_tls_handshake(SSL_CTX *ctx, struct root_ca root_ca,
                                   struct ssl_connection *ssl_connection,
                                   int server_fd) {
    // Create TLS with the user.
    int status = create_TLS_connection_with_user(ctx, root_ca, ssl_connection,
                                                 server_fd);

    // If everything went wrong, clean the SSL connection and continues.
    if (status == -1) {
        clean_SSL_connection(ssl_connection, true);
        return -1;
    } else {
        // Create TLS with the destination server.
        status = create_TLS_connection_with_host_with_changed_SNI(
            ctx, ssl_connection);

        // In case of failure, clean the SSL connection.
        if (status == -1) {
            clean_SSL_connection(ssl_connection, true);
            return -1;
        }
    }

    return 0;
}

/**
 * Establish a new connection with the user and the host.
 *
 * @param ctx -> Configure context to create SSL connections.
 * @param root_ca -> Root certificate.
 * @param ssl_connections -> All the current connections.
 * @param server_fd -> Server FD to listen to connections.
 * @return -> 0 success, -1 otherwise.
 */
int establish_new_connection(SSL_CTX *ctx, struct root_ca root_ca,
                             struct ssl_connection *ssl_connections,
                             int server_fd) {
    printf("(debug) > NEW CONNECTION <\n");

    int empty_position =
        find_empty_position_in_ssl_connection_list(ssl_connections);
    printf("(info) Empty position: %d\n", empty_position);

    // There is no more space in the array to create a new connection.
    if (empty_position == -1) {
        printf("(error) Missing space for instanciating new "
               "connections.\n");
        exit(1);
    }

    if (create_two_sided_tls_handshake(
            ctx, root_ca, &ssl_connections[empty_position], server_fd) == -1) {
        printf("(debug) > END CONNECTION (FAILED) <\n");
        return -1;
    }

    printf("(debug) > CONNECTION ESTABLISHED <\n");

    return 0;
}

/**
 * Send a message from a origin to a destination, using TCP tunnels with SSL
 * encryption.
 *
 * @param ssl_connection -> Connection information.
 * @param is_host_destination -> True if destination is the host, and false if
 * it is the user.
 * @return -> 0 success, -1 otherwise.
 */
int transfer_SSL_message(struct ssl_connection *ssl_connection,
                         bool is_host_destination) {
    int total_bytes;

    SSL *origin = is_host_destination ? ssl_connection->user.connection
                                      : ssl_connection->host.connection;
    SSL *destination = is_host_destination ? ssl_connection->host.connection
                                           : ssl_connection->user.connection;

    bool end_connection = false;
    char *request_body = read_data_from_ssl(origin, &end_connection, &total_bytes);

    if (end_connection) {
        clean_SSL_connection(ssl_connection, true);

        return -1;
    } else {
        write_data_in_ssl(destination, request_body, total_bytes);

        if (is_host_destination) {
            printf("(debug) Request sent from %d to %s!\n",
                   ssl_connection->user.fd, ssl_connection->hostname);
        } else {
            printf("(debug) Response sent from %s to %d!\n",
                   ssl_connection->hostname, ssl_connection->user.fd);
        }
    }

    free(request_body);

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        printf(
            "Usage: %s <root-ca-location> <root-key-location> <key-password>\n",
            argv[0]);
        return 1;
    }

    struct root_ca root_ca;
    // Load ROOT-CA key and certificate
    if (load_root_ca_key_and_crt(&root_ca, argv[2], argv[1], argv[3]) == -1) {
        fprintf(stderr,
                "Failed to load the root certificate and/or the root key!\n");
        return -1;
    }

    // Ignore broken pipe signals (OpenSSL recommendation).
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = create_ssl_context();

    // Add the correct address to the tcp socket and create server socket.
    struct sockaddr_in server_address;
    set_address(&server_address, INADDR_ANY, SERVER_PORT);
    int server_fd = create_server_socket(server_address, 8080);

    // Create array with the information of all connections.
    struct ssl_connection ssl_connections[MAX_CONNECTIONS];

    // Initialize all sockets with zero.
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clean_SSL_connection(&ssl_connections[i], false);
    }

    fd_set read_fds;

    while (1) {
        int max_fd = server_fd;
        update_FDSET_with_all_connected_sockets(ssl_connections, &read_fds,
                                                &max_fd, server_fd);

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            printf("(error) Error in user select!\n");
            exit(0);
        }

        // New connection to the server
        if (FD_ISSET(server_fd, &read_fds) &&
            establish_new_connection(ctx, root_ca, ssl_connections,
                                     server_fd) == -1) {
            continue;
        }

        int current_user_fd;
        int current_host_fd;

        // Read all sockets to see if message has arrived.
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            struct ssl_connection *current_connection = &ssl_connections[i];
            current_user_fd = ssl_connections[i].user.fd;
            current_host_fd = ssl_connections[i].host.fd;

            if (!is_socket_still_open(current_connection, current_user_fd) ||
                !is_socket_still_open(current_connection, current_host_fd))
                break;

            // Verify if any request was sent by the user.
            if (FD_ISSET(current_user_fd, &read_fds)) {
                transfer_SSL_message(&ssl_connections[i], true);
                continue;
            }

            // Verify if any response was sent by the host.
            if (FD_ISSET(current_host_fd, &read_fds)) {
                transfer_SSL_message(&ssl_connections[i], false);
                continue;
            }
        }
    }
}