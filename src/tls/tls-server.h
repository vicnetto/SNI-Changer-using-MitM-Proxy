#ifndef TLS_SERVER_H

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdint.h>

void set_address(struct sockaddr_in *address, uint32_t ip, int port);
int create_server_socket(struct sockaddr_in address, int port);
int create_TLS_connection_with_user(SSL_CTX *ctx,
                                    struct ssl_connection *ssl_connections,
                                    struct ssl_connection *ssl_connection,
                                    int max_connections, int server_fd);

#endif // !TLS_SERVER_H
