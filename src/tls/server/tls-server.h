#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include "../../cert/cert.h"

#ifndef INCLUDE_TLS_HANDSHAKE_H
#define INCLUDE_TLS_HANDSHAKE_H
#include "../io/tls-handshake.h"
#endif

#ifndef INCLUDE_CONFIGURATION_H
#define INCLUDE_CONFIGURATION_H
#include "../../config/configuration.h"
#endif

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdint.h>

void set_address(struct sockaddr_in *address, uint32_t ip, uint16_t port);
int create_server_socket(struct sockaddr_in address, int port);
int create_TLS_connection_with_user(SSL_CTX *ctx, struct root_ca root_ca,
                                    struct ssl_connection *ssl_connection,
                                    int server_fd);

#endif // !TLS_SERVER_H
