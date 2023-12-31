#ifndef TLS_COMMON_C

#include <openssl/ssl.h>
#include <stdbool.h>

#ifndef INCLUDE_CONFIGURATION_H
#define INCLUDE_CONFIGURATION_H
#include "../../config/configuration.h"
#endif

struct socket {
    int fd;
    SSL *connection;
};

struct ssl_connection {
    struct socket user;
    struct socket host;
    char hostname[DOMAIN_MAX_SIZE];
    char sni[DOMAIN_MAX_SIZE];
    char port[PORT_MAX_SIZE];
};

int do_tls_handshake(SSL *ssl, int fd, bool is_server);
void clean_SSL_connection(struct ssl_connection *ssl_connection,
                          bool should_free);

#endif // TLS_COMMON_C