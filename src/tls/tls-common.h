#ifndef TLS_COMMON_C

#include <openssl/ssl.h>

#define BUFFER_MAX_SIZE 1024
#define DOMAIN_MAX_SIZE 100
#define PORT_MAX_SIZE 5

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

int do_tls_handshake(SSL *ssl, int fd, int type);
int do_tls_shutdown(SSL *ssl, int fd);

#endif // TLS_COMMON_C
