#ifndef TLS_COMMON_C

#include <openssl/ssl.h>

int do_tls_handshake(SSL *ssl, int fd, int type);
int do_tls_shutdown(SSL *ssl, int fd);

#endif // TLS_COMMON_C