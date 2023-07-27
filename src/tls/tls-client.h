#ifndef TLSCLIENT_H

#include "tls-common.h"
#include <openssl/ssl.h>

int create_TLS_connection_with_host_with_changed_SNI(
    SSL_CTX *ctx, struct ssl_connection *ssl_connection);

#endif // !TLS-CLIENT_H
