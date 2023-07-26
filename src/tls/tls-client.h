#ifndef TLSCLIENT_H

#include "tls-common.h"
#include <openssl/ssl.h>

char *createTLSConnectionWithChangedSNI(char *message, const char *hostname,
                                        const char *new_hostname,
                                        const char *port, int *bytes);

int create_TLS_connection_with_host_with_changed_SNI(
    SSL_CTX *ctx, struct ssl_connection *ssl_connection);

#endif // !TLS-CLIENT_H
