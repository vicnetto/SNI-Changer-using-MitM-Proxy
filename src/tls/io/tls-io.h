#ifndef BUFFER_READER_H

#include <openssl/ssl.h>
#include <stdbool.h>

#ifndef INCLUDE_CONFIGURATION_H
#define INCLUDE_CONFIGURATION_H
#include "../../config/configuration.h"
#endif

char *read_data_from_ssl(SSL *ssl, bool *end_connection, int *total_bytes);
int write_data_in_ssl(SSL *ssl, const char *message, int total_bytes);

#endif // !BUFFER_READER_H
