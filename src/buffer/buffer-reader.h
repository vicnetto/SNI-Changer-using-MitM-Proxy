#ifndef BUFFER_READER_H

#include <openssl/ssl.h>
#include <stdbool.h>

#define WRITE_ERROR -1

char *read_data_from_ssl(SSL *ssl, bool *end_connection);
int write_data_in_ssl(SSL *ssl, char *message);

#endif // !BUFFER_READER_H
