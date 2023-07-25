#ifndef BUFFER_READER_H

#include <openssl/ssl.h>

#define WRITE_ERROR -1

char *read_data_from_ssl(SSL *ssl, int *total_bytes);
int write_data_in_ssl(SSL *ssl, char *message);

#endif // !BUFFER_READER_H
