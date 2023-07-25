#ifndef BUFFER_READER_H

#include <openssl/ssl.h>

char *read_data_from_ssl(SSL *ssl, int *total_bytes);

#endif // !BUFFER_READER_H
