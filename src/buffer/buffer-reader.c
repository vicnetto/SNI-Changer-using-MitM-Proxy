#include <openssl/ssl.h>
#include <stdlib.h>
#include <unistd.h>

#define FULL_BUFFER_SIZE 1024
#define READER_BUFFER_SIZE 160

char *read_data_from_ssl(SSL *ssl, int *total_bytes) {
    size_t readbytes;
    int current_allocation_size_for_response = FULL_BUFFER_SIZE;
    char read_buffer[READER_BUFFER_SIZE];

    char *body = (char *)malloc(current_allocation_size_for_response);

    // Read all the message sent and put into an allocated space of memory. In
    // case it needs more memory, a realloc is used.
    while (SSL_read_ex(ssl, read_buffer, sizeof(read_buffer), &readbytes)) {
        if (current_allocation_size_for_response - READER_BUFFER_SIZE >=
            *total_bytes)
            memcpy(body + *total_bytes, read_buffer, readbytes);
        else {
            current_allocation_size_for_response *= 2;
            body =
                (char *)realloc(body, current_allocation_size_for_response + 1);
            memcpy(body + *total_bytes, read_buffer, readbytes);
        }

        *total_bytes += readbytes;
    }

    // Realloc the memory to the total response size.
    body = (char *)realloc(body, *total_bytes + 1);
    body[*total_bytes + 1] = '\0';

    return body;
}
