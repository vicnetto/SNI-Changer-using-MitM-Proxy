#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "buffer-reader.h"

#define FULL_BUFFER_SIZE 1024
#define READER_BUFFER_SIZE 160
#define SLEEP_TIME 10
#define MAX_RETRIES 3

/*
 * Sleep for m_sec miliseconds.
 *
 * @param long m_sec -> Quantity in miliseconds.
 */
static int m_sleep(long m_sec) {
    struct timespec ts;
    int res;

    if (m_sec < 0) {
        errno = EINVAL;
        return -1;
    }

    // Distribute milisseconds into seconds and nanoseconds.
    ts.tv_sec = m_sec / 1000;
    ts.tv_nsec = (m_sec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

char *read_data_from_ssl(SSL *ssl, bool *end_connection) {
    int total_bytes = 0;
    int read_bytes;
    bool has_done_reading = false;
    int current_allocation_size_for_response = FULL_BUFFER_SIZE;
    char read_buffer[READER_BUFFER_SIZE + 1];
    char *body = (char *)malloc(current_allocation_size_for_response);
    int retry_read = 0;

    do {
        read_bytes = SSL_read(ssl, read_buffer, READER_BUFFER_SIZE);
        read_buffer[read_bytes] = '\0';

        if (read_bytes <= 0) {
            if (read_bytes == 0) {
                *end_connection = true;
                return body;
            }

            if (!has_done_reading)
                continue;

            int err = SSL_get_error(ssl, read_bytes);
            if (err == SSL_ERROR_WANT_READ) {
                retry_read++;
                m_sleep(SLEEP_TIME);

                if (retry_read == MAX_RETRIES)
                    break;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                printf("\n(error) Want_write in read function!\n");
                break;
            }
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL ||
                err == SSL_ERROR_SSL) {
                printf("\n(error) ZERO_RETURN - ERROR in read function!\n");
                break;
            }
        } else {
            has_done_reading = true;
            retry_read = 0;

            if (current_allocation_size_for_response - READER_BUFFER_SIZE >=
                total_bytes)
                memcpy(body + total_bytes, read_buffer, read_bytes);
            else {
                current_allocation_size_for_response *= 2;
                body = (char *)realloc(
                    body, current_allocation_size_for_response + 1);
                memcpy(body + total_bytes, read_buffer, read_bytes);
            }

            total_bytes += read_bytes;
        }
    } while (retry_read != MAX_RETRIES);

    body = (char *)realloc(body, total_bytes + 1);
    body[total_bytes + 1] = '\0';

    return body;
}

int write_data_in_ssl(SSL *ssl, char *message) {

    size_t written;

    if (!SSL_write_ex(ssl, message, strlen(message), &written)) {
        printf("(error) Failed to write HTTP request.\n");

        int status = SSL_get_error(ssl, written);

        switch (status) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            printf("(error) Write/read error.\n");
            return WRITE_ERROR;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            printf("(error) Error within the SSL connection.\n");
            return WRITE_ERROR;
        }
    }

    return written;
}
