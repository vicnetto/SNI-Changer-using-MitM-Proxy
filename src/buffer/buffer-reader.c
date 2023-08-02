#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "buffer-reader.h"

#define FULL_BUFFER_SIZE 1024
#define READER_BUFFER_SIZE 160
#define SLEEP_TIME 10
#define MAX_RETRIES_TO_START_READING 10
#define MAX_RETRIES_TO_STOP_READING 3

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

char *read_data_from_ssl(SSL *ssl, int *total_bytes) {
    bool first_reading_done = false;
    int attempts_after_end_message = 0;
    int attempts_to_get_first_message = 0;
    int current_allocation_size_for_response = FULL_BUFFER_SIZE;
    *total_bytes = 0;
    int read_bytes = 0;

    char read_buffer[READER_BUFFER_SIZE + 1];
    char *body = (char *)malloc(current_allocation_size_for_response);

    do {
        read_bytes = SSL_read(ssl, read_buffer, READER_BUFFER_SIZE);
        read_buffer[read_bytes] = '\0';

        if (read_bytes <= 0) {
            if (!first_reading_done) {
                attempts_to_get_first_message++;
                m_sleep(SLEEP_TIME);

                if (attempts_to_get_first_message ==
                    MAX_RETRIES_TO_START_READING)
                    return body;

                continue;
            }

            int err = SSL_get_error(ssl, read_bytes);
            if (err == SSL_ERROR_WANT_READ) {
                attempts_after_end_message++;
                m_sleep(SLEEP_TIME);

                if (attempts_after_end_message == MAX_RETRIES_TO_STOP_READING)
                    break;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                printf("\n(error) Want_write in read function!\n");
                exit(0);
                break;
            } else if (err == SSL_ERROR_ZERO_RETURN ||
                       err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                printf("\n(error) ZERO_RETURN - ERROR in read function!\n");
                break;
            }
        } else {
            first_reading_done = true;
            attempts_after_end_message = 0;

            if (current_allocation_size_for_response - READER_BUFFER_SIZE >=
                *total_bytes)
                memcpy(body + *total_bytes, read_buffer, read_bytes);
            else {
                current_allocation_size_for_response *= 2;
                body = (char *)realloc(
                    body, current_allocation_size_for_response + 1);
                memcpy(body + *total_bytes, read_buffer, read_bytes);
            }

            *total_bytes += read_bytes;
        }
    } while (attempts_after_end_message != MAX_RETRIES_TO_STOP_READING);

    body = (char *)realloc(body, *total_bytes + 1);
    body[*total_bytes + 1] = '\0';

    return body;
}

int write_data_in_ssl(SSL *ssl, char *message, int total_bytes) {

    size_t written;

    if (!SSL_write_ex(ssl, message, total_bytes, &written)) {
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
