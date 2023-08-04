#ifndef CONFIGURATION_H
#define CONFIGURATION_H

// Server.
#define SERVER_PORT 8080
#define MAX_CONNECTIONS 200

// TLS.
#define DOMAIN_MAX_SIZE 255
#define PORT_MAX_SIZE 5
#define RESPONSE_TIMEOUT_MS 50
#define DEFAULT_RESPONSE_TO_CLIENT "HTTP/1.1 200 OK\r\n\r\n"

// TLS IO.
#define BUFFER_SIZE 4096
#define IO_WAIT_TIME_MS 10
#define MAX_RETRIES_TO_START_READING 10
#define MAX_RETRIES_TO_STOP_READING 3

// Certificate.
#define RSA_KEY_BITS (4096)
#define DN_COUNTRY "FR"
#define DN_STATE "Lorraine"
#define DN_LOCALITY "Nancy"
#define DN_ORGANIZATION "LORIA"
#define DN_ORGANIZATION_UNIT "RESIST"

// Configuration.
#define CONFIGURATION_FILE_NAME "sni.conf"

struct sni_change {
    char domain[DOMAIN_MAX_SIZE];
    char sni[DOMAIN_MAX_SIZE];
};

int read_config_file(struct sni_change **sni_changes);

#endif // CONFIGURATION_H
