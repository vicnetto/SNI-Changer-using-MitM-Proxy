#ifndef CERT_H

#include <openssl/x509v3.h>

struct root_ca {
    EVP_PKEY *root_ca_key;
    X509 *root_ca_crt;
};

int load_root_ca_key_and_crt(struct root_ca *root_ca, char *key_location,
                             char *cert_location, char *key_password);
int generate_certificate(struct root_ca root_ca, EVP_PKEY **key, X509 **crt,
                         const char *hostname);

#endif // !CERT_H
