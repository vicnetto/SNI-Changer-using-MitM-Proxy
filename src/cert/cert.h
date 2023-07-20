#ifndef CERT_H

#include <openssl/x509v3.h>

int generate_certificate(char *root_ca_key_path, char *root_ca_crt_path,
                         EVP_PKEY **key, X509 **crt, char *hostname);

#endif // !CERT_H
