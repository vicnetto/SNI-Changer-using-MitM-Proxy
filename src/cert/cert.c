// Copyright (c) 2017, 2018, 2019 Linus Karlsson
// Copyright (c) 2023 Victor Netto

#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define RSA_KEY_BITS (4096)

#define DN_COUNTRY "FR"
#define DN_STATE "Lorraine"
#define DN_LOCALITY "Nancy"
#define DN_ORGANIZATION "LORIA"
#define DN_ORGANIZATION_UNIT "RESIST"
#define DN_COMMON_NAME "SNI Changer"

#define PRIVATE_PASSWORD "xarope12"

int load_root_ca_key_and_crt(const char *root_ca_key_path,
                             EVP_PKEY **root_ca_key,
                             const char *root_ca_crt_path, X509 **root_ca_crt) {
    BIO *bio = NULL;

    // Load certificate
    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, root_ca_crt_path))
        goto error;

    *root_ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!*root_ca_crt)
        goto error;

    BIO_free_all(bio);

    // Load private key
    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, root_ca_key_path))
        goto error;

    *root_ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, PRIVATE_PASSWORD);
    if (!root_ca_key)
        goto error;

    BIO_free_all(bio);

    return 1;
error:
    // Free everything in case of error.
    BIO_free_all(bio);
    X509_free(*root_ca_crt);
    EVP_PKEY_free(*root_ca_key);
    return 0;
}

int generate_certificate_key(EVP_PKEY **key, X509_REQ **req) {
    // Create key
    *key = EVP_PKEY_new();
    if (!*key)
        goto error;

    // Create certificate request
    *req = X509_REQ_new();
    if (!*req)
        goto error;

    // After the creation of the key, now it gives a random RSA value to it.
    if ((*key = EVP_RSA_gen(RSA_KEY_BITS)) == NULL) {
        goto error;
    }

    // Associate the key with the certificate.
    X509_REQ_set_pubkey(*req, *key);

    // Set information about the certificate (distinguished name).
    X509_NAME *name = X509_REQ_get_subject_name(*req);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (const unsigned char *)DN_COUNTRY, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                               (const unsigned char *)DN_STATE, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                               (const unsigned char *)DN_LOCALITY, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (const unsigned char *)DN_ORGANIZATION, -1, -1,
                               0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               (const unsigned char *)DN_ORGANIZATION_UNIT, -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)DN_COMMON_NAME, -1, -1,
                               0);

    // Self-sign the certificate to show that we possess the private key
    // associated with the certificate.
    if (!X509_REQ_sign(*req, *key, EVP_sha256()))
        goto error;

    return 1;
error:
    // Free everything if it is not needed.
    EVP_PKEY_free(*key);
    X509_REQ_free(*req);
    return 0;
}

int generate_random_serial(X509 *crt) {
    unsigned char serial_bytes[20];

    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        fprintf(stderr, "(error) Failed to create random sequence os bytes!\n");

        return 0;
    }

    // Transform into number and then to ASN1, to be used as a serial number.
    BIGNUM *bn_serial = BN_new();
    BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn_serial);
    ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn_serial, asn_serial);

    // Ensure the serial number is positive (make it non-negative)
    if (BN_is_negative(bn_serial)) {
        BN_set_negative(bn_serial, 0);
    }

    X509_set_serialNumber(crt, asn_serial);

    ASN1_INTEGER_free(asn_serial);
    BN_free(bn_serial);

    return 1;
}

int sign_certificate(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt,
                     char *hostname) {

    // Create private key and request CSR.
    X509_REQ *req = NULL;
    if (!generate_certificate_key(key, &req))
        return 0;

    *crt = X509_new();
    if (!*crt)
        goto error;

    // Set metadata of the certificate.
    X509_set_version(*crt, 3);
    X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    X509_gmtime_adj(X509_get_notBefore(*crt), 0);
    X509_gmtime_adj(X509_get_notAfter(*crt), 60 * 60 * 24 * 365 * 5); // 5 years

    // Get public key and set to the certificate.
    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(*crt, req_pubkey);

    if (!generate_random_serial(*crt))
        goto error;

    // Set the SAN (subjectNameAlt) to the domain.
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *gen = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, hostname, strlen(hostname));
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, gen);
    X509_add1_ext_i2d(*crt, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);

    // Sign the certificate.
    if (X509_sign(*crt, ca_key, EVP_sha256()) == 0)
        goto error;

    // Free everything.
    X509_REQ_free(req);
    GENERAL_NAMES_free(gens);

    return 1;
error:
    X509_REQ_free(req);
    GENERAL_NAMES_free(gens);
    EVP_PKEY_free(*key);
    X509_free(*crt);

    return 0;
}

int generate_certificate(char *root_ca_key_path, char *root_ca_crt_path,
                         EVP_PKEY **key, X509 **crt, char *hostname) {

    // Load ROOT-CA key and certificate
    EVP_PKEY *root_ca_key = NULL;
    X509 *root_ca_crt = NULL;
    if (!load_root_ca_key_and_crt(root_ca_key_path, &root_ca_key,
                                  root_ca_crt_path, &root_ca_crt)) {
        fprintf(stderr,
                "Failed to load the root certificate and/or the root key!\n");

        return 0;
    }

    // Generate signed key and certificate by the CA.
    int ret = sign_certificate(root_ca_key, root_ca_crt, key, crt, hostname);
    if (!ret) {
        fprintf(stderr, "(error) Failed to sign certificate!\n");
        return 0;
    }

    /* Free stuff. */
    EVP_PKEY_free(root_ca_key);
    X509_free(root_ca_crt);

    return 1;
}
