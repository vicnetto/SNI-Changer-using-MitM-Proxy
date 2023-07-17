#ifndef TLSCLIENT_H

char *createTLSConnectionWithChangedSNI(char *message, const char *hostname,
                                        const char *new_hostname,
                                        const char *port, int *bytes);

#endif // !TLS-CLIENT_H
