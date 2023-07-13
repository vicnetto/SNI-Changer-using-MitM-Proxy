#ifndef TLSCLIENT_H

int createTLSConnectionWithChangedSNI(const char *message, const char *hostname,
                                      const char *new_hostname,
                                      const char *port);

#endif // !TLS-CLIENT_H
