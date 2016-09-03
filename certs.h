#ifndef _CERTS_H_
#define _CERTS_H_

#include <openssl/pem.h>

#define PIXEL_CERT_PIPE "/tmp/pixelcerts"

typedef struct {
    const char* pem_dir;
    X509 *cacert;
} cert_tlstor_t;

void *cert_generator(void *ptr);

#endif
