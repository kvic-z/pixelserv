#ifndef _CERTS_H_
#define _CERTS_H_

#include <openssl/pem.h>

#define PIXEL_CERT_PIPE "/tmp/pixelcerts"
#define PIXELSERV_MAX_PATH 1024
#define DEFAULT_PEM_PATH "/opt/var/cache/pixelserv"
#define PIXELSERV_MAX_PATH 1024
#define PIXELSERV_MAX_SERVER_NAME 255

typedef struct {
    const char* pem_dir;
    X509 *cacert;
} cert_tlstor_t;

void ssl_init_locks();
void ssl_free_locks();
void *cert_generator(void *ptr);

#endif
