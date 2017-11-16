#ifndef _CERTS_H_
#define _CERTS_H_

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define PIXEL_CERT_PIPE "/tmp/pixelcerts"
#define PIXELSERV_MAX_PATH 1024
#define DEFAULT_PEM_PATH "/opt/var/cache/pixelserv"
#define PIXELSERV_MAX_PATH 1024
#define PIXELSERV_MAX_SERVER_NAME 255

/* ECDHE-RSA-AES128-GCM-SHA256 :
   Android >= 4.4.2; Chrome >= 51; Firefox >= 49;
   IE 11 Win 10; Edge >= 13; Safari >= 9; Apple ATS 9 iOS 9
   ECDHE-RSA-AES128-SHA :
   IE 11 Win 7,8.1; IE 11 Winphone 8.1; Opera >= 17; Safar 7 iOS 7.1 */
#define PIXELSERV_CIPHER_LIST \
  "ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-SHA:" \
  "AES128-SHA256:AES128-SHA"

typedef struct {
    const char* pem_dir;
    X509 *cacert;
} cert_tlstor_t;

typedef enum {
  SSL_NOT_TLS,
  SSL_ERR,
  SSL_MISS,
  SSL_HIT,
  SSL_HIT_CLS,
  SSL_UNKNOWN
} ssl_enum;

typedef struct {
    const char *tls_pem;
    const STACK_OF(X509_INFO) *cachain;
    const char *servername;
    char server_ip[INET6_ADDRSTRLEN];
    ssl_enum status;
    void *sslctx;
} tlsext_cb_arg_struct;

typedef struct {
    int new_fd;
    SSL *ssl;
    double init_time;
    tlsext_cb_arg_struct * tlsext_cb_arg;
} conn_tlstor_struct;

#define CONN_TLSTOR(p, e) ((conn_tlstor_struct*)p)->e

void ssl_init_locks();
void ssl_free_locks();
void *cert_generator(void *ptr);
SSL_CTX * create_default_sslctx(const char *pem_dir);
int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports);

#endif
