#ifndef _CERTS_H_
#define _CERTS_H_

#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <pthread.h>

#define PIXEL_SSL_SESS_CACHE_SIZE 128*20
#define PIXEL_SSL_SESS_TIMEOUT 3600 /* seconds */
#define PIXEL_CERT_PIPE "/tmp/pixelcerts"
#ifndef DEFAULT_PEM_PATH
#define DEFAULT_PEM_PATH "/opt/var/cache/pixelserv"
#endif
#define PIXELSERV_MAX_PATH 1024
#define PIXELSERV_MAX_SERVER_NAME 255

/* ECDHE-RSA-AES128-GCM-SHA256 :
   Android >= 4.4.2; Chrome >= 51; Firefox >= 49;
   IE 11 Win 10; Edge >= 13; Safari >= 9; Apple ATS 9 iOS 9
   ECDHE-RSA-AES128-SHA :
   IE 11 Win 7,8.1; IE 11 Winphone 8.1; Opera >= 17; Safar 7 iOS 7.1 */
#define PIXELSERV_CIPHER_LIST \
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES128-SHA"

#if defined(SSL_CTX_set_ecdh_auto)
# define PIXELSRV_SSL_HAS_ECDH_AUTO
#endif

typedef struct {
    const char* pem_dir;
    X509 *cacert;
    void *stk;
    pthread_mutex_t mutex;
    pthread_cond_t cv;
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
    int sslctx_idx;
} tlsext_cb_arg_struct;

typedef struct {
    int new_fd;
    SSL *ssl;
    double init_time;
    tlsext_cb_arg_struct *tlsext_cb_arg;
    int allow_admin;
    tlsext_cb_arg_struct v;
} conn_tlstor_struct;

typedef struct {
    int alloc_len;
    char *cert_name;
    unsigned int last_use; /* seconds since process up */
    int reuse_count;
    SSL_CTX *sslctx;
    pthread_mutex_t lock;
} sslctx_cache_struct;

#define CONN_TLSTOR(p, e) ((conn_tlstor_struct*)p)->e

void ssl_init_locks();
void ssl_free_locks();
void *cert_generator(void *ptr);
void sslctx_tbl_init(int tbl_size);
void sslctx_tbl_cleanup();
void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain);
void sslctx_tbl_save(const char* pem_dir);
void run_benchmark(const char *pem_dir, const STACK_OF(X509_INFO) *cachain, const char *cert);
void sslctx_tbl_lock(int idx);
void sslctx_tbl_unlock(int idx);
int sslctx_tbl_get_cnt_total();
int sslctx_tbl_get_cnt_hit();
int sslctx_tbl_get_cnt_miss();
int sslctx_tbl_get_cnt_purge();
int sslctx_tbl_get_sess_cnt();
int sslctx_tbl_get_sess_hit();
int sslctx_tbl_get_sess_miss();
int sslctx_tbl_get_sess_purge();
SSL_CTX * create_default_sslctx(const char *pem_dir);
int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports);
void conn_stor_init(int slots);
void conn_stor_relinq(conn_tlstor_struct *p);
conn_tlstor_struct* conn_stor_acquire();
void conn_stor_flush();
#endif
