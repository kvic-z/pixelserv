#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h> 
#include <openssl/x509v3.h> 

#ifdef USE_PTHREAD
#include <pthread.h>
#include <signal.h>
#endif

#include "certs.h"
#include "logger.h"
#include "util.h"

#ifdef USE_PTHREAD

static pthread_mutex_t *locks;

static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
#if 0
    printf("%s: mode = %d, type = %d\n", __FUNCTION__, mode, type);
#endif
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

void ssl_thread_id(CRYPTO_THREADID *id)
{
    unsigned int tid = (unsigned int) pthread_self();
#if 0
    printf("%s: id = %d\n", __FUNCTION__, tid);
#endif
    CRYPTO_THREADID_set_numeric(id, tid);
}

void ssl_init_locks()
{
#ifdef DEBUG
    printf("%s: CRYPTO_num_locks = %d\n", __FUNCTION__, CRYPTO_num_locks());
#endif
    int i;
    locks = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));

    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&(locks[i]), NULL);

    CRYPTO_THREADID_set_callback((void (*)(CRYPTO_THREADID *)) ssl_thread_id);
    CRYPTO_set_locking_callback((void (*)(int, int, const char *, int)) ssl_lock_cb);
}

void ssl_free_locks()
{
    int i;
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(locks[i]));

    OPENSSL_free(locks);
}
#endif //USE_PTHREAD

static void generate_cert(char* pem_fn, const char *pem_dir, X509_NAME *issuer, EVP_MD_CTX *p_ctx)
{
    char *fname = NULL;
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    X509V3_CTX ext_ctx;
    char *san_str = NULL;
    char *tld = NULL, *tld_tmp = NULL;
    int dot_count = 0;

    if(pem_fn[0] == '_') pem_fn[0] = '*';

    // -- generate cert
    RSA *rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
    if(rsa == NULL)
        goto free_all;
#ifdef DEBUG
    printf("%s: rsa key generated for [%s]\n", __FUNCTION__, pem_fn);
#endif
    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa); // rsa will be freed when key is freed
#ifdef DEBUG
    printf("%s: rsa key assigned\n", __FUNCTION__);
#endif
    if((x509 = X509_new()) == NULL)
        goto free_all;
    ASN1_INTEGER_set(X509_get_serialNumber(x509),(unsigned)time(NULL));
    X509_set_version(x509,2); // X509 v3
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); // cert valid for 10yrs
    X509_set_issuer_name(x509, issuer);
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)pem_fn, -1, -1, 0);
    X509V3_set_ctx_nodb(&ext_ctx);

    tld_tmp = strchr(pem_fn, '.');
    while(tld_tmp != NULL){
        dot_count++;
        tld = tld_tmp + 1;
        tld_tmp = strchr(tld, '.');
    }
    tld_tmp = (dot_count == 3 && (atoi(tld) > 0 || (atoi(tld) == 0 && strlen(tld) == 1))) ? "IP" : "DNS";
    asprintf(&san_str, "%s:%s", tld_tmp, pem_fn);
    if ((ext = X509V3_EXT_conf_nid(NULL, &ext_ctx, NID_subject_alt_name, san_str)) == NULL)
        goto free_all;
    X509_add_ext(x509, ext, -1);
    X509_set_pubkey(x509, key);
    X509_sign_ctx(x509, p_ctx);
#ifdef DEBUG
    printf("%s: x509 cert created\n", __FUNCTION__);
#endif

    // -- save cert
    if(pem_fn[0] == '*') pem_fn[0] = '_';
    asprintf(&fname, "%s/%s", pem_dir, pem_fn);
    FILE *fp = fopen(fname, "wb");
    if(fp == NULL) {
        log_msg(LGG_ERR, "Failed to open file for write: %s", fname);
        goto free_all;
    }
    PEM_write_X509(fp, x509);
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    log_msg(LGG_NOTICE, "cert generated and saved: %s", pem_fn);

free_all:
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    free(fname);
    free(san_str);
}


static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) { 
    int rv = 0;
    char *fname = NULL; 
    asprintf(&fname, "%s/ca.key.passphrase", ((cert_tlstor_t*)u)->pem_dir);

    int fp = open(fname, O_RDONLY);    
    if(fp == -1)
        log_msg(LGG_ERR, "Failed to open ca.key.passphrase");
    else {
        rv = read(fp, buf, size);
        close(fp);
#ifdef DEBUG
        buf[rv] = '\0';
        printf("%s: %d, %d\n", buf, size, rv);
#endif
    }
    free(fname);
    return --rv; // trim \n at the end
} 

void *cert_generator(void *ptr) {

#ifdef DEBUG
    printf("%s: thread up and running\n", __FUNCTION__);
#endif
    cert_tlstor_t *cert_tlstor = (cert_tlstor_t *) ptr;
    char *fname = malloc(PIXELSERV_MAX_PATH);
    strcpy(fname, cert_tlstor->pem_dir);
    strcat(fname, "/ca.crt");
    FILE *fp = fopen(fname, "r");
    X509 *x509 = X509_new();
    if(fp == NULL || PEM_read_X509(fp, &x509, NULL, NULL) == NULL)
       log_msg(LGG_ERR, "Failed to read ca.crt");
    fclose(fp);
    free(fname);

    X509_NAME *issuer = X509_NAME_dup(X509_get_subject_name(x509));
    X509_free(x509);

    char *buf = malloc(PIXELSERV_MAX_SERVER_NAME * 4 + 1);
    buf[PIXELSERV_MAX_SERVER_NAME * 4] = '\0';
    char *half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
    int fd = open(PIXEL_CERT_PIPE, O_RDONLY);

    for (;;) {
        int cnt;
        if(fd == -1)
            log_msg(LGG_ERR, "Failed to open %s: %s", PIXEL_CERT_PIPE, strerror(errno));
        strcpy(buf, half_token);
#ifdef DEBUG
        printf("%s 1: %s\n", __FUNCTION__, buf);
#endif
        if((cnt = read(fd, buf + strlen(half_token), PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token))) == 0) {
#ifdef DEBUG
             printf("%s: pipe EOF\n", __FUNCTION__);
#endif
            close(fd);
            fd = open(PIXEL_CERT_PIPE, O_RDONLY);
            continue;
        }
        if (cnt < PIXELSERV_MAX_SERVER_NAME * 4 - strlen(half_token)) {
            buf[cnt + strlen(half_token)] = '\0';
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4;
        } else {
            int i;
            for (i=1; buf[PIXELSERV_MAX_SERVER_NAME * 4 - i]!=':' && i < strlen(buf); i++);
            half_token = buf + PIXELSERV_MAX_SERVER_NAME * 4 - i + 1;
            buf[PIXELSERV_MAX_SERVER_NAME * 4 - i + 1] = '\0';
        }
#ifdef DEBUG
        printf("%s 2: %s\n", __FUNCTION__, buf);
#endif

        fname = malloc(PIXELSERV_MAX_PATH);
        EVP_PKEY *key = NULL;
        EVP_MD_CTX *md_ctx = NULL;

        strcpy(fname, cert_tlstor->pem_dir);
        strcat(fname, "/ca.key");
        FILE *fp = fopen(fname, "r");
        RSA *rsa = NULL;
        if(fp == NULL || PEM_read_RSAPrivateKey(fp, &rsa, pem_passwd_cb, (void*)cert_tlstor) == NULL) {
            log_msg(LGG_ERR, "Failed to open/read ca.key");
        }
        fclose(fp);

        key = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(key, rsa);
        md_ctx = EVP_MD_CTX_create();

        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            strcpy(fname, ((cert_tlstor_t*)cert_tlstor)->pem_dir);
            strcat(fname, "/");
            strcat(fname, p_buf);
            struct stat st;
            if(stat(fname, &st) != 0) {// doesn't exists
                // we don't check disk for cert. Simply re-gen and let it overwrite if exists on disk.
                if(EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key) != 1)
                    log_msg(LGG_ERR, "Failed to init signing context");
                else
                    generate_cert(p_buf, cert_tlstor->pem_dir, issuer, md_ctx);
            }
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }

        EVP_PKEY_free(key);
        EVP_MD_CTX_destroy(md_ctx);
        free(fname);
    }
    X509_NAME_free(issuer);
    free(buf);
    return NULL;
}

static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {

    int rv = SSL_TLSEXT_ERR_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 1 + 1]; /* worst case ':\0' */
    int len;

    full_pem_path[PIXELSERV_MAX_PATH] = '\0';
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    len = strlen(cbarg->tls_pem);
    strncat(full_pem_path, "/", PIXELSERV_MAX_PATH - len);
    ++len;

    char *srv_name = NULL;
    cbarg->servername = (char*)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (cbarg->servername)
        srv_name = (char *)cbarg->servername;
    else if (cbarg->server_ip)
        srv_name = cbarg->server_ip;
    else {
        log_msg(LGG_WARNING, "SNI failed. server name and server ip empty.");
        rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        goto quit_cb;
    }
#ifdef DEBUG
    printf("SNI servername: %s\n", srv_name);
#endif

    int dot_count = 0;
    char *tld = NULL;
    char *pem_file = strchr(srv_name, '.');
    while(pem_file){
        dot_count++;
        tld = pem_file + 1;
        pem_file = strchr(tld, '.');
    }
    if (dot_count == 1 || (dot_count == 3 && atoi(tld) > 0)) {
        pem_file = srv_name;
        strncat(full_pem_path, srv_name, PIXELSERV_MAX_PATH - len);
        len += strlen(srv_name);
    } else {
        pem_file = full_pem_path + strlen(full_pem_path);
        strncat(full_pem_path, "_", PIXELSERV_MAX_PATH - len);
        len += 1;
        strncat(full_pem_path, strchr(srv_name, '.'), PIXELSERV_MAX_PATH - len);
        len += strlen(strchr(srv_name, '.'));
    }
#ifdef DEBUG
    printf("PEM filename: %s\n",full_pem_path);
#endif
    if (len > PIXELSERV_MAX_PATH) {
        log_msg(LGG_ERR, "Buffer overflow. %s", full_pem_path);
        rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        goto quit_cb;
    }
    struct stat st;
    if(stat(full_pem_path, &st) != 0){
        int fd;
        cbarg->status = SSL_MISS;
        log_msg(LGG_WARNING, "%s %s missing", srv_name, pem_file);
        if((fd = open(PIXEL_CERT_PIPE, O_WRONLY)) < 0)
            log_msg(LGG_ERR, "Failed to open %s: %s", PIXEL_CERT_PIPE, strerror(errno));
        else {
            strcat(pem_file, ":");
            write(fd, pem_file, strlen(pem_file));
            close(fd);
        }
        rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        goto quit_cb;
    }

    SSL_CTX *sslctx = NULL;
    sslctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_ecdh_auto(sslctx, 1);
    SSL_CTX_set_options(sslctx,
          SSL_OP_SINGLE_DH_USE |
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "Failed to set cipher list");
    if(SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0
       || SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(sslctx);
        cbarg->status = SSL_ERR;
        log_msg(LGG_ERR, "Cannot use %s\n",full_pem_path);
        rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        goto quit_cb;
    }
    if (cbarg->cachain) {
        X509_INFO *inf; int i;
        for (i=sk_X509_INFO_num(cbarg->cachain)-1; i >= 0; i--) {
            if ((inf = sk_X509_INFO_value(cbarg->cachain, i)) && inf->x509 &&
                    !SSL_CTX_add_extra_chain_cert(sslctx, X509_dup(inf->x509))) {
                SSL_CTX_free(sslctx);
                log_msg(LGG_ERR, "Cannot add CA cert %d\n", i);  /* X509_ref_up requires >= v1.1 */
                rv = SSL_TLSEXT_ERR_ALERT_FATAL;
                goto quit_cb;
            }
        }
    }
    SSL_set_SSL_CTX(ssl, sslctx);
    cbarg->status = SSL_HIT;
    cbarg->sslctx = (void*)sslctx;

quit_cb:

#ifdef DEBUG
    printf("%s: sslctx %p\n", __FUNCTION__, (void*) sslctx);
#endif
    return rv;
}

SSL_CTX * create_default_sslctx(const char *pem_dir) {

    SSL_CTX *sslctx = NULL;
    sslctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_options(sslctx,
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "cipher_list cannot be set");
    SSL_CTX_set_tlsext_servername_callback(sslctx, tls_servername_cb);

    return sslctx;
}

int is_ssl_conn(int fd, char *srv_ip, int srv_ip_len, const int *ssl_ports, int num_ssl_ports) {

    char server_ip[INET6_ADDRSTRLEN] = {'\0'};
    struct sockaddr_storage sin_addr;
    socklen_t sin_addr_len = sizeof(sin_addr);
    char port[NI_MAXSERV] = {'\0'};
    int rv = 0, i;
    errno = 0;
    getsockname(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len,
                   server_ip, sizeof server_ip,
                   port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        log_msg(LGG_ERR, "getnameinfo: %s", strerror(errno));
    if (srv_ip)
        strncpy(srv_ip, server_ip, srv_ip_len);
    for(i=0; i<num_ssl_ports; i++)
        if(atoi(port) == ssl_ports[i])
            rv = 1;
#ifdef DEBUG
    char client_ip[INET6_ADDRSTRLEN]= {'\0'};
    getpeername(fd, (struct sockaddr*)&sin_addr, &sin_addr_len);
    if(getnameinfo((struct sockaddr *)&sin_addr, sin_addr_len, client_ip, \
            sizeof client_ip, NULL, 0, NI_NUMERICHOST) != 0)
        perror("getnameinfo");
    printf("new connection from %s on %s\n", client_ip, port);
#endif

    return rv;
}
