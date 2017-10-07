#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
    asprintf(&san_str, "DNS:%s", pem_fn);
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
        syslog(LOG_ERR, "Failed to open file %s", fname);
        goto free_all;
    }
    PEM_write_X509(fp, x509);
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    syslog(LOG_NOTICE, "cert %s generated and saved", pem_fn);

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
        syslog(LOG_ERR, "Failed to open ca.key.passphrase");
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
       syslog(LOG_ERR, "Failed to open/read ca.crt");
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
            syslog(LOG_ERR, "Failed to open %s: %s", PIXEL_CERT_PIPE, strerror(errno));
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
            syslog(LOG_ERR, "Failed to open/read ca.key");
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
                    syslog(LOG_ERR, "Failed to init signing context");
                else
                    generate_cert(p_buf, cert_tlstor->pem_dir, issuer, md_ctx);
            }
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
        }

//free_all:
        EVP_PKEY_free(key);
        EVP_MD_CTX_destroy(md_ctx);
        free(fname);
    }
    X509_NAME_free(issuer);
    free(buf);
    return NULL;
}
