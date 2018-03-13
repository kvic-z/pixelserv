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
#include <pthread.h>
#include <signal.h>

#include "certs.h"
#include "logger.h"
#include "util.h"

static SSL_CTX *g_sslctx;
static pthread_mutex_t *locks;

static sslctx_cache_struct *sslctx_tbl;
static int sslctx_tbl_size, sslctx_tbl_end;
static int sslctx_tbl_cnt_hit, sslctx_tbl_cnt_miss, sslctx_tbl_cnt_purge;

#define SSLCTX_TBL_ptr(h)         ((sslctx_cache_struct *)(sslctx_tbl + h))
#define SSLCTX_TBL_get(h, k)      SSLCTX_TBL_ptr(h)->k
#define SSLCTX_TBL_set(h, k, v)   SSLCTX_TBL_ptr(h)->k = v

inline int sslctx_tbl_get_cnt_total() { return sslctx_tbl_end; }
inline int sslctx_tbl_get_cnt_hit() { return sslctx_tbl_cnt_hit; }
inline int sslctx_tbl_get_cnt_miss() { return sslctx_tbl_cnt_miss; }
inline int sslctx_tbl_get_cnt_purge() { return sslctx_tbl_cnt_purge; }
inline int sslctx_tbl_get_sess_cnt() { return SSL_CTX_sess_number(g_sslctx); }
inline int sslctx_tbl_get_sess_hit() { return SSL_CTX_sess_hits(g_sslctx); }
inline int sslctx_tbl_get_sess_miss() { return SSL_CTX_sess_misses(g_sslctx); }
inline int sslctx_tbl_get_sess_purge() { return SSL_CTX_sess_cache_full(g_sslctx); }

static int sslctx_tbl_cache(const char *cert_name, SSL_CTX *sslctx, int ins_idx);
static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain);

void sslctx_tbl_init(int tbl_size)
{
    sslctx_tbl_end = 0;
    sslctx_tbl = malloc(tbl_size * sizeof(sslctx_cache_struct));
    if (!sslctx_tbl)
    {
        sslctx_tbl_size = 0;
        log_msg(LGG_ERR, "Failed to allocate sslctx_tbl of size %d", tbl_size);
    } else {
        sslctx_tbl_size = tbl_size;
        sslctx_tbl_cnt_hit = sslctx_tbl_cnt_miss = sslctx_tbl_cnt_purge = 0;
        memset(sslctx_tbl, 0, tbl_size * sizeof(sslctx_cache_struct));
    }
}

void sslctx_tbl_cleanup()
{
    int idx;
    for (idx = 0; idx < sslctx_tbl_end; idx++)
    {
        free(SSLCTX_TBL_get(idx, cert_name));
        SSL_CTX_free(SSLCTX_TBL_get(idx, sslctx));
    }
}

void sslctx_tbl_load(const char* pem_dir, const STACK_OF(X509_INFO) *cachain)
{
    char *line = malloc(PIXELSERV_MAX_PATH);
    char *fname = NULL;
    asprintf(&fname, "%s/prefetch", pem_dir);
    FILE *fp = fopen(fname, "r");
    if(fp == NULL)
    {
        log_msg(LGG_WARNING, "%s: %s doesn't exist.", __FUNCTION__, fname);
        goto quit_load;
    }
    free(fname);
    while (getline(&line, &(size_t){ PIXELSERV_MAX_PATH }, fp) != -1)
    {
        char *cert_name = strtok(line, " \n\t");
        asprintf(&fname, "%s/%s", pem_dir, cert_name);
        SSL_CTX *sslctx = create_child_sslctx(fname, cachain);
        if (sslctx)
        {
            int ins_idx = sslctx_tbl_end;
            sslctx_tbl_cache(cert_name, sslctx, ins_idx);
            /* Randomize last_flush a bit to avoid avalanche later.
               Don't care about randomness. Hence, no seeding */
            SSLCTX_TBL_set(ins_idx, last_flush, process_uptime() + 300.0 * rand() / RAND_MAX);
            log_msg(LGG_NOTICE, "%s: %s", __FUNCTION__, cert_name);
        }
        free(fname);
        if (sslctx_tbl_end >= sslctx_tbl_size)
            break;
    }
    fclose(fp);
    sslctx_tbl_cnt_miss = 0; /* reset */
quit_load:
    free(line);
}

static int cmp_sslctx_reuse_count(const void *p1, const void *p2)
{
    /* reverse order */
    return ((sslctx_cache_struct *)p2)->reuse_count - ((sslctx_cache_struct *)p1)->reuse_count;
}

void sslctx_tbl_save(const char* pem_dir)
{
    #define RATIO_TO_SAVE (3.0 / 4.0)
    int idx;
    char *fname = NULL;
    asprintf(&fname, "%s/prefetch", pem_dir);
    FILE *fp = fopen(fname, "w");
    if(fp == NULL)
    {
        log_msg(LGG_ERR, "%s: Failed to open %s", __FUNCTION__, fname);
        goto quit_save;
    }
    qsort(SSLCTX_TBL_ptr(0), sslctx_tbl_end, sizeof(sslctx_cache_struct), cmp_sslctx_reuse_count);
    if (sslctx_tbl_end > (sslctx_tbl_size * RATIO_TO_SAVE))
        sslctx_tbl_end = sslctx_tbl_size * RATIO_TO_SAVE;

    for (idx=0; idx < sslctx_tbl_end; idx++)
        fprintf(fp, "%s\t%d\n", SSLCTX_TBL_get(idx, cert_name), SSLCTX_TBL_get(idx, reuse_count));
    fclose(fp);
quit_save:
    free(fname);
}

void sslctx_tbl_lock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size)
    {
        log_msg(LOG_DEBUG, "%s: invalid idx %d", __FUNCTION__, idx);
        return;
    }
    pthread_mutex_lock(&SSLCTX_TBL_get(idx, lock));
}

void sslctx_tbl_unlock(int idx)
{
    if (idx < 0 || idx >= sslctx_tbl_size)
    {
        log_msg(LOG_DEBUG, "%s: invalid idx %d", __FUNCTION__, idx);
        return;
    }
    pthread_mutex_unlock(&SSLCTX_TBL_get(idx, lock));
}

/*
static int sslctx_tbl_check_and_flush(int idx)
{
    int pixel_now = process_uptime();
#ifdef DEBUG
    printf("%s: %s now %d last_flush %d last_use %d", __FUNCTION__, SSLCTX_TBL_get(idx, cert_name), 
        pixel_now, SSLCTX_TBL_get(idx, last_flush), SSLCTX_TBL_get(idx, last_use));
#endif
    if (SSLCTX_TBL_get(idx, last_flush) > SSLCTX_TBL_get(idx, last_use))
        return -1;

    // check and flush every 3600s at most
    int do_flush = pixel_now - SSLCTX_TBL_get(idx, last_flush) - 3600;
    if (do_flush < 0)
        return -1;

    struct timespec now;
    get_time(&now);
    sslctx_tbl_lock(idx);
    SSL_CTX_flush_sessions(SSLCTX_TBL_get(idx, sslctx), (long)now.tv_sec);
    sslctx_tbl_unlock(idx);
    SSLCTX_TBL_set(idx, last_flush, pixel_now);
    log_msg(LGG_NOTICE, "flushed expired TLS sessions (%s)", SSLCTX_TBL_get(idx, cert_name));
    return 1;
}*/

static int sslctx_tbl_lookup(char* cert_name, int* found_idx, int* ins_idx)
{
    if (!cert_name || !found_idx || !ins_idx) {
        log_msg(LOG_ERR, "Invalid params. cert_name: %s. found_idx: %d, ins_idx: %d",
            cert_name, found_idx, ins_idx);
        return -1;
    }
    *found_idx = -1; *ins_idx = -1;
    int _name_len = strlen(cert_name);
    int _last_use = process_uptime();
    int purge_idx = sslctx_tbl_end;
    int idx;
    for (idx = 0; idx < sslctx_tbl_end; idx++)
    {
        if (SSLCTX_TBL_get(idx, last_use) < _last_use)
        {
            _last_use = SSLCTX_TBL_get(idx, last_use);
            purge_idx = idx;
        }
        if (_name_len != SSLCTX_TBL_get(idx, name_len))
            continue;
        if (_name_len > 10 && (SSLCTX_TBL_get(idx, cert_name)[7] != cert_name[7] ||
            SSLCTX_TBL_get(idx, cert_name)[10] != cert_name[10]))
            continue;
        if (memcmp(cert_name, SSLCTX_TBL_get(idx, cert_name), _name_len) == 0)
        {
            *found_idx = idx;
            sslctx_tbl_cnt_hit++;
            SSLCTX_TBL_ptr(idx)->reuse_count++;
            SSLCTX_TBL_set(idx, last_use, process_uptime());

            return 0;
        }
    }
    if (sslctx_tbl_end == sslctx_tbl_size)
    {
        if (purge_idx == sslctx_tbl_size)
        {
            log_msg(LOG_ERR, "Failed to find candiate in sslctx_tbl for purge.");
            purge_idx = 0; /* decimate the first entry */
        }
        *ins_idx = purge_idx;
    }
    else
        *ins_idx = sslctx_tbl_end;
    return 0;
}

static int sslctx_tbl_cache(const char *cert_name, SSL_CTX *sslctx, int ins_idx)
{
    if (cert_name == NULL || sslctx == NULL || ins_idx >= sslctx_tbl_size || ins_idx < 0)
    {
        log_msg(LOG_ERR, "Invalid params. cert_name: %s. sslctx: %d, ins_idx: %d",
            cert_name, sslctx, ins_idx);
        return -1;
    }
    sslctx_tbl_cnt_miss++;

    /* add new cache entry */
    unsigned int pixel_now = process_uptime();
    int len = strlen(cert_name);
    char *str = SSLCTX_TBL_get(ins_idx, cert_name);
    if ((len + 1) > SSLCTX_TBL_get(ins_idx, alloc_len))
    {
        str = realloc(str, len + 1);
        SSLCTX_TBL_set(ins_idx, alloc_len, len + 1);
    }
    strncpy(str, cert_name, len + 1);
    SSLCTX_TBL_set(ins_idx, cert_name, str);
    SSLCTX_TBL_set(ins_idx, name_len, len);
    SSLCTX_TBL_set(ins_idx, last_use, pixel_now);
    SSLCTX_TBL_set(ins_idx, last_flush, pixel_now);
    if (ins_idx == sslctx_tbl_end && sslctx_tbl_end < sslctx_tbl_size)
        sslctx_tbl_end++;
    else {
#ifdef DEBUG
        printf("%s: SSL_CTX_free sslctx %p\n", __FUNCTION__, SSLCTX_TBL_get(ins_idx, sslctx));
#endif
        sslctx_tbl_lock(ins_idx);
        SSL_CTX_free(SSLCTX_TBL_get(ins_idx, sslctx));
        sslctx_tbl_unlock(ins_idx);
        sslctx_tbl_cnt_purge++;
    }
    SSLCTX_TBL_set(ins_idx, sslctx, sslctx);
    return 0;
}

#ifdef DEBUG
static void sslctx_tbl_dump(int idx, const char * func)
{
    printf("%s: idx %d now %d\n", func, idx, process_uptime());
    printf("%s: ** cert_name %p\n", func, sslctx_tbl[idx].cert_name);
    printf("%s: ** name_len %d\n", func, sslctx_tbl[idx].name_len);
    printf("%s: ** alloc_len %d\n", func, sslctx_tbl[idx].alloc_len);
    printf("%s: ** last_use %d\n", func, sslctx_tbl[idx].last_use);
    printf("%s: ** reuse_count %d\n", func, sslctx_tbl[idx].reuse_count);
    printf("%s: ** sslctx %p\n", func, sslctx_tbl[idx].sslctx);
    if (sslctx_tbl[idx].sslctx)
        printf("%s: ** sslctx ref %d\n", func, sslctx_tbl[idx].sslctx->references);
}
#endif

static void ssl_lock_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

void ssl_thread_id(CRYPTO_THREADID *id)
{
    unsigned long tid = (unsigned long) pthread_self();
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

static void generate_cert(char* pem_fn, const char *pem_dir, X509_NAME *issuer, EVP_PKEY *privkey)
{
    char *fname = NULL;
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    X509_EXTENSION *ext = NULL;
    X509V3_CTX ext_ctx;
    char *san_str = NULL;
    char *tld = NULL, *tld_tmp = NULL;
    int dot_count = 0;
    EVP_MD_CTX *p_ctx = NULL;

    p_ctx = EVP_MD_CTX_create();
    if(EVP_DigestSignInit(p_ctx, NULL, EVP_sha256(), NULL, privkey) != 1)
        log_msg(LGG_ERR, "%s: failed to init sign context", __FUNCTION__);

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
        log_msg(LGG_ERR, "%s: failed to open file for write: %s", __FUNCTION__, fname);
        goto free_all;
    }
    PEM_write_X509(fp, x509);
    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    log_msg(LGG_NOTICE, "cert generated to disk: %s", pem_fn);

free_all:
    EVP_MD_CTX_destroy(p_ctx);
    EVP_PKEY_free(key);
    X509_EXTENSION_free(ext);
    X509_free(x509);
    free(fname);
    free(san_str);
}


static int pem_passwd_cb(char *buf, int size, int rwflag, void *u) { 
    int rv = 0;
    char *fname = NULL; 
    asprintf(&fname, "%s/ca.key.passphrase", (char*)u);

    int fp = open(fname, O_RDONLY);    
    if(fp == -1)
        log_msg(LGG_ERR, "%s: failed to open ca.key.passphrase", __FUNCTION__);
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

static void cert_gen_init(const char* pem_dir, X509_NAME **issuer, EVP_PKEY **privkey)
{
    X509 *x509;
    char *cert_file;
    FILE *fp;
    asprintf(&cert_file, "%s/ca.crt", pem_dir);
    fp = fopen(cert_file, "r");
    x509 = X509_new();
    if(!fp || !PEM_read_X509(fp, &x509, NULL, NULL))
       log_msg(LGG_ERR, "%s: failed to load ca.crt", __FUNCTION__);
    *issuer = X509_NAME_dup(X509_get_subject_name(x509));
    X509_free(x509);
    fclose(fp);
    free(cert_file);

    asprintf(&cert_file, "%s/ca.key", pem_dir);
    fp = fopen(cert_file, "r");
    RSA *rsa = NULL;
    if(!fp || !PEM_read_RSAPrivateKey(fp, &rsa, pem_passwd_cb, (void*)pem_dir))
       log_msg(LGG_ERR, "%s: failed to read ca.key", __FUNCTION__);
    fclose(fp);
    free(cert_file);

    *privkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(*privkey, rsa); /* rsa auto freed when key is freed */
}

void *cert_generator(void *ptr) {
#ifdef DEBUG
    printf("%s: thread up and running\n", __FUNCTION__);
#endif
    cert_tlstor_t *cert_tlstor = (cert_tlstor_t *) ptr;

    X509_NAME *issuer;
    EVP_PKEY *key;
    cert_gen_init(cert_tlstor->pem_dir, &issuer, &key);

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
        char *p_buf, *p_buf_sav = NULL;
        p_buf = strtok_r(buf, ":", &p_buf_sav);
        while (p_buf != NULL) {
            char *cert_file;
            struct stat st;
            asprintf(&cert_file, "%s/%s", ((cert_tlstor_t*)cert_tlstor)->pem_dir, p_buf);
            if(stat(cert_file, &st) != 0) /* doesn't exist */
                generate_cert(p_buf, cert_tlstor->pem_dir, issuer, key);
            p_buf = strtok_r(NULL, ":", &p_buf_sav);
            free(cert_file);
        }
    }
    X509_NAME_free(issuer);
    EVP_PKEY_free(key);
    free(buf);
    return NULL;
}

static int tls_servername_cb(SSL *ssl, int *ad, void *arg) {

    int rv = SSL_TLSEXT_ERR_OK;
    tlsext_cb_arg_struct *cbarg = (tlsext_cb_arg_struct *)arg;
    char full_pem_path[PIXELSERV_MAX_PATH + 1 + 1]; /* worst case ':\0' */
    int len;

    len = strlen(cbarg->tls_pem);
    full_pem_path[PIXELSERV_MAX_PATH] = '\0';
    strncpy(full_pem_path, cbarg->tls_pem, PIXELSERV_MAX_PATH);
    strncat(full_pem_path, "/", PIXELSERV_MAX_PATH - len);
    ++len;

    char *srv_name = NULL;
    cbarg->servername = (char*)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (cbarg->servername)
        srv_name = (char *)cbarg->servername;
    else if (cbarg->server_ip)
        srv_name = cbarg->server_ip;
    else {
        log_msg(LGG_WARNING, "SNI failed. server name and ip empty.");
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
    if (dot_count <= 1 || (dot_count == 3 && atoi(tld) > 0)) {
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
        log_msg(LGG_ERR, "%s: buffer overflow. %s", __FUNCTION__, full_pem_path);
        rv = SSL_TLSEXT_ERR_ALERT_FATAL;
        goto quit_cb;
    }

    int handle, ins_handle;
    sslctx_tbl_lookup(pem_file, &handle, &ins_handle);
#ifdef DEBUG
    printf("%s: handle %d ins_handle %d\n", __FUNCTION__, handle, ins_handle);
    if (handle >=0) sslctx_tbl_dump(handle, __FUNCTION__);
    if (ins_handle >=0) sslctx_tbl_dump(ins_handle, __FUNCTION__);
#endif

    if(handle < 0) {
        struct stat st;
        if (stat(full_pem_path, &st) != 0){
            int fd;
            cbarg->status = SSL_MISS;
            log_msg(LGG_WARNING, "%s %s missing", srv_name, pem_file);
            if((fd = open(PIXEL_CERT_PIPE, O_WRONLY)) < 0)
                log_msg(LGG_ERR, "%s: failed to open pipe: %s", __FUNCTION__, strerror(errno));
            else {
                /* reuse full_pem_path as scratchpad */
                strcpy(full_pem_path, pem_file);
                strcat(full_pem_path, ":");
                write(fd, full_pem_path, strlen(full_pem_path));
                close(fd);
            }
            rv = SSL_TLSEXT_ERR_ALERT_FATAL;
            goto quit_cb;
        }
        SSL_CTX *sslctx;
        if (NULL == (sslctx  = create_child_sslctx(full_pem_path, cbarg->cachain))
            || 0 > sslctx_tbl_cache(pem_file, sslctx, ins_handle))
        {
            log_msg(LGG_ERR, "%s: fail to create sslctx or cache %s", __FUNCTION__, pem_file);
            cbarg->status = SSL_ERR;
            rv = SSL_TLSEXT_ERR_ALERT_FATAL;
            goto quit_cb;
        }
        handle = ins_handle;
    }
    sslctx_tbl_lock(handle);
    SSL_set_SSL_CTX(ssl, SSLCTX_TBL_get(handle, sslctx));
    sslctx_tbl_unlock(handle);
    cbarg->sslctx_idx = handle;
    cbarg->status = SSL_HIT;
    cbarg->sslctx = (void*)SSLCTX_TBL_get(handle, sslctx);

quit_cb:
    return rv;
}


/*
static int new_session(SSL *ssl, SSL_SESSION *sess) {
    return 1; // keep internal session
}

static void remove_session(SSL_CTX *sslctx, SSL_SESSION *sess) {
}

static SSL_SESSION *get_session(SSL *ssl, unsigned char *id, int idlen, int *do_copy) {
    return NULL;
}
*/

static SSL_CTX* create_child_sslctx(const char* full_pem_path, const STACK_OF(X509_INFO) *cachain)
{
    SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_server_method());
#ifdef PIXELSERV_SSL_HAS_ECDH_AUTO
    SSL_CTX_set_ecdh_auto(sslctx, 1);
#else
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (!ecdh)
        log_msg(LGG_ERR, "%s: cannot get ECDH curve", __FUNCTION__);
    SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
    EC_KEY_free(ecdh);
#endif
    SSL_CTX_set_options(sslctx,
          SSL_OP_SINGLE_DH_USE |
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_NO_TICKET |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    /* server-side caching */
    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);
    if (SSL_CTX_set_cipher_list(sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "%s: failed to set cipher list", __FUNCTION__);
    if(SSL_CTX_use_certificate_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0
       || SSL_CTX_use_PrivateKey_file(sslctx, full_pem_path, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(sslctx);
        log_msg(LGG_ERR, "%s: cannot find or use %s\n", __FUNCTION__, full_pem_path);
        return NULL;
    }
    if (cachain) {
        X509_INFO *inf; int i;
        for (i=sk_X509_INFO_num(cachain)-1; i >= 0; i--) {
            if ((inf = sk_X509_INFO_value(cachain, i)) && inf->x509 &&
                    !SSL_CTX_add_extra_chain_cert(sslctx, X509_dup(inf->x509))) {
                SSL_CTX_free(sslctx);
                log_msg(LGG_ERR, "%s: cannot add CA cert %d\n", i, __FUNCTION__);  /* X509_ref_up requires >= v1.1 */
                return NULL;
            }
        }
    }
    return sslctx;
}

SSL_CTX* create_default_sslctx(const char *pem_dir) {

    if (g_sslctx)
        return g_sslctx;

    g_sslctx = SSL_CTX_new(TLSv1_2_server_method());
    SSL_CTX_set_options(g_sslctx,
          SSL_MODE_RELEASE_BUFFERS |
          SSL_OP_NO_COMPRESSION |
          SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_sess_set_cache_size(g_sslctx, PIXEL_SSL_SESS_CACHE_SIZE);
    SSL_CTX_set_session_cache_mode(g_sslctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_sslctx, PIXEL_SSL_SESS_TIMEOUT);
/*  // cb for server-side caching
    SSL_CTX_sess_set_new_cb(g_sslctx, new_session);
    SSL_CTX_sess_set_remove_cb(g_sslctx, remove_session); */
    if (SSL_CTX_set_cipher_list(g_sslctx, PIXELSERV_CIPHER_LIST) <= 0)
        log_msg(LGG_DEBUG, "cipher_list cannot be set");
    SSL_CTX_set_tlsext_servername_callback(g_sslctx, tls_servername_cb);

    return g_sslctx;
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
            rv = ssl_ports[i];
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

void run_benchmark(const char *pem_dir, const STACK_OF(X509_INFO) *cachain, const char *cert)
{
    int c, d;
    char *cert_file, *domain;
    struct stat st;
    struct timespec tm;
    float r_tm0, g_tm0, tm1;
    SSL_CTX *sslctx = NULL;
    X509_NAME *issuer = NULL;
    EVP_PKEY *key = NULL;

    printf("CERT_PATH: %s\n", pem_dir);
    if (!cachain) goto quit;

    printf("CERT_FILE: ");
    if (cert)
    {
        asprintf(&cert_file, "%s/%s", pem_dir, cert);
        if (stat(cert_file, &st) != 0) {
            printf("%s not found\n", cert);
            goto quit;
        }
    } else
        cert = "_.bing.com";
    asprintf(&cert_file, "%s/%s", pem_dir, cert);
    printf("%s\n", cert);

    cert_gen_init(pem_dir, &issuer, &key);
    asprintf(&domain, "%s", cert);
    if (domain[0] == '_') domain[0] = '*';

    r_tm0 = 0; g_tm0 = 0;
    for (c=1; c<=10; c++)
    {
        get_time(&tm);
        for (d=0; d<5; d++)
            generate_cert(domain, pem_dir, issuer, key);
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("%2d. generate cert to disk: %.3f ms\t", c, tm1);
        g_tm0 += tm1;

        get_time(&tm);
        for (d=0; d<5; d++)
        {
            stat(cert_file, &st);
            sslctx = create_child_sslctx(cert_file, cachain);
            sslctx_tbl_cache(cert, sslctx, 0);
        }
        tm1 = elapsed_time_msec(tm) / 5.0;
        printf("load from disk: %.3f ms\n", tm1);
        r_tm0 += tm1;

    }
    printf("generate to disk average: %.3f ms\n", g_tm0 / 10.0);
    printf("  load from disk average: %.3f ms\n", r_tm0 / 10.0);

    free(domain);
    X509_NAME_free(issuer);
    EVP_PKEY_free(key);
quit:
    free(cert_file);
}
