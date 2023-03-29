#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>

#include "../arg_struct.h"

void SSL_CTX_sess_set_get_cb(SSL_CTX * arg_a,SSL_SESSION *(*arg_b)(struct ssl_st *, unsigned char *, int, int *)) 
{
    void (*orig_SSL_CTX_sess_set_get_cb)(SSL_CTX *,SSL_SESSION *(*)(struct ssl_st *, unsigned char *, int, int *));
    orig_SSL_CTX_sess_set_get_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_get_cb");
    (*orig_SSL_CTX_sess_set_get_cb)(arg_a,arg_b);

}

