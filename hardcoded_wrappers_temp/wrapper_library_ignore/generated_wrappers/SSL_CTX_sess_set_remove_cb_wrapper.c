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

void SSL_CTX_sess_set_remove_cb(SSL_CTX * arg_a,void (*arg_b)(struct ssl_ctx_st *,SSL_SESSION *)) 
{
    void (*orig_SSL_CTX_sess_set_remove_cb)(SSL_CTX *,void (*)(struct ssl_ctx_st *,SSL_SESSION *));
    orig_SSL_CTX_sess_set_remove_cb = dlsym(RTLD_NEXT, "SSL_CTX_sess_set_remove_cb");
    (*orig_SSL_CTX_sess_set_remove_cb)(new_arg_a,new_arg_b);

}

