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

void SSL_CTX_set_tmp_dh_callback(SSL_CTX * arg_a,DH *(*arg_b)(SSL *, int, int)) 
{
    void (*orig_SSL_CTX_set_tmp_dh_callback)(SSL_CTX *,DH *(*)(SSL *, int, int));
    orig_SSL_CTX_set_tmp_dh_callback = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh_callback");
    (*orig_SSL_CTX_set_tmp_dh_callback)(arg_a,arg_b);

}

