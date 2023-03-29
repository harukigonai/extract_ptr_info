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

int SSL_get_ex_new_index(long arg_a,void * arg_b,CRYPTO_EX_new * arg_c,CRYPTO_EX_dup * arg_d,CRYPTO_EX_free * arg_e) 
{
    int ret;

    int (*orig_SSL_get_ex_new_index)(long,void *,CRYPTO_EX_new *,CRYPTO_EX_dup *,CRYPTO_EX_free *);
    orig_SSL_get_ex_new_index = dlsym(RTLD_NEXT, "SSL_get_ex_new_index");
    ret = (*orig_SSL_get_ex_new_index)(arg_a,arg_b,arg_c,arg_d,arg_e);

    return ret;
}

