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

void SSL_CTX_set_verify(SSL_CTX * arg_a,int arg_b,int (*arg_c)(int, X509_STORE_CTX *)) 
{
    void (*orig_SSL_CTX_set_verify)(SSL_CTX *,int,int (*)(int, X509_STORE_CTX *));
    orig_SSL_CTX_set_verify = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    (*orig_SSL_CTX_set_verify)(new_arg_a,new_arg_b,new_arg_c);

}

