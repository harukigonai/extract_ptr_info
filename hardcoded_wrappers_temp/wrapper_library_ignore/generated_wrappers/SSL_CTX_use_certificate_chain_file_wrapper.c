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

int SSL_CTX_use_certificate_chain_file(SSL_CTX * arg_a,const char * arg_b) 
{
    int ret;

    int (*orig_SSL_CTX_use_certificate_chain_file)(SSL_CTX *,const char *);
    orig_SSL_CTX_use_certificate_chain_file = dlsym(RTLD_NEXT, "SSL_CTX_use_certificate_chain_file");
    ret = (*orig_SSL_CTX_use_certificate_chain_file)(new_arg_a,new_arg_b);

    return ret;
}

