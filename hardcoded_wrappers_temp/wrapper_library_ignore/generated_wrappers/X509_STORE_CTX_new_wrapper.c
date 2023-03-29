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

X509_STORE_CTX * X509_STORE_CTX_new(void) 
{
    X509_STORE_CTX * ret;

    X509_STORE_CTX * (*orig_X509_STORE_CTX_new)(void);
    orig_X509_STORE_CTX_new = dlsym(RTLD_NEXT, "X509_STORE_CTX_new");
    ret = (*orig_X509_STORE_CTX_new)();

    return ret;
}

