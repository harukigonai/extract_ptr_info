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

int CRYPTO_THREADID_set_callback(void (*arg_a)(CRYPTO_THREADID *)) 
{
    int ret;

    int (*orig_CRYPTO_THREADID_set_callback)(void (*)(CRYPTO_THREADID *));
    orig_CRYPTO_THREADID_set_callback = dlsym(RTLD_NEXT, "CRYPTO_THREADID_set_callback");
    ret = (*orig_CRYPTO_THREADID_set_callback)(arg_a);

    return ret;
}

