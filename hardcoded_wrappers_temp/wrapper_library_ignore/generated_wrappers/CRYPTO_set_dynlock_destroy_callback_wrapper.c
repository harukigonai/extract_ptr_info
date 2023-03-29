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

void CRYPTO_set_dynlock_destroy_callback(void (*arg_a)(struct CRYPTO_dynlock_value *, const char *, int)) 
{
    void (*orig_CRYPTO_set_dynlock_destroy_callback)(void (*)(struct CRYPTO_dynlock_value *, const char *, int));
    orig_CRYPTO_set_dynlock_destroy_callback = dlsym(RTLD_NEXT, "CRYPTO_set_dynlock_destroy_callback");
    (*orig_CRYPTO_set_dynlock_destroy_callback)(arg_a);

}

