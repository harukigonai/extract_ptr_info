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

int EVP_SignFinal(EVP_MD_CTX * arg_a,unsigned char * arg_b,unsigned int * arg_c,EVP_PKEY * arg_d) 
{
    int ret;

    int (*orig_EVP_SignFinal)(EVP_MD_CTX *,unsigned char *,unsigned int *,EVP_PKEY *);
    orig_EVP_SignFinal = dlsym(RTLD_NEXT, "EVP_SignFinal");
    ret = (*orig_EVP_SignFinal)(arg_a,arg_b,arg_c,arg_d);

    return ret;
}

