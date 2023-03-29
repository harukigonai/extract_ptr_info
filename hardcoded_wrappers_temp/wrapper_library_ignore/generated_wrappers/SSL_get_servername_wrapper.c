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

const char * SSL_get_servername(const SSL * arg_a,const int arg_b) 
{
    const char * ret;

    const char * (*orig_SSL_get_servername)(const SSL *,const int);
    orig_SSL_get_servername = dlsym(RTLD_NEXT, "SSL_get_servername");
    ret = (*orig_SSL_get_servername)(new_arg_a,new_arg_b);

    return ret;
}

