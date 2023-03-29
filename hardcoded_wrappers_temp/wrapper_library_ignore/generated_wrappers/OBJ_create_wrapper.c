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

int OBJ_create(const char * arg_a,const char * arg_b,const char * arg_c) 
{
    int ret;

    int (*orig_OBJ_create)(const char *,const char *,const char *);
    orig_OBJ_create = dlsym(RTLD_NEXT, "OBJ_create");
    ret = (*orig_OBJ_create)(arg_a,arg_b,arg_c);

    return ret;
}

