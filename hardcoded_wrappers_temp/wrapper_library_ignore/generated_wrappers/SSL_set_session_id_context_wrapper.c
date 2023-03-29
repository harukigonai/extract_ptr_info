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

int SSL_set_session_id_context(SSL * arg_a,const unsigned char * arg_b,unsigned int arg_c) 
{
    int ret;

    int (*orig_SSL_set_session_id_context)(SSL *,const unsigned char *,unsigned int);
    orig_SSL_set_session_id_context = dlsym(RTLD_NEXT, "SSL_set_session_id_context");
    ret = (*orig_SSL_set_session_id_context)(arg_a,arg_b,arg_c);

    return ret;
}

