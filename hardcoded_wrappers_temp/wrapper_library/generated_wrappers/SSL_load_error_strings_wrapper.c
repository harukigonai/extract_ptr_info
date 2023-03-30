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

void bb_SSL_load_error_strings(void);

void SSL_load_error_strings(void) 
{
    if (syscall(890))
        bb_SSL_load_error_strings();
    else {
        void (*orig_SSL_load_error_strings)(void);
        orig_SSL_load_error_strings = dlsym(RTLD_NEXT, "SSL_load_error_strings");
        orig_SSL_load_error_strings();
    }
}

void bb_SSL_load_error_strings(void) 
{
    printf("SSL_load_error_strings called\n");
    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    void (*orig_SSL_load_error_strings)(void);
    orig_SSL_load_error_strings = dlsym(RTLD_NEXT, "SSL_load_error_strings");
    (*orig_SSL_load_error_strings)();

    syscall(889);

}

