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

int bb_SSL_library_init(void);

int SSL_library_init(void) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_library_init called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_library_init();
    else {
        int (*orig_SSL_library_init)(void);
        orig_SSL_library_init = dlsym(RTLD_NEXT, "SSL_library_init");
        return orig_SSL_library_init();
    }
}

int bb_SSL_library_init(void) 
{
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: pointer.void */
            0, 4, 0, /* 3: int */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 3,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_library_init)(void);
    orig_SSL_library_init = dlsym(RTLD_NEXT, "SSL_library_init");
    *new_ret_ptr = (*orig_SSL_library_init)();

    syscall(889);

    return ret;
}

