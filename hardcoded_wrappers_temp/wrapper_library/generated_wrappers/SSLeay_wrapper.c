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

unsigned long bb_SSLeay(void);

unsigned long SSLeay(void) 
{
    printf("SSLeay called\n");
    if (syscall(890))
        return bb_SSLeay();
    else {
        unsigned long (*orig_SSLeay)(void);
        orig_SSLeay = dlsym(RTLD_NEXT, "SSLeay");
        return orig_SSLeay();
    }
}

unsigned long bb_SSLeay(void) 
{
    unsigned long ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: long */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 0,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    unsigned long *new_ret_ptr = (unsigned long *)new_args->ret;

    unsigned long (*orig_SSLeay)(void);
    orig_SSLeay = dlsym(RTLD_NEXT, "SSLeay");
    *new_ret_ptr = (*orig_SSLeay)();

    syscall(889);

    return ret;
}

