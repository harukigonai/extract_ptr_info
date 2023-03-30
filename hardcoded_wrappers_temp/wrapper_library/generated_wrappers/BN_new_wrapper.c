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

BIGNUM * bb_BN_new(void);

BIGNUM * BN_new(void) 
{
    if (syscall(890))
        return bb_BN_new();
    else {
        BIGNUM * (*orig_BN_new)(void);
        orig_BN_new = dlsym(RTLD_NEXT, "BN_new");
        return orig_BN_new();
    }
}

BIGNUM * bb_BN_new(void) 
{
    printf("BN_new called\n");
    BIGNUM * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 4, 0, /* 0: int */
            1, 8, 1, /* 3: pointer.int */
            	0, 0,
            0, 24, 1, /* 8: struct.bignum_st */
            	3, 0,
            1, 8, 1, /* 13: pointer.struct.bignum_st */
            	8, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 13,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIGNUM * *new_ret_ptr = (BIGNUM * *)new_args->ret;

    BIGNUM * (*orig_BN_new)(void);
    orig_BN_new = dlsym(RTLD_NEXT, "BN_new");
    *new_ret_ptr = (*orig_BN_new)();

    syscall(889);

    return ret;
}

