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

void BN_free(BIGNUM * arg_a) 
{
    printf("BN_free called\n");
    struct lib_enter_args args = {
        .entity_metadata = {
            0, 4, 0, /* 0: int */
            1, 8, 1, /* 3: pointer.int */
            	0, 0,
            0, 24, 1, /* 8: struct.bignum_st */
            	3, 0,
            1, 8, 1, /* 13: pointer.struct.bignum_st */
            	8, 0,
        },
        .arg_entity_index = { 13, },
        .ret_entity_index = -1,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIGNUM * new_arg_a = *((BIGNUM * *)new_args->args[0]);

    void (*orig_BN_free)(BIGNUM *);
    orig_BN_free = dlsym(RTLD_NEXT, "BN_free");
    (*orig_BN_free)(new_arg_a);

    syscall(889);

}

