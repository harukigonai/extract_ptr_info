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

int BN_set_word(BIGNUM * arg_a,BN_ULONG arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 24, 5, /* 0: struct.bignum_st */
            	13, 0,
            	18, 8,
            	18, 12,
            	18, 16,
            	18, 20,
            1, 8, 1, /* 13: pointer.int */
            	18, 0,
            0, 4, 0, /* 18: int */
            1, 8, 1, /* 21: pointer.struct.bignum_st */
            	0, 0,
        },
        .arg_entity_index = { 21, 18, },
        .ret_entity_index = 18,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIGNUM * new_arg_a = *((BIGNUM * *)new_args->args[0]);

    BN_ULONG new_arg_b = *((BN_ULONG *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_BN_set_word)(BIGNUM *,BN_ULONG);
    orig_BN_set_word = dlsym(RTLD_NEXT, "BN_set_word");
    *new_ret_ptr = (*orig_BN_set_word)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}
