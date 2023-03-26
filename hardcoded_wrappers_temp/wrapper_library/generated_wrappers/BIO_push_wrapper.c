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

BIO * BIO_push(BIO * arg_a,BIO * arg_b) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            1, 8, 1, /* 0: pointer.func */
            	5, 0,
            0, 0, 0, /* 5: func */
            0, 32, 5, /* 8: struct.stack_st */
            	21, 0,
            	24, 8,
            	21, 16,
            	21, 20,
            	0, 24,
            0, 4, 0, /* 21: int */
            1, 8, 1, /* 24: pointer.pointer.char */
            	29, 0,
            1, 8, 1, /* 29: pointer.char */
            	34, 0,
            0, 1, 0, /* 34: char */
            0, 32, 1, /* 37: struct.stack_st_OPENSSL_STRING */
            	8, 0,
            0, 16, 2, /* 42: struct.crypto_ex_data_st */
            	49, 0,
            	21, 8,
            1, 8, 1, /* 49: pointer.struct.stack_st_OPENSSL_STRING */
            	37, 0,
            0, 8, 0, /* 54: long */
            0, 0, 0, /* 57: func */
            0, 0, 0, /* 60: func */
            0, 0, 0, /* 63: func */
            1, 8, 1, /* 66: pointer.func */
            	57, 0,
            1, 8, 1, /* 71: pointer.func */
            	63, 0,
            1, 8, 1, /* 76: pointer.struct.bio_st */
            	81, 0,
            0, 112, 15, /* 81: struct.bio_st */
            	114, 0,
            	66, 8,
            	29, 16,
            	21, 24,
            	21, 28,
            	21, 32,
            	21, 36,
            	21, 40,
            	29, 48,
            	76, 56,
            	76, 64,
            	21, 72,
            	54, 80,
            	54, 88,
            	42, 96,
            1, 8, 1, /* 114: pointer.struct.bio_method_st */
            	119, 0,
            0, 80, 10, /* 119: struct.bio_method_st */
            	21, 0,
            	29, 8,
            	142, 16,
            	142, 24,
            	150, 32,
            	142, 40,
            	158, 48,
            	71, 56,
            	71, 64,
            	166, 72,
            1, 8, 1, /* 142: pointer.func */
            	147, 0,
            0, 0, 0, /* 147: func */
            1, 8, 1, /* 150: pointer.func */
            	155, 0,
            0, 0, 0, /* 155: func */
            1, 8, 1, /* 158: pointer.func */
            	163, 0,
            0, 0, 0, /* 163: func */
            1, 8, 1, /* 166: pointer.func */
            	60, 0,
        },
        .arg_entity_index = { 76, 76, },
        .ret_entity_index = 76,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    BIO * new_arg_b = *((BIO * *)new_args->args[1]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_push)(BIO *,BIO *);
    orig_BIO_push = dlsym(RTLD_NEXT, "BIO_push");
    *new_ret_ptr = (*orig_BIO_push)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

