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

BIO * bb_BIO_new(BIO_METHOD * arg_a);

BIO * BIO_new(BIO_METHOD * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_new called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_new(arg_a);
    else {
        BIO * (*orig_BIO_new)(BIO_METHOD *);
        orig_BIO_new = dlsym(RTLD_NEXT, "BIO_new");
        return orig_BIO_new(arg_a);
    }
}

BIO * bb_BIO_new(BIO_METHOD * arg_a) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 32, 1, /* 3: struct.stack_st */
            	8, 8,
            1, 8, 1, /* 8: pointer.pointer.char */
            	13, 0,
            1, 8, 1, /* 13: pointer.char */
            	4096, 0,
            0, 16, 1, /* 18: struct.crypto_ex_data_st */
            	23, 0,
            1, 8, 1, /* 23: pointer.struct.stack_st_OPENSSL_STRING */
            	28, 0,
            0, 32, 1, /* 28: struct.stack_st_OPENSSL_STRING */
            	3, 0,
            0, 8, 0, /* 33: long */
            0, 0, 0, /* 36: func */
            0, 0, 0, /* 39: func */
            0, 0, 0, /* 42: func */
            4097, 8, 0, /* 45: pointer.func */
            4097, 8, 0, /* 48: pointer.func */
            1, 8, 1, /* 51: pointer.struct.bio_st */
            	56, 0,
            0, 112, 6, /* 56: struct.bio_st */
            	71, 0,
            	13, 16,
            	13, 48,
            	51, 56,
            	51, 64,
            	18, 96,
            1, 8, 1, /* 71: pointer.struct.bio_method_st */
            	76, 0,
            0, 80, 1, /* 76: struct.bio_method_st */
            	13, 8,
            0, 4, 0, /* 81: int */
            0, 0, 0, /* 84: func */
            4097, 8, 0, /* 87: pointer.func */
            0, 1, 0, /* 90: char */
            4097, 8, 0, /* 93: pointer.func */
            4097, 8, 0, /* 96: pointer.func */
            0, 0, 0, /* 99: func */
            4097, 8, 0, /* 102: pointer.func */
            0, 0, 0, /* 105: func */
            4097, 8, 0, /* 108: pointer.func */
        },
        .arg_entity_index = { 71, },
        .ret_entity_index = 51,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO_METHOD * new_arg_a = *((BIO_METHOD * *)new_args->args[0]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_new)(BIO_METHOD *);
    orig_BIO_new = dlsym(RTLD_NEXT, "BIO_new");
    *new_ret_ptr = (*orig_BIO_new)(new_arg_a);

    syscall(889);

    return ret;
}

