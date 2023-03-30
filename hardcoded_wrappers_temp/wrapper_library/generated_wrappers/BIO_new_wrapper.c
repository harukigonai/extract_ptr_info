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

BIO * BIO_new(BIO_METHOD * arg_a) 
{
    if (syscall(890))
        return _BIO_new(arg_a);
    else {
        BIO * (*orig_BIO_new)(BIO_METHOD *);
        orig_BIO_new = dlsym(RTLD_NEXT, "BIO_new");
        return orig_BIO_new(arg_a);
    }
}

BIO * _BIO_new(BIO_METHOD * arg_a) 
{
    printf("BIO_new called\n");
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 32, 2, /* 0: struct.stack_st */
            	7, 8,
            	20, 24,
            1, 8, 1, /* 7: pointer.pointer.char */
            	12, 0,
            1, 8, 1, /* 12: pointer.char */
            	17, 0,
            0, 1, 0, /* 17: char */
            1, 8, 1, /* 20: pointer.func */
            	25, 0,
            0, 0, 0, /* 25: func */
            0, 32, 1, /* 28: struct.stack_st_OPENSSL_STRING */
            	0, 0,
            0, 16, 1, /* 33: struct.crypto_ex_data_st */
            	38, 0,
            1, 8, 1, /* 38: pointer.struct.stack_st_OPENSSL_STRING */
            	28, 0,
            0, 8, 0, /* 43: long */
            0, 0, 0, /* 46: func */
            0, 0, 0, /* 49: func */
            0, 0, 0, /* 52: func */
            1, 8, 1, /* 55: pointer.struct.bio_st */
            	60, 0,
            0, 112, 7, /* 60: struct.bio_st */
            	77, 0,
            	137, 8,
            	12, 16,
            	12, 48,
            	55, 56,
            	55, 64,
            	33, 96,
            1, 8, 1, /* 77: pointer.struct.bio_method_st */
            	82, 0,
            0, 80, 9, /* 82: struct.bio_method_st */
            	12, 8,
            	103, 16,
            	103, 24,
            	111, 32,
            	103, 40,
            	119, 48,
            	127, 56,
            	127, 64,
            	132, 72,
            1, 8, 1, /* 103: pointer.func */
            	108, 0,
            0, 0, 0, /* 108: func */
            1, 8, 1, /* 111: pointer.func */
            	116, 0,
            0, 0, 0, /* 116: func */
            1, 8, 1, /* 119: pointer.func */
            	124, 0,
            0, 0, 0, /* 124: func */
            1, 8, 1, /* 127: pointer.func */
            	52, 0,
            1, 8, 1, /* 132: pointer.func */
            	49, 0,
            1, 8, 1, /* 137: pointer.func */
            	46, 0,
            0, 4, 0, /* 142: int */
        },
        .arg_entity_index = { 77, },
        .ret_entity_index = 55,
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

