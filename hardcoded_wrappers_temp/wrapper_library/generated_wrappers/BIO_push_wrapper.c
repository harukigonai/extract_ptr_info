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

BIO * bb_BIO_push(BIO * arg_a,BIO * arg_b);

BIO * BIO_push(BIO * arg_a,BIO * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_push called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_push(arg_a,arg_b);
    else {
        BIO * (*orig_BIO_push)(BIO *,BIO *);
        orig_BIO_push = dlsym(RTLD_NEXT, "BIO_push");
        return orig_BIO_push(arg_a,arg_b);
    }
}

BIO * bb_BIO_push(BIO * arg_a,BIO * arg_b) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            64097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 8: pointer.char */
            	64096, 0,
            0, 32, 1, /* 13: struct.stack_st_void */
            	18, 0,
            0, 32, 2, /* 18: struct.stack_st */
            	3, 8,
            	0, 24,
            1, 8, 1, /* 25: pointer.struct.stack_st_void */
            	13, 0,
            0, 16, 1, /* 30: struct.crypto_ex_data_st */
            	25, 0,
            1, 8, 1, /* 35: pointer.struct.bio_st */
            	40, 0,
            0, 112, 7, /* 40: struct.bio_st */
            	57, 0,
            	106, 8,
            	8, 16,
            	109, 48,
            	35, 56,
            	35, 64,
            	30, 96,
            1, 8, 1, /* 57: pointer.struct.bio_method_st */
            	62, 0,
            0, 80, 9, /* 62: struct.bio_method_st */
            	83, 8,
            	88, 16,
            	91, 24,
            	94, 32,
            	91, 40,
            	97, 48,
            	100, 56,
            	100, 64,
            	103, 72,
            1, 8, 1, /* 83: pointer.char */
            	64096, 0,
            64097, 8, 0, /* 88: pointer.func */
            64097, 8, 0, /* 91: pointer.func */
            64097, 8, 0, /* 94: pointer.func */
            64097, 8, 0, /* 97: pointer.func */
            64097, 8, 0, /* 100: pointer.func */
            64097, 8, 0, /* 103: pointer.func */
            64097, 8, 0, /* 106: pointer.func */
            0, 8, 0, /* 109: pointer.void */
            1, 8, 1, /* 112: pointer.struct.bio_st */
            	40, 0,
            0, 1, 0, /* 117: char */
        },
        .arg_entity_index = { 112, 112, },
        .ret_entity_index = 112,
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

