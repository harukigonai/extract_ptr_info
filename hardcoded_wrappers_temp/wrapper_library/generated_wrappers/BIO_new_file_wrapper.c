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

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b);

BIO * BIO_new_file(const char * arg_a,const char * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_new_file called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_new_file(arg_a,arg_b);
    else {
        BIO * (*orig_BIO_new_file)(const char *,const char *);
        orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
        return orig_BIO_new_file(arg_a,arg_b);
    }
}

BIO * bb_BIO_new_file(const char * arg_a,const char * arg_b) 
{
    BIO * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            4097, 8, 0, /* 0: pointer.func */
            1, 8, 1, /* 3: pointer.pointer.char */
            	8, 0,
            1, 8, 1, /* 8: pointer.char */
            	4096, 0,
            0, 32, 2, /* 13: struct.stack_st */
            	3, 8,
            	0, 24,
            0, 32, 1, /* 20: struct.stack_st_OPENSSL_STRING */
            	13, 0,
            1, 8, 1, /* 25: pointer.struct.stack_st_OPENSSL_STRING */
            	20, 0,
            0, 16, 1, /* 30: struct.crypto_ex_data_st */
            	25, 0,
            1, 8, 1, /* 35: pointer.struct.bio_method_st */
            	40, 0,
            0, 80, 9, /* 40: struct.bio_method_st */
            	8, 8,
            	61, 16,
            	61, 24,
            	64, 32,
            	61, 40,
            	67, 48,
            	70, 56,
            	70, 64,
            	73, 72,
            4097, 8, 0, /* 61: pointer.func */
            4097, 8, 0, /* 64: pointer.func */
            4097, 8, 0, /* 67: pointer.func */
            4097, 8, 0, /* 70: pointer.func */
            4097, 8, 0, /* 73: pointer.func */
            1, 8, 1, /* 76: pointer.struct.bio_st */
            	81, 0,
            0, 112, 7, /* 81: struct.bio_st */
            	35, 0,
            	98, 8,
            	8, 16,
            	8, 48,
            	76, 56,
            	76, 64,
            	30, 96,
            4097, 8, 0, /* 98: pointer.func */
            0, 1, 0, /* 101: char */
            0, 8, 0, /* 104: pointer.void */
        },
        .arg_entity_index = { 8, 8, },
        .ret_entity_index = 76,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const char * new_arg_a = *((const char * *)new_args->args[0]);

    const char * new_arg_b = *((const char * *)new_args->args[1]);

    BIO * *new_ret_ptr = (BIO * *)new_args->ret;

    BIO * (*orig_BIO_new_file)(const char *,const char *);
    orig_BIO_new_file = dlsym(RTLD_NEXT, "BIO_new_file");
    *new_ret_ptr = (*orig_BIO_new_file)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

