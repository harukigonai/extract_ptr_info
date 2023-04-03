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

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c);

int BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_write called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_write(arg_a,arg_b,arg_c);
    else {
        int (*orig_BIO_write)(BIO *,const void *,int);
        orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
        return orig_BIO_write(arg_a,arg_b,arg_c);
    }
}

int bb_BIO_write(BIO * arg_a,const void * arg_b,int arg_c) 
{
    int ret;

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
            0, 8, 0, /* 25: pointer.void */
            1, 8, 1, /* 28: pointer.struct.stack_st_OPENSSL_STRING */
            	20, 0,
            0, 16, 1, /* 33: struct.crypto_ex_data_st */
            	28, 0,
            0, 0, 0, /* 38: func */
            4097, 8, 0, /* 41: pointer.func */
            4097, 8, 0, /* 44: pointer.func */
            1, 8, 1, /* 47: pointer.struct.bio_st */
            	52, 0,
            0, 112, 7, /* 52: struct.bio_st */
            	69, 0,
            	41, 8,
            	8, 16,
            	25, 48,
            	47, 56,
            	47, 64,
            	33, 96,
            1, 8, 1, /* 69: pointer.struct.bio_method_st */
            	74, 0,
            0, 80, 9, /* 74: struct.bio_method_st */
            	8, 8,
            	95, 16,
            	95, 24,
            	98, 32,
            	95, 40,
            	101, 48,
            	44, 56,
            	44, 64,
            	104, 72,
            4097, 8, 0, /* 95: pointer.func */
            4097, 8, 0, /* 98: pointer.func */
            4097, 8, 0, /* 101: pointer.func */
            4097, 8, 0, /* 104: pointer.func */
            0, 0, 0, /* 107: func */
            0, 8, 0, /* 110: long */
            0, 4, 0, /* 113: int */
            0, 0, 0, /* 116: func */
            0, 0, 0, /* 119: func */
            0, 0, 0, /* 122: func */
            0, 1, 0, /* 125: char */
            0, 0, 0, /* 128: func */
            0, 0, 0, /* 131: func */
        },
        .arg_entity_index = { 47, 25, 113, },
        .ret_entity_index = 113,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO * new_arg_a = *((BIO * *)new_args->args[0]);

    const void * new_arg_b = *((const void * *)new_args->args[1]);

    int new_arg_c = *((int *)new_args->args[2]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_BIO_write)(BIO *,const void *,int);
    orig_BIO_write = dlsym(RTLD_NEXT, "BIO_write");
    *new_ret_ptr = (*orig_BIO_write)(new_arg_a,new_arg_b,new_arg_c);

    syscall(889);

    return ret;
}

