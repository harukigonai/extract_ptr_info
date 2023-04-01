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
            4097, 94396163562416, 94396163562496, /* 45: pointer.func */
            	4097, 94396163562656,
            	94396163562736, 0,
            	4, 0,
            	1, 8,
            	1, 59,
            	0, 0,
            	112, 6,
            	74, 0,
            	13, 16,
            	13, 48,
            	54, 56,
            	54, 64,
            	18, 96,
            	1, 8,
            	1, 79,
            	0, 0,
            	80, 1,
            	13, 8,
            	0, 0,
            	0, 4097,
            	94396163565776, 94396163565856,
            	0, 1,
            	0, 4097,
            	94396163566256, 94396163566336,
            	4097, 94396163566496,
            	94396163566576, 0,
            	0, 0,
            	4097, 94396163566976,
            	94396163567056, 0,
            	0, 0,
            	4097, 94396163567456,
            	94396163567536, 81,
        },
        .arg_entity_index = { 54, 13, 51, },
        .ret_entity_index = 51,
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

