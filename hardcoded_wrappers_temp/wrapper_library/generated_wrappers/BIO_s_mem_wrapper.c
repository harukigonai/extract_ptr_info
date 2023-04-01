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

BIO_METHOD * bb_BIO_s_mem(void);

BIO_METHOD * BIO_s_mem(void) 
{
    unsigned long in_lib = syscall(890);
    printf("BIO_s_mem called %lu\n", in_lib);
    if (!in_lib)
        return bb_BIO_s_mem();
    else {
        BIO_METHOD * (*orig_BIO_s_mem)(void);
        orig_BIO_s_mem = dlsym(RTLD_NEXT, "BIO_s_mem");
        return orig_BIO_s_mem();
    }
}

BIO_METHOD * bb_BIO_s_mem(void) 
{
    BIO_METHOD * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 80, 1, /* 3: struct.bio_method_st */
            	8, 8,
            1, 8, 1, /* 8: pointer.char */
            	4096, 0,
            0, 4, 0, /* 13: int */
            0, 0, 0, /* 16: func */
            0, 1, 0, /* 19: char */
            4097, 48, 94416502371640, /* 22: pointer.func */
            	0, 0,
            	0, 4097,
            	48, 94416502369144,
            	4097, 0,
            	0, 4097,
            	193, 94396195311776,
            	0, 0,
            	0, 0,
            	0, 0,
            	1, 8,
            	1, 3,
            	0, 4097,
            	94396196026832, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 43,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    BIO_METHOD * *new_ret_ptr = (BIO_METHOD * *)new_args->ret;

    BIO_METHOD * (*orig_BIO_s_mem)(void);
    orig_BIO_s_mem = dlsym(RTLD_NEXT, "BIO_s_mem");
    *new_ret_ptr = (*orig_BIO_s_mem)();

    syscall(889);

    return ret;
}

