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
            0, 8, 1, /* 0: pointer.struct.bio_method_st */
            	5, 0,
            0, 80, 9, /* 5: struct.bio_method_st */
            	26, 8,
            	31, 16,
            	31, 24,
            	34, 32,
            	31, 40,
            	37, 48,
            	40, 56,
            	40, 64,
            	43, 72,
            0, 8, 1, /* 26: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 31: pointer.func */
            4097, 8, 0, /* 34: pointer.func */
            4097, 8, 0, /* 37: pointer.func */
            4097, 8, 0, /* 40: pointer.func */
            4097, 8, 0, /* 43: pointer.func */
            0, 4, 0, /* 46: int */
            0, 0, 0, /* 49: func */
            0, 0, 0, /* 52: func */
            0, 0, 0, /* 55: func */
            0, 0, 0, /* 58: func */
            0, 1, 0, /* 61: char */
            0, 0, 0, /* 64: func */
            0, 8, 0, /* 67: pointer.void */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 0,
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

