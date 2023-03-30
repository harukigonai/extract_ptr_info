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
    printf("BIO_s_mem called\n");
    if (syscall(890))
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
            0, 80, 9, /* 3: struct.bio_method_st */
            	24, 8,
            	32, 16,
            	32, 24,
            	40, 32,
            	32, 40,
            	48, 48,
            	56, 56,
            	56, 64,
            	64, 72,
            1, 8, 1, /* 24: pointer.char */
            	29, 0,
            0, 1, 0, /* 29: char */
            1, 8, 1, /* 32: pointer.func */
            	37, 0,
            0, 0, 0, /* 37: func */
            1, 8, 1, /* 40: pointer.func */
            	45, 0,
            0, 0, 0, /* 45: func */
            1, 8, 1, /* 48: pointer.func */
            	53, 0,
            0, 0, 0, /* 53: func */
            1, 8, 1, /* 56: pointer.func */
            	61, 0,
            0, 0, 0, /* 61: func */
            1, 8, 1, /* 64: pointer.func */
            	0, 0,
            0, 4, 0, /* 69: int */
            1, 8, 1, /* 72: pointer.struct.bio_method_st */
            	3, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 72,
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

