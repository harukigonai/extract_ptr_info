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

int SSL_get_ex_new_index(long arg_a,void * arg_b,CRYPTO_EX_new * arg_c,CRYPTO_EX_dup * arg_d,CRYPTO_EX_free * arg_e) 
{
    printf("SSL_get_ex_new_index called\n");
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            1, 8, 1, /* 6: pointer.func */
            	3, 0,
            1, 8, 1, /* 11: pointer.func */
            	16, 0,
            0, 0, 0, /* 16: func */
            1, 8, 1, /* 19: pointer.func */
            	0, 0,
            0, 1, 0, /* 24: char */
            1, 8, 1, /* 27: pointer.char */
            	24, 0,
            0, 8, 0, /* 32: long */
            0, 4, 0, /* 35: int */
        },
        .arg_entity_index = { 32, 27, 11, 6, 19, },
        .ret_entity_index = 35,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_arg(args_addr, arg_c);
    populate_arg(args_addr, arg_d);
    populate_arg(args_addr, arg_e);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    long new_arg_a = *((long *)new_args->args[0]);

    void * new_arg_b = *((void * *)new_args->args[1]);

    CRYPTO_EX_new * new_arg_c = *((CRYPTO_EX_new * *)new_args->args[2]);

    CRYPTO_EX_dup * new_arg_d = *((CRYPTO_EX_dup * *)new_args->args[3]);

    CRYPTO_EX_free * new_arg_e = *((CRYPTO_EX_free * *)new_args->args[4]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_get_ex_new_index)(long,void *,CRYPTO_EX_new *,CRYPTO_EX_dup *,CRYPTO_EX_free *);
    orig_SSL_get_ex_new_index = dlsym(RTLD_NEXT, "SSL_get_ex_new_index");
    *new_ret_ptr = (*orig_SSL_get_ex_new_index)(new_arg_a,new_arg_b,new_arg_c,new_arg_d,new_arg_e);

    syscall(889);

    return ret;
}

