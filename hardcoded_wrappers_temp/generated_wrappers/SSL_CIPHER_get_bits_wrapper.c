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

int SSL_CIPHER_get_bits(const SSL_CIPHER * arg_a,int * arg_b) 
{
    int ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 8, 0, /* 0: long */
            0, 1, 0, /* 3: char */
            1, 8, 1, /* 6: pointer.char */
            	3, 0,
            0, 88, 12, /* 11: struct.ssl_cipher_st */
            	38, 0,
            	6, 8,
            	0, 16,
            	0, 24,
            	0, 32,
            	0, 40,
            	0, 48,
            	0, 56,
            	0, 64,
            	0, 72,
            	38, 80,
            	38, 84,
            0, 4, 0, /* 38: int */
            1, 8, 1, /* 41: pointer.struct.ssl_cipher_st */
            	11, 0,
            1, 8, 1, /* 46: pointer.int */
            	38, 0,
        },
        .arg_entity_index = { 41, 46, },
        .ret_entity_index = 38,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_arg(args_addr, arg_b);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CIPHER * new_arg_a = *((const SSL_CIPHER * *)new_args->args[0]);

    int * new_arg_b = *((int * *)new_args->args[1]);

    int *new_ret_ptr = (int *)new_args->ret;

    int (*orig_SSL_CIPHER_get_bits)(const SSL_CIPHER *,int *);
    orig_SSL_CIPHER_get_bits = dlsym(RTLD_NEXT, "SSL_CIPHER_get_bits");
    *new_ret_ptr = (*orig_SSL_CIPHER_get_bits)(new_arg_a,new_arg_b);

    syscall(889);

    return ret;
}

