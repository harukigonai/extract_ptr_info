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
    if (syscall(890))
        return _SSL_CIPHER_get_bits(arg_a,arg_b);
    else {
        int (*orig_SSL_CIPHER_get_bits)(const SSL_CIPHER *,int *);
        orig_SSL_CIPHER_get_bits = dlsym(RTLD_NEXT, "SSL_CIPHER_get_bits");
        return orig_SSL_CIPHER_get_bits(arg_a,arg_b);
    }
}

int _SSL_CIPHER_get_bits(const SSL_CIPHER * arg_a,int * arg_b) 
{
    printf("SSL_CIPHER_get_bits called\n");
    int ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 8, 0, /* 0: long */
            0, 1, 0, /* 3: char */
            1, 8, 1, /* 6: pointer.char */
            	3, 0,
            0, 88, 1, /* 11: struct.ssl_cipher_st */
            	6, 8,
            1, 8, 1, /* 16: pointer.struct.ssl_cipher_st */
            	11, 0,
            1, 8, 1, /* 21: pointer.int */
            	26, 0,
            0, 4, 0, /* 26: int */
        },
        .arg_entity_index = { 16, 21, },
        .ret_entity_index = 26,
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

