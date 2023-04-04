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

const char * bb_SSL_CIPHER_get_name(const SSL_CIPHER * arg_a);

const char * SSL_CIPHER_get_name(const SSL_CIPHER * arg_a) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CIPHER_get_name called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CIPHER_get_name(arg_a);
    else {
        const char * (*orig_SSL_CIPHER_get_name)(const SSL_CIPHER *);
        orig_SSL_CIPHER_get_name = dlsym(RTLD_NEXT, "SSL_CIPHER_get_name");
        return orig_SSL_CIPHER_get_name(arg_a);
    }
}

const char * bb_SSL_CIPHER_get_name(const SSL_CIPHER * arg_a) 
{
    const char * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 88, 1, /* 0: struct.ssl_cipher_st */
            	5, 8,
            1, 8, 1, /* 5: pointer.char */
            	4096, 0,
            0, 1, 0, /* 10: char */
            1, 8, 1, /* 13: pointer.struct.ssl_cipher_st */
            	0, 0,
            0, 8, 0, /* 18: pointer.void */
        },
        .arg_entity_index = { 13, },
        .ret_entity_index = 5,
    };
    struct lib_enter_args *args_addr = &args;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CIPHER * new_arg_a = *((const SSL_CIPHER * *)new_args->args[0]);

    const char * *new_ret_ptr = (const char * *)new_args->ret;

    const char * (*orig_SSL_CIPHER_get_name)(const SSL_CIPHER *);
    orig_SSL_CIPHER_get_name = dlsym(RTLD_NEXT, "SSL_CIPHER_get_name");
    *new_ret_ptr = (*orig_SSL_CIPHER_get_name)(new_arg_a);

    syscall(889);

    return ret;
}

