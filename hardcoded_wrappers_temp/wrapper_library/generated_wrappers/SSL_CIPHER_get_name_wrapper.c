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

const char * SSL_CIPHER_get_name(const SSL_CIPHER * arg_a) 
{
    const char * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 8, 0, /* 0: long */
            0, 4, 0, /* 3: int */
            0, 88, 12, /* 6: struct.ssl_cipher_st */
            	3, 0,
            	33, 8,
            	0, 16,
            	0, 24,
            	0, 32,
            	0, 40,
            	0, 48,
            	0, 56,
            	0, 64,
            	0, 72,
            	3, 80,
            	3, 84,
            1, 8, 1, /* 33: pointer.char */
            	38, 0,
            0, 1, 0, /* 38: char */
            1, 8, 1, /* 41: pointer.struct.ssl_cipher_st */
            	6, 0,
        },
        .arg_entity_index = { 41, },
        .ret_entity_index = 33,
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

