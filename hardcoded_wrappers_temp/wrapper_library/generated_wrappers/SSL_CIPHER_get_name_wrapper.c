#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
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

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    memset(args_addr, 0, sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 0; em[1] = 88; em[2] = 1; /* 0: struct.ssl_cipher_st */
    	em[3] = 5; em[4] = 8; 
    em[5] = 1; em[6] = 8; em[7] = 1; /* 5: pointer.char */
    	em[8] = 8884096; em[9] = 0; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.struct.ssl_cipher_st */
    	em[13] = 0; em[14] = 0; 
    em[15] = 0; em[16] = 1; em[17] = 0; /* 15: char */
    args_addr->arg_entity_index[0] = 10;
    args_addr->ret_entity_index = 5;
    populate_arg(args_addr, arg_a);
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const SSL_CIPHER * new_arg_a = *((const SSL_CIPHER * *)new_args->args[0]);

    const char * *new_ret_ptr = (const char * *)new_args->ret;

    const char * (*orig_SSL_CIPHER_get_name)(const SSL_CIPHER *);
    orig_SSL_CIPHER_get_name = dlsym(RTLD_NEXT, "SSL_CIPHER_get_name");
    *new_ret_ptr = (*orig_SSL_CIPHER_get_name)(new_arg_a);

    syscall(889);

    free(args_addr);

    return ret;
}

