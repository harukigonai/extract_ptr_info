#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
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

int bb_SSL_CIPHER_get_bits(const SSL_CIPHER * arg_a,int * arg_b);

int SSL_CIPHER_get_bits(const SSL_CIPHER * arg_a,int * arg_b) 
{
    unsigned long in_lib = syscall(890);
    printf("SSL_CIPHER_get_bits called %lu\n", in_lib);
    if (!in_lib)
        return bb_SSL_CIPHER_get_bits(arg_a,arg_b);
    else {
        int (*orig_SSL_CIPHER_get_bits)(const SSL_CIPHER *,int *);
        orig_SSL_CIPHER_get_bits = dlsym(RTLD_NEXT, "SSL_CIPHER_get_bits");
        return orig_SSL_CIPHER_get_bits(arg_a,arg_b);
    }
}

int bb_SSL_CIPHER_get_bits(const SSL_CIPHER * arg_a,int * arg_b) 
{
    int ret;

    struct lib_enter_args *args_addr = malloc(sizeof(struct lib_enter_args));
    args_addr->num_args = 0;
    uint32_t *em = args_addr->entity_metadata;
    em[0] = 1; em[1] = 8; em[2] = 1; /* 0: pointer.char */
    	em[3] = 8884096; em[4] = 0; 
    em[5] = 0; em[6] = 88; em[7] = 1; /* 5: struct.ssl_cipher_st */
    	em[8] = 0; em[9] = 8; 
    em[10] = 1; em[11] = 8; em[12] = 1; /* 10: pointer.int */
    	em[13] = 15; em[14] = 0; 
    em[15] = 0; em[16] = 4; em[17] = 0; /* 15: int */
    em[18] = 0; em[19] = 1; em[20] = 0; /* 18: char */
    em[21] = 1; em[22] = 8; em[23] = 1; /* 21: pointer.struct.ssl_cipher_st */
    	em[24] = 5; em[25] = 0; 
    args_addr->arg_entity_index[0] = 21;
    args_addr->arg_entity_index[1] = 10;
    args_addr->ret_entity_index = 15;
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

    free(args_addr);

    return ret;
}

