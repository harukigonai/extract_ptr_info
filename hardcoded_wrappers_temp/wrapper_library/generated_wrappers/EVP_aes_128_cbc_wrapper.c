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

const EVP_CIPHER * bb_EVP_aes_128_cbc(void);

const EVP_CIPHER * EVP_aes_128_cbc(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_aes_128_cbc called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_aes_128_cbc();
    else {
        const EVP_CIPHER * (*orig_EVP_aes_128_cbc)(void);
        orig_EVP_aes_128_cbc = dlsym(RTLD_NEXT, "EVP_aes_128_cbc");
        return orig_EVP_aes_128_cbc();
    }
}

const EVP_CIPHER * bb_EVP_aes_128_cbc(void) 
{
    const EVP_CIPHER * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            0, 0, 0, /* 3: func */
            0, 88, 7, /* 6: struct.evp_cipher_st */
            	23, 24,
            	26, 32,
            	29, 40,
            	32, 56,
            	32, 64,
            	35, 72,
            	38, 80,
            4097, 8, 0, /* 23: pointer.func */
            4097, 8, 0, /* 26: pointer.func */
            4097, 8, 0, /* 29: pointer.func */
            4097, 8, 0, /* 32: pointer.func */
            4097, 8, 0, /* 35: pointer.func */
            0, 8, 0, /* 38: pointer.void */
            0, 4, 0, /* 41: int */
            0, 8, 0, /* 44: long */
            0, 0, 0, /* 47: func */
            0, 0, 0, /* 50: func */
            0, 0, 0, /* 53: func */
            0, 1, 0, /* 56: char */
            1, 8, 1, /* 59: pointer.char */
            	4096, 0,
            1, 8, 1, /* 64: pointer.struct.evp_cipher_st */
            	6, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 64,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_CIPHER * *new_ret_ptr = (const EVP_CIPHER * *)new_args->ret;

    const EVP_CIPHER * (*orig_EVP_aes_128_cbc)(void);
    orig_EVP_aes_128_cbc = dlsym(RTLD_NEXT, "EVP_aes_128_cbc");
    *new_ret_ptr = (*orig_EVP_aes_128_cbc)();

    syscall(889);

    return ret;
}

