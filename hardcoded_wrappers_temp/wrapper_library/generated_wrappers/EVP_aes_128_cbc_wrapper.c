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
            0, 1, 0, /* 0: char */
            1, 8, 1, /* 3: pointer.char */
            	4096, 0,
            4097, 8, 0, /* 8: pointer.func */
            4097, 8, 0, /* 11: pointer.func */
            4097, 8, 0, /* 14: pointer.func */
            4097, 8, 0, /* 17: pointer.func */
            0, 88, 7, /* 20: struct.evp_cipher_st */
            	14, 24,
            	17, 32,
            	11, 40,
            	8, 56,
            	8, 64,
            	37, 72,
            	3, 80,
            4097, 8, 0, /* 37: pointer.func */
            1, 8, 1, /* 40: pointer.struct.evp_cipher_st */
            	20, 0,
            0, 8, 0, /* 45: pointer.void */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 40,
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

