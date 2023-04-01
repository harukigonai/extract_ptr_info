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

const EVP_MD * bb_EVP_sha256(void);

const EVP_MD * EVP_sha256(void) 
{
    unsigned long in_lib = syscall(890);
    printf("EVP_sha256 called %lu\n", in_lib);
    if (!in_lib)
        return bb_EVP_sha256();
    else {
        const EVP_MD * (*orig_EVP_sha256)(void);
        orig_EVP_sha256 = dlsym(RTLD_NEXT, "EVP_sha256");
        return orig_EVP_sha256();
    }
}

const EVP_MD * bb_EVP_sha256(void) 
{
    const EVP_MD * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            4097, 8, 0, /* 3: pointer.func */
            0, 20, 0, /* 6: array[5].int */
            0, 0, 0, /* 9: func */
            4097, 8, 0, /* 12: pointer.func */
            0, 0, 0, /* 15: func */
            1, 8, 1, /* 18: pointer.struct.env_md_st */
            	23, 0,
            0, 120, 0, /* 23: struct.env_md_st */
            0, 0, 0, /* 26: func */
            0, 4, 0, /* 29: int */
            4097, 8, 0, /* 32: pointer.func */
            4097, 8, 0, /* 35: pointer.func */
            0, 0, 0, /* 38: func */
            0, 0, 0, /* 41: func */
            0, 8, 0, /* 44: long */
            4097, 8, 0, /* 47: pointer.func */
            4097, 8, 0, /* 50: pointer.func */
            0, 0, 0, /* 53: func */
            4097, 8, 0, /* 56: pointer.func */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 18,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_MD * *new_ret_ptr = (const EVP_MD * *)new_args->ret;

    const EVP_MD * (*orig_EVP_sha256)(void);
    orig_EVP_sha256 = dlsym(RTLD_NEXT, "EVP_sha256");
    *new_ret_ptr = (*orig_EVP_sha256)();

    syscall(889);

    return ret;
}

