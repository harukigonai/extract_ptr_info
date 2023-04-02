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
            0, 8, 0, /* 0: pointer.void */
            0, 0, 0, /* 3: func */
            4097, 8, 0, /* 6: pointer.func */
            0, 20, 0, /* 9: array[5].int */
            0, 0, 0, /* 12: func */
            4097, 8, 0, /* 15: pointer.func */
            0, 0, 0, /* 18: func */
            1, 8, 1, /* 21: pointer.struct.env_md_st */
            	26, 0,
            0, 120, 8, /* 26: struct.env_md_st */
            	45, 24,
            	48, 32,
            	51, 40,
            	54, 48,
            	45, 56,
            	57, 64,
            	15, 72,
            	6, 112,
            4097, 8, 0, /* 45: pointer.func */
            4097, 8, 0, /* 48: pointer.func */
            4097, 8, 0, /* 51: pointer.func */
            4097, 8, 0, /* 54: pointer.func */
            4097, 8, 0, /* 57: pointer.func */
            0, 0, 0, /* 60: func */
            0, 4, 0, /* 63: int */
            0, 8, 0, /* 66: long */
            0, 0, 0, /* 69: func */
            0, 0, 0, /* 72: func */
            0, 0, 0, /* 75: func */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 21,
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

