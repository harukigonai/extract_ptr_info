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

const EVP_MD * bb_EVP_sha1(void);

const EVP_MD * EVP_sha1(void) 
{
    if (syscall(890))
        return bb_EVP_sha1();
    else {
        const EVP_MD * (*orig_EVP_sha1)(void);
        orig_EVP_sha1 = dlsym(RTLD_NEXT, "EVP_sha1");
        return orig_EVP_sha1();
    }
}

const EVP_MD * bb_EVP_sha1(void) 
{
    printf("EVP_sha1 called\n");
    const EVP_MD * ret;

    struct lib_enter_args args = {
        .num_args = 0,
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 20, 0, /* 8: array[5].int */
            0, 0, 0, /* 11: func */
            1, 8, 1, /* 14: pointer.func */
            	11, 0,
            0, 0, 0, /* 19: func */
            0, 120, 8, /* 22: struct.env_md_st */
            	41, 24,
            	49, 32,
            	57, 40,
            	65, 48,
            	41, 56,
            	73, 64,
            	14, 72,
            	3, 112,
            1, 8, 1, /* 41: pointer.func */
            	46, 0,
            0, 0, 0, /* 46: func */
            1, 8, 1, /* 49: pointer.func */
            	54, 0,
            0, 0, 0, /* 54: func */
            1, 8, 1, /* 57: pointer.func */
            	62, 0,
            0, 0, 0, /* 62: func */
            1, 8, 1, /* 65: pointer.func */
            	70, 0,
            0, 0, 0, /* 70: func */
            1, 8, 1, /* 73: pointer.func */
            	19, 0,
            1, 8, 1, /* 78: pointer.struct.env_md_st */
            	22, 0,
            0, 8, 0, /* 83: long */
            0, 4, 0, /* 86: int */
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 78,
    };
    struct lib_enter_args *args_addr = &args;
    populate_ret(args_addr, ret);

    struct lib_enter_args *new_args = (struct lib_enter_args *)syscall(888, args_addr);

    const EVP_MD * *new_ret_ptr = (const EVP_MD * *)new_args->ret;

    const EVP_MD * (*orig_EVP_sha1)(void);
    orig_EVP_sha1 = dlsym(RTLD_NEXT, "EVP_sha1");
    *new_ret_ptr = (*orig_EVP_sha1)();

    syscall(889);

    return ret;
}

