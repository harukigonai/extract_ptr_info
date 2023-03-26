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

const EVP_MD * EVP_sha1(void) 
{
    const EVP_MD * ret;

    struct lib_enter_args args = {
        .entity_metadata = {
            0, 0, 0, /* 0: func */
            1, 8, 1, /* 3: pointer.func */
            	0, 0,
            0, 20, 5, /* 8: array[5].int */
            	21, 0,
            	21, 4,
            	21, 8,
            	21, 12,
            	21, 16,
            0, 4, 0, /* 21: int */
            0, 0, 0, /* 24: func */
            1, 8, 1, /* 27: pointer.func */
            	24, 0,
            0, 0, 0, /* 32: func */
            1, 8, 1, /* 35: pointer.struct.env_md_st */
            	40, 0,
            0, 120, 15, /* 40: struct.env_md_st */
            	21, 0,
            	21, 4,
            	21, 8,
            	73, 16,
            	76, 24,
            	84, 32,
            	92, 40,
            	100, 48,
            	76, 56,
            	108, 64,
            	27, 72,
            	8, 80,
            	21, 100,
            	21, 104,
            	3, 112,
            0, 8, 0, /* 73: long */
            1, 8, 1, /* 76: pointer.func */
            	81, 0,
            0, 0, 0, /* 81: func */
            1, 8, 1, /* 84: pointer.func */
            	89, 0,
            0, 0, 0, /* 89: func */
            1, 8, 1, /* 92: pointer.func */
            	97, 0,
            0, 0, 0, /* 97: func */
            1, 8, 1, /* 100: pointer.func */
            	105, 0,
            0, 0, 0, /* 105: func */
            1, 8, 1, /* 108: pointer.func */
            	32, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 35,
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

