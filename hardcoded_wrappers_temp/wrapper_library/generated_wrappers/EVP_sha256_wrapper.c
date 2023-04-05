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
            8884097, 8, 0, /* 0: pointer.func */
            8884097, 8, 0, /* 3: pointer.func */
            8884097, 8, 0, /* 6: pointer.func */
            0, 120, 8, /* 9: struct.env_md_st */
            	28, 24,
            	31, 32,
            	34, 40,
            	6, 48,
            	28, 56,
            	3, 64,
            	0, 72,
            	37, 112,
            8884097, 8, 0, /* 28: pointer.func */
            8884097, 8, 0, /* 31: pointer.func */
            8884097, 8, 0, /* 34: pointer.func */
            8884097, 8, 0, /* 37: pointer.func */
            1, 8, 1, /* 40: pointer.struct.env_md_st */
            	9, 0,
        },
        .arg_entity_index = { -1 },
        .ret_entity_index = 40,
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

